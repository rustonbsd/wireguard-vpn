use std::any;
use std::borrow::BorrowMut;
use std::io::Read;
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread::{self, sleep};
use std::time::Duration;

use anyhow::bail;
use base64::prelude::*;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{self, Tunn, TunnResult};
use boringtun::x25519::{self, PublicKey, StaticSecret};

#[derive(Clone)]
pub struct Wireguard {
    private_key: x25519::StaticSecret,
    public_key: x25519::PublicKey,
    endpoint: String,
    virtual_ip: String,
}

#[derive(Clone)]
pub struct Tunnel {
    tun: Arc<Mutex<Tunn>>, // 1. MUTEX THIS; 2. TRY HANDSHAKE 3. FIGURE OUT HOW TO SEND DESTINATION PATH TO WIREGUARD
    socket: Arc<Mutex<UdpSocket>>,
}

impl Tunnel {
    pub fn new(wg: Wireguard) -> anyhow::Result<Self> {
        let socket: UdpSocket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        match socket.connect(wg.endpoint.clone()) {
            Ok(a) => {
                socket.set_read_timeout(Some(Duration::from_millis(1000)));
                socket.set_write_timeout(Some(Duration::from_millis(1000)));
                println!("wg socket connected");
            }
            Err(_) => {
                println!("wg socket failed to connect");
                bail!(
                    "wg socket failed to connect to endpoint {}",
                    wg.endpoint.clone()
                )
            }
        };

        let secret = StaticSecret::from(wg.private_key);
        let public = PublicKey::from(wg.public_key);

        match Tunn::new(secret, public, None, Some(5), 0, None) {
            Ok(tun) => Ok(Self {
                tun: Arc::new(Mutex::new(tun)),
                socket: Arc::new(Mutex::new(socket)),
            }),
            Err(err) => bail!("tunnel error: {}", err),
        }
    }
    
    pub fn udp_send_ip_packet(&mut self, packet: &[u8], wg: &Wireguard) -> anyhow::Result<()> {
        let mut sent = [0u8; 65536];
        let enc_res = {
            match self.tun.try_lock() {
                Ok(mut tun) => {
                    tun.encapsulate(&packet, &mut sent)
                },
                Err(_) => {
                    println!("failed to lock tun device udp_send_ip_packet");
                    bail!("failed to lock tun device!")
                },
            }
        };

        match enc_res {
            TunnResult::WriteToNetwork(packet) => {
                loop {
                    let socket = Arc::clone(&self.socket);

                    {
                        let socket = match socket.try_lock() {
                            Ok(socket) => socket,
                            Err(_) => continue,
                        };

                        match socket.send_to(&packet, wg.endpoint.clone()) {
                            Ok(a) => { 
                                println!("Packet sent: {a} (udp_send_ip_packet)");
                                break;
                            }
                            Err(_) => {
                                sleep(Duration::from_millis(10));
                            }
                        }
                    }
                }
            },
            _ => {
                println!("udp_send_ip_packet other");
            }
        }

        Ok(())
    }

    pub fn maintainance_loop(&mut self, wg: &Wireguard) {
        let socket = Arc::clone(&self.socket);
        thread::spawn({
            let self1 = self.clone();
            let wg = wg.clone();
            move || {
                let socket = Arc::clone(&socket);
                let mut sent = [0u8; 65536];
                loop {
                    {
                        match self1.tun.try_lock() {
                            Ok(mut tun) => {
                                
                                match tun.update_timers(&mut sent) {
                                    TunnResult::Done => { sleep(Duration::from_millis(1)); },
                                    TunnResult::Err(WireGuardError::ConnectionExpired) => {
                                        println!("routine failed: re-initialization with handshake needed");

                                    },
                                    TunnResult::Err(wire_guard_error) => {
                                        println!("routine failed: other error: {:?}",wire_guard_error);
                                    },
                                    TunnResult::WriteToNetwork(packet) => {
                                        {
                                            loop {
                                                match socket.try_lock() {
                                                    Ok(socket) => match socket.send_to(&packet, wg.endpoint.clone()) {
                                                        Ok(n) => {
                                                            println!("maintainance sent: {n}");
                                                            break
                                                        },
                                                        Err(_) => { println!("maintainance failed to sent!"); },
                                                    },
                                                    Err(_) => {
                                                        sleep(Duration::from_millis(10)); 
                                                        continue
                                                    },
                                                };
                                            }
                                        }
                                    },
                                    _ => {println!("maintainance other"); },
                                };
                            },
                            Err(_) => {
                                //println!("lock failed: tun.update_timers err");
                                },
                        };
                    }
                }
                
            }
        });
    }

    pub fn create_handshake_init(&mut self) {
        let mut dst = vec![0u8; 2048];
        let mut tun = self.tun.lock().unwrap();
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        
        match handshake_init {
            TunnResult::Done => {
                sleep(Duration::from_millis(1));
            },
            TunnResult::Err(wire_guard_error) => {println!("Error: {:?}",wire_guard_error);},
            TunnResult::WriteToNetwork(sent) => {
                
                loop {
                    match self.socket.try_lock() {
                        Ok(socket) => {
                            socket.send(&sent).unwrap();
                            println!("Handshake sent!");
                            break;
                        }
                        Err(_) => {
                            sleep(Duration::from_millis(10));
                        }
                    }
                }
            },
            _ => {println!("unexpected wireguard routing task");},
        }

    }

    pub fn udp_rec_loop(&mut self) {
        let socket = Arc::clone(&self.socket);
        thread::spawn({
            let self1 = self.clone();
            move || {
                let socket = Arc::clone(&socket);
                let mut buf = [0u8; 65536];
                loop {
                    {
                        match socket.try_lock() {
                            Ok(socket) => match socket.recv(&mut buf) {
                                Ok(n) => {
                                    println!("Received: {:?}", n);
                                    let mut packet = [0u8; 65536];
                                    let mut tun = self1.tun.lock().unwrap();
                                    match tun.decapsulate(
                                        Some(socket.local_addr().unwrap().ip()),
                                        &buf[..n],
                                        &mut packet,
                                    ) {
                                        boringtun::noise::TunnResult::Done => {
                                            println!("Done");
                                        }
                                        boringtun::noise::TunnResult::Err(_) => {
                                            continue;
                                        }
                                        boringtun::noise::TunnResult::WriteToNetwork(sent_buf) => {
                                            loop {
                                                match socket.send(&sent_buf) {
                                                    Ok(a) => { 
                                                        println!("Packet sent: {a}");
                                                        break;
                                                    }
                                                    Err(_) => {
                                                        sleep(Duration::from_millis(10));
                                                    }
                                                }
                                            }
                                        }
                                        boringtun::noise::TunnResult::WriteToTunnelV4(
                                            packet,
                                            ipv4_addr,
                                        ) => {
                                            println!("IPV4: {}", ipv4_addr);
                                        }
                                        boringtun::noise::TunnResult::WriteToTunnelV6(
                                            packet,
                                            ipv6_addr,
                                        ) => {
                                            println!("IPV6: {}", ipv6_addr);
                                        }
                                    }
                                }
                                Err(_) => {
                                    println!("Ehhh");
                                }
                            },
                            Err(_) => {
                                //println!("lock");
                                continue;
                            }
                        }
                    }
                    sleep(Duration::from_millis(11));
                }
            }
        });
    }
}

impl Wireguard {
    pub fn new(private_key: &str, public_key: &str, endpoint: &str, virtual_ip: &str) -> Self {
        let mut private_key_buf = [0u8; 32];
        let mut public_key_buf = [0u8; 32];

        private_key_buf.copy_from_slice(BASE64_STANDARD.decode(private_key).unwrap().as_slice());
        public_key_buf.copy_from_slice(BASE64_STANDARD.decode(public_key).unwrap().as_slice());

        Self {
            private_key: StaticSecret::from(private_key_buf),
            public_key: PublicKey::from(public_key_buf),
            endpoint: endpoint.to_string(),
            virtual_ip: virtual_ip.to_string(),
        }
    }
}
