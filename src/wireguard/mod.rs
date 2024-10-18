use std::io::Read;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::bail;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{self, Tunn, TunnResult};
use boringtun::x25519::{self, PublicKey, StaticSecret};
use base64::prelude::*;

#[derive(Clone)]
pub struct Wireguard {
    private_key: x25519::StaticSecret,
    public_key: x25519::PublicKey,
    endpoint: String,
    virtual_ip: String,
}

pub struct Tunnel {
    tun: Tunn, // 1. MUTEX THIS; 2. TRY HANDSHAKE 3. FIGURE OUT HOW TO SEND DESTINATION PATH TO WIREGUARD
    socket: Arc<Mutex<UdpSocket>>,
}

impl Tunnel {
    pub fn new(wg: Wireguard) -> anyhow::Result<Self> {
        let socket: UdpSocket = UdpSocket::bind("0.0.0.0:0").unwrap();
        match socket.connect(wg.endpoint.clone()) {
            Ok(a) => {
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
            Ok(tun) => Ok(Self { tun, socket: Arc::new(Mutex::new(socket)) }),
            Err(err) => bail!("tunnel error: {}", err),
        }
    }
    /*
        async fn udp_send_loop(mut self, socket: Arc<Mutex<UdpSocket>>) {
            thread::spawn(move || {
                let socket = Arc::clone(&socket);
                let mut buf = [0u8; 65536];
                let mut send_buf = [0u8; 65536];

                loop {
                    let n = match self.test_socket.read(&mut buf) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };

                    match self.tun.encapsulate(&buf[..n], &mut send_buf) {
                        boringtun::noise::TunnResult::WriteToNetwork(packet) => {
                            {
                                let socket = socket.lock().unwrap();
                                socket.send(&packet).unwrap();
                            }
                        },
                        _ => {
                            println!("other encap");
                        }
                    }

                }
            });
        }
    */

    pub fn create_handshake_init(mut self) {
        let mut dst = vec![0u8; 2048];
        let handshake_init = self.tun.format_handshake_initiation(&mut dst, false);
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            {
                let socket = self.socket.lock().unwrap();
                socket.send(&sent).unwrap();
            }
        } else {
            unreachable!();
        };
    }

    pub fn udp_rec_loop(mut self) {
        let socket = Arc::clone(&self.socket);
        thread::spawn(move || {
            let socket = Arc::clone(&socket);
            let mut buf = [0u8; 65536];
            loop {
                {
                    match socket.try_lock() {
                        Ok(socket) => {
                            match socket.recv(&mut buf) {
                                Ok(_) => {
                                    let mut packet = [0u8; 65536];
                                    match self.tun.decapsulate(
                                        Some(socket.local_addr().unwrap().ip()),
                                        &buf,
                                        &mut packet,
                                    ) {
                                        boringtun::noise::TunnResult::Done => {
                                            println!("Done");
                                        }
                                        boringtun::noise::TunnResult::Err(_) => {
                                            continue;
                                        }
                                        boringtun::noise::TunnResult::WriteToNetwork(_) => {
                                            socket.send(&packet).unwrap();
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
                                Err(_) => {}
                            };
                        }
                        Err(_) => {
                            println!("lock");
                            continue;
                        }
                    }
                }
            }
        });
    }
}

impl Wireguard {
    pub fn new(
        private_key: &str,
        public_key: &str,
        endpoint: &str,
        virtual_ip: &str,
    ) -> Self {
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
