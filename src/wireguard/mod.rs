use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::bail;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey, StaticSecret};

#[derive(Clone, Debug)]
struct Wireguard {
    private_key: [u8; 32],
    public_key: [u8; 32],
    endpoint: String,
    virtual_ip: String,
}

struct Tunnel {
    tun: Tunn,
    socket: UdpSocket,
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
            Ok(tun) => Ok(Self { tun, socket }),
            Err(err) => bail!("tunnel error: {}", err),
        }
    }

    async fn udp_rec_loop(self, socket: Arc<Mutex<UdpSocket>>) {
        thread::spawn(
            move || {
                let socket = Arc::clone(&socket);
                let mut buf = [0u8; 65536];
                loop {
                    {
                        match socket.try_lock() {
                            Ok(socket) => {
                                match socket.recv(&mut buf) {
                                    Ok(n) => {
                                        self.tun
                                    },
                                    Err(_) => {
                                        
                                    },
                                };
                            },
                            Err(_) => {
                                println!("lock");
                                continue
                            },
                        }
                    }
            }
        });
    }
}

impl Wireguard {
    pub fn new(
        private_key: [u8; 32],
        public_key: [u8; 32],
        endpoint: &str,
        virtual_ip: &str,
    ) -> Self {
        Self {
            private_key,
            public_key,
            endpoint: endpoint.to_string(),
            virtual_ip: virtual_ip.to_string(),
        }
    }
}
