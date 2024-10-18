use std::{sync::{Arc, Mutex}, thread::sleep, time::Duration};

mod wireguard;

fn main() {
    let mut tun = wireguard::Tunnel::new(wireguard::Wireguard::new(
        "EJHiDdrGDd1pJsr/BXoBN2r0Y7nQn6eYxgbCUfmSWWo=", 
        "tzSfoiq9ZbCcE5I0Xz9kCrsWksDn0wgvaz9TiHYTmnU=", 
        "37.19.221.143:51820", 
    "10.0.0.2")).unwrap();
    
    {
        tun.udp_rec_loop();
    }
    {
        tun.create_handshake_init();
    }

    loop {
        sleep(Duration::from_secs(10));
    }
}
