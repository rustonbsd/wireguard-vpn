use std::sync::{Arc, Mutex};

mod wireguard;

fn main() {
    let tun = Arc::new(Mutex::new(wireguard::Tunnel::new(wireguard::Wireguard::new(
        "EJHiDdrGDd1pJsr/BXoBN2r0Y7nQn6eYxgbCUfmSWWo=", 
        "tzSfoiq9ZbCcE5I0Xz9kCrsWksDn0wgvaz9TiHYTmnU=", 
        "37.19.221.143", 
    "10.0.0.2")).unwrap()));

    {
        let tun = Arc::clone(&tun);
        match tun.lock() {
            Ok(tun) => {
                tun.udp_rec_loop();
            },
            Err(_) => todo!(),
        };
    }
    {
        let tun = Arc::clone(&tun);
        tun.lock().unwrap().create_handshake_init();
    }
}
