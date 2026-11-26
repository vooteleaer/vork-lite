//! Writes a boringtun handshake initiation to a responder key (for checking other tools).
use boringtun::noise::{Tunn, TunnResult};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let pubkey: [u8; 32] = (0..32).map(|i| u8::from_str_radix(&args[1][2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<_>>().try_into().unwrap();
    let mut t = Tunn::new(StaticSecret::from([3u8; 32]), PublicKey::from(pubkey), None, None, 1, None);
    let mut buf = vec![0u8; 256];
    if let TunnResult::WriteToNetwork(p) = t.format_handshake_initiation(&mut buf, false) {
        std::fs::write(&args[2], p).unwrap();
    }
}
