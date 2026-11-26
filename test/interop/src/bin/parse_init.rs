//! Parses a captured handshake initiation as a full node does (parse_handshake_anon).
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn};
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key = std::fs::read(&args[1]).unwrap();
    let pkt = std::fs::read(&args[2]).unwrap();
    let secret = StaticSecret::from(<[u8; 32]>::try_from(&key[..32]).unwrap());
    let public = PublicKey::from(&secret);
    println!("responder public {}", hex(public.as_bytes()));
    match Tunn::parse_incoming_packet(&pkt) {
        Ok(Packet::HandshakeInit(init)) => match parse_handshake_anon(&secret, &public, &init) {
            Ok(h) => println!("parsed: initiator static {}", hex(&h.peer_static_public)),
            Err(e) => println!("parse_handshake_anon failed: {e:?}"),
        },
        Ok(_) => println!("not an initiation"),
        Err(e) => println!("parse_incoming_packet failed: {e:?}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
