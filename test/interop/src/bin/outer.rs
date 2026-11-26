//! The Lite node opens the outer link (its own WireGuard initiator) to boringtun
//! as the full node, makes new keys, and both send both ways.
use boringtun::noise::{Tunn, TunnResult};
use x25519_dalek::{PublicKey, StaticSecret};

extern "C" {
    fn vl_test_init_keys(secret: *const u8, peer: *const u8);
    fn vl_test_initiation(tai: *const u8, out: *mut u8) -> i32;
    fn vl_test_response(p: *const u8, n: usize) -> i32;
    fn vl_test_out_seal(plain: *const u8, n: usize, out: *mut u8) -> i32;
    fn vl_test_out_open(p: *const u8, n: usize, plain: *mut u8) -> i32;
}

fn handshake(node: &mut Tunn, secs: u64) {
    let mut tai = [0u8; 12];
    tai[..8].copy_from_slice(&((1u64 << 62) + 37 + secs).to_be_bytes());
    let mut init = vec![0u8; 148];
    assert_eq!(unsafe { vl_test_initiation(tai.as_ptr(), init.as_mut_ptr()) }, 148);
    let mut buf = vec![0u8; 2048];
    let resp = match node.decapsulate(None, &init, &mut buf) {
        TunnResult::WriteToNetwork(r) => r.to_vec(),
        other => panic!("the node took no initiation: {other:?}"),
    };
    assert_eq!(unsafe { vl_test_response(resp.as_ptr(), resp.len()) }, 1, "response refused");
}

fn ipv4(payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0, 10, 89, 0, 2, 10, 89, 0, 1]);
    let mut sum: u32 = p.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]]) as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p.extend_from_slice(&[0x12, 0xbf, 0x12, 0xbf]);
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

fn both_ways(node: &mut Tunn, n: u8) {
    let mut buf = vec![0u8; 2048];
    // Lite → node.
    let msg = ipv4(&[n; 40]);
    let mut sealed = vec![0u8; 2048];
    let k = unsafe { vl_test_out_seal(msg.as_ptr(), msg.len(), sealed.as_mut_ptr()) };
    assert!(k > 0);
    match node.decapsulate(None, &sealed[..k as usize], &mut buf) {
        TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, &msg[..]),
        other => panic!("the node didn't take it: {other:?}"),
    }
    // Node → Lite.
    let back = ipv4(&[n ^ 0xff; 30]);
    let out = match node.encapsulate(&back, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("{other:?}"),
    };
    let mut plain = vec![0u8; 2048];
    let k = unsafe { vl_test_out_open(out.as_ptr(), out.len(), plain.as_mut_ptr()) };
    assert_eq!(&plain[..k as usize], &back[..]);
}

fn main() {
    let node_secret = StaticSecret::from([9u8; 32]);
    let node_pub = PublicKey::from(&node_secret);
    let lite_secret = [5u8; 32];
    let lite_pub = PublicKey::from(&StaticSecret::from(lite_secret));
    unsafe { vl_test_init_keys(lite_secret.as_ptr(), node_pub.as_bytes().as_ptr()) };
    let mut node = Tunn::new(node_secret, lite_pub, None, None, 1, None);
    handshake(&mut node, 1_800_000_000);
    both_ways(&mut node, 1);
    println!("outer link: handshake and both ways");
    // New keys (every two minutes on the device): the old session's packets still taken.
    handshake(&mut node, 1_800_000_120);
    both_ways(&mut node, 2);
    println!("outer link: new keys, both ways");
}
