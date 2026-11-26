//! boringtun (a full node's inner layer) opens a session to the Lite node's
//! responder and sends both ways; ed25519-dalek checks a Lite signature.
use boringtun::noise::{Tunn, TunnResult};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

extern "C" {
    fn vl_test_set_static(secret: *const u8);
    fn vl_test_public(pub_: *mut u8, secret: *const u8);
    fn vl_test_receive(p: *const u8, n: usize, out: *mut u8, plain: *mut u8, plain_len: *mut usize, session: *mut i32) -> i32;
    fn vl_test_seal(session: i32, plain: *const u8, n: usize, out: *mut u8) -> i32;
    fn vl_test_sign(sig: *mut u8, pub_: *mut u8, seed: *const u8, msg: *const u8, n: usize);
}

struct Lite;
impl Lite {
    /// (what it sends back, the plaintext it took, its session)
    fn receive(&self, p: &[u8]) -> Option<(Vec<u8>, Vec<u8>, i32)> {
        let mut out = vec![0u8; 2048];
        let mut plain = vec![0u8; 2048];
        let (mut pl, mut s) = (0usize, -1i32);
        let n = unsafe { vl_test_receive(p.as_ptr(), p.len(), out.as_mut_ptr(), plain.as_mut_ptr(), &mut pl, &mut s) };
        if n < 0 {
            return None;
        }
        out.truncate(n as usize);
        plain.truncate(pl);
        Some((out, plain, s))
    }
    fn seal(&self, session: i32, plain: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; plain.len() + 64];
        let n = unsafe { vl_test_seal(session, plain.as_ptr(), plain.len(), out.as_mut_ptr()) };
        assert!(n > 0, "seal refused");
        out.truncate(n as usize);
        out
    }
}

/// An IPv4/UDP datagram, as vØrk frames its messages (wire::frame).
fn frame(payload: &[u8]) -> Vec<u8> {
    let total = 28 + payload.len();
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0, 10, 89, 0, 1, 10, 89, 0, 2]);
    let mut sum: u32 = p.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]]) as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    p.extend_from_slice(&4799u16.to_be_bytes());
    p.extend_from_slice(&4799u16.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

fn main() {
    // The Lite node's static key.
    let lite_secret = [7u8; 32];
    let mut lite_pub = [0u8; 32];
    unsafe {
        vl_test_set_static(lite_secret.as_ptr());
        vl_test_public(lite_pub.as_mut_ptr(), lite_secret.as_ptr());
    }
    assert_eq!(lite_pub, *PublicKey::from(&StaticSecret::from(lite_secret)).as_bytes(), "X25519 public keys agree");
    let lite = Lite;

    // A full node opens a session (a fresh, anonymous static key, as vØrk does).
    let mut tunn = Tunn::new(StaticSecret::from([9u8; 32]), PublicKey::from(lite_pub), None, None, 1, None);
    let mut buf = vec![0u8; 2048];
    let init = match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        _ => panic!("no initiation"),
    };
    let (response, _, _) = lite.receive(&init).expect("the Lite node took the initiation");
    assert_eq!(response.len(), 92);
    // boringtun takes the response and sends its keepalive (key confirmation).
    let keepalive = match tunn.decapsulate(None, &response, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("boringtun didn't take the response: {other:?}"),
    };
    let (_, plain, _) = lite.receive(&keepalive).expect("keepalive taken");
    assert!(plain.is_empty(), "a keepalive is empty");
    println!("handshake: ok");

    // A ping (vØrk's app message 1 + nonce) to the Lite node, framed as vØrk frames it.
    let ping = frame(&[1, 1, 2, 3, 4, 5, 6, 7, 8]);
    let sealed = match tunn.encapsulate(&ping, &mut buf) {
        TunnResult::WriteToNetwork(p) => p.to_vec(),
        other => panic!("encapsulate: {other:?}"),
    };
    let (_, plain, session) = lite.receive(&sealed).expect("data taken");
    assert_eq!(plain, ping, "the Lite node read what was sent");
    // A replay is refused.
    assert!(lite.receive(&sealed).is_none(), "a replay is refused");
    println!("full node -> Lite: ok");

    // The pong back.
    let pong = frame(&[2, 1, 2, 3, 4, 5, 6, 7, 8]);
    let back = lite.seal(session, &pong);
    match tunn.decapsulate(None, &back, &mut buf) {
        TunnResult::WriteToTunnelV4(p, _) => assert_eq!(p, &pong[..], "boringtun read what the Lite node sent"),
        other => panic!("boringtun didn't take the Lite node's packet: {other:?}"),
    }
    println!("Lite -> full node: ok");

    // Ed25519: a Lite signature checks as a full node checks it.
    let seed = [5u8; 32];
    let msg = b"vork/v0/bindsomething";
    let (mut sig, mut pub_) = ([0u8; 64], [0u8; 32]);
    unsafe { vl_test_sign(sig.as_mut_ptr(), pub_.as_mut_ptr(), seed.as_ptr(), msg.as_ptr(), msg.len()) };
    let key = VerifyingKey::from_bytes(&pub_).unwrap();
    assert_eq!(key, ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key(), "the same public key from the seed");
    key.verify(msg, &Signature::from_bytes(&sig)).expect("the signature checks");
    println!("ed25519: ok");
}
