// C entry points to the Lite node's inner layer and signing, for the interop
// test against boringtun and ed25519-dalek (what full nodes use).
#include <string.h>

#include "../../src/monocypher-ed25519.h"
#include "../../src/monocypher.h"
#include "../../src/wg.h"

using vl::WgResponder;

static WgResponder responder;

extern "C" {

void vl_test_public(uint8_t pub[32], const uint8_t secret[32]) { crypto_x25519_public_key(pub, secret); }

void vl_test_set_static(const uint8_t secret[32]) {
  uint8_t pub[32];
  crypto_x25519_public_key(pub, secret);
  responder.set_static(secret, pub);
}

/// Hands a packet to the responder: what it sends back (into `out`, its
/// length the result, or -1 if nothing taken) and the plaintext of a
/// transport packet (`plain`, `plain_len`, `session`).
int vl_test_receive(const uint8_t *p, size_t n, uint8_t *out, uint8_t *plain, size_t *plain_len, int *session) {
  std::vector<uint8_t> o, pl;
  int s = -1;
  if (!responder.receive(7, p, n, 1, o, pl, s)) return -1;
  memcpy(out, o.data(), o.size());
  memcpy(plain, pl.data(), pl.size());
  *plain_len = pl.size();
  *session = s;
  return (int) o.size();
}

int vl_test_seal(int session, const uint8_t *plain, size_t n, uint8_t *out) {
  std::vector<uint8_t> o;
  if (!responder.seal(session, plain, n, o)) return -1;
  memcpy(out, o.data(), o.size());
  return (int) o.size();
}

/// Ed25519 from a 32-byte seed, as vØrk's key files keep it.
void vl_test_sign(uint8_t sig[64], uint8_t pub[32], const uint8_t seed[32], const uint8_t *msg, size_t n) {
  uint8_t s[32], secret[64];
  memcpy(s, seed, 32);
  crypto_ed25519_key_pair(secret, pub, s);
  crypto_ed25519_sign(sig, secret, msg, n);
}
}

// The outer layer's initiator against boringtun as the full node.
static vl::WgInitiator initiator;

extern "C" {

void vl_test_init_keys(const uint8_t secret[32], const uint8_t peer[32]) {
  uint8_t pub[32];
  crypto_x25519_public_key(pub, secret);
  initiator.set_keys(secret, pub, peer);
}

int vl_test_initiation(const uint8_t tai[12], uint8_t *out) {
  std::vector<uint8_t> o;
  initiator.initiation(tai, o);
  memcpy(out, o.data(), o.size());
  return (int) o.size();
}

int vl_test_response(const uint8_t *p, size_t n) { return initiator.response(p, n, 1) ? 1 : 0; }

int vl_test_out_seal(const uint8_t *plain, size_t n, uint8_t *out) {
  std::vector<uint8_t> o;
  if (!initiator.seal(plain, n, o)) return -1;
  memcpy(out, o.data(), o.size());
  return (int) o.size();
}

int vl_test_out_open(const uint8_t *p, size_t n, uint8_t *plain) {
  std::vector<uint8_t> o;
  if (!initiator.open(p, n, o)) return -1;
  memcpy(plain, o.data(), o.size());
  return (int) o.size();
}
}
