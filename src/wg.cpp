#include "wg.h"

#include <string.h>

#include "crypto.h"
#include "monocypher.h"

#ifdef VL_HOST_TEST
#include <stdlib.h>
static void random_bytes(uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++) p[i] = (uint8_t) rand();
}
#else
#include "esp_random.h"
static void random_bytes(uint8_t *p, size_t n) { esp_fill_random(p, n); }
#endif

namespace vl {

static const char CONSTRUCTION[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
static const char LABEL_MAC1[] = "mac1----";

static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t) p[3] << 24; }
static void put_le32(uint8_t *p, uint32_t v) {
  for (int i = 0; i < 4; i++) p[i] = (uint8_t) (v >> (8 * i));
}
static uint64_t le64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
  return v;
}

void WgResponder::set_static(const uint8_t secret[32], const uint8_t pub[32]) {
  memcpy(secret_, secret, 32);
  memcpy(pub_, pub, 32);
  vl_hash(ck_start_, (const uint8_t *) CONSTRUCTION, strlen(CONSTRUCTION), nullptr, 0);
  uint8_t h[32];
  vl_hash(h, ck_start_, 32, (const uint8_t *) IDENTIFIER, strlen(IDENTIFIER));
  vl_hash(h_start_, h, 32, pub_, 32);
  vl_hash(mac1_key_, (const uint8_t *) LABEL_MAC1, 8, pub_, 32);
}

bool WgResponder::receive(uint64_t label, const uint8_t *p, size_t n, uint32_t now_ms, std::vector<uint8_t> &out, std::vector<uint8_t> &plain, int &session) {
  out.clear();
  plain.clear();
  session = -1;
  if (n < 4 || p[1] || p[2] || p[3]) return false;
  switch (p[0]) {
    case 1:
      return initiation(label, p, n, now_ms, out);
    case 4:
      return transport(p, n, plain, session);
    default:
      return false;  // responses and cookie replies: a responder gets none
  }
}

bool WgResponder::initiation(uint64_t label, const uint8_t *p, size_t n, uint32_t now_ms, std::vector<uint8_t> &out) {
  if (n != 148) return false;
  uint8_t mac[16];
  vl_mac(mac, mac1_key_, p, 116);
  if (crypto_verify16(mac, p + 116) != 0) return false;
  const uint32_t sender = le32(p + 4);
  const uint8_t *e_i = p + 8, *enc_static = p + 40, *enc_ts = p + 88;
  uint8_t ck[32], h[32], k[32], dh[32], s_i[32], ts[12];
  memcpy(ck, ck_start_, 32);
  vl_kdf(ck, nullptr, nullptr, ck, e_i, 32);
  vl_hash(h, h_start_, 32, e_i, 32);
  crypto_x25519(dh, secret_, e_i);
  vl_kdf(ck, k, nullptr, ck, dh, 32);
  if (vl_open(s_i, k, 0, enc_static, 48, h, 32) != 0) return false;
  vl_hash(h, h, 32, enc_static, 48);
  crypto_x25519(dh, secret_, s_i);
  vl_kdf(ck, k, nullptr, ck, dh, 32);
  if (vl_open(ts, k, 0, enc_ts, 28, h, 32) != 0) return false;
  vl_hash(h, h, 32, enc_ts, 28);

  // The response, and the session's keys.
  uint8_t e_r[32], e_r_pub[32];
  random_bytes(e_r, 32);
  crypto_x25519_public_key(e_r_pub, e_r);
  out.assign(92, 0);
  uint8_t *r = out.data();
  r[0] = 2;
  uint32_t local;
  random_bytes((uint8_t *) &local, 4);
  put_le32(r + 4, local);
  put_le32(r + 8, sender);
  memcpy(r + 12, e_r_pub, 32);
  vl_kdf(ck, nullptr, nullptr, ck, e_r_pub, 32);
  vl_hash(h, h, 32, e_r_pub, 32);
  crypto_x25519(dh, e_r, e_i);
  vl_kdf(ck, nullptr, nullptr, ck, dh, 32);
  crypto_x25519(dh, e_r, s_i);
  vl_kdf(ck, nullptr, nullptr, ck, dh, 32);
  static const uint8_t psk[32] = {0};
  uint8_t tau[32];
  vl_kdf(ck, tau, k, ck, psk, 32);
  vl_hash(h, h, 32, tau, 32);
  vl_seal(r + 44, k, 0, nullptr, 0, h, 32);
  uint8_t their_mac1_key[32];
  vl_hash(their_mac1_key, (const uint8_t *) LABEL_MAC1, 8, s_i, 32);
  vl_mac(r + 60, their_mac1_key, r, 60);

  // The oldest slot (or a free one) for it.
  int slot = 0;
  for (int i = 0; i < MAX_SESSIONS; i++) {
    if (!sessions[i].used) {
      slot = i;
      break;
    }
    if (sessions[i].made_ms < sessions[slot].made_ms) slot = i;
  }
  WgSession &s = sessions[slot];
  s = WgSession();
  s.used = true;
  s.local = local;
  s.remote = sender;
  s.label = label;
  s.made_ms = now_ms;
  memcpy(s.peer, s_i, 32);
  // (initiator's sending key = our receiving key, ours = theirs) := KDF2(ck, empty)
  vl_kdf(s.recv_key, s.send_key, nullptr, ck, nullptr, 0);
  crypto_wipe(e_r, 32);
  crypto_wipe(dh, 32);
  crypto_wipe(k, 32);
  crypto_wipe(ck, 32);
  return true;
}

bool WgResponder::transport(const uint8_t *p, size_t n, std::vector<uint8_t> &plain, int &session) {
  if (n < 32) return false;
  const uint32_t receiver = le32(p + 4);
  const uint64_t counter = le64(p + 8);
  int i = 0;
  while (i < MAX_SESSIONS && !(sessions[i].used && sessions[i].local == receiver)) i++;
  if (i == MAX_SESSIONS) return false;
  WgSession &s = sessions[i];
  // Seen already, or older than the window: a replay.
  if (s.confirmed && (counter + 64 <= s.top || (counter <= s.top && ((s.window >> (s.top - counter)) & 1)))) return false;
  plain.resize(n - 32);
  if (vl_open(plain.data(), s.recv_key, counter, p + 16, n - 16, nullptr, 0) != 0) {
    plain.clear();
    return false;
  }
  if (!s.confirmed || counter > s.top) {
    uint64_t shift = s.confirmed ? counter - s.top : 64;
    s.window = shift >= 64 ? 1 : ((s.window << shift) | 1);
    s.top = counter;
  } else {
    s.window |= (uint64_t) 1 << (s.top - counter);
  }
  s.confirmed = true;
  session = i;
  return true;
}

bool WgResponder::seal(int i, const uint8_t *plain, size_t n, std::vector<uint8_t> &out) {
  if (i < 0 || i >= MAX_SESSIONS || !sessions[i].used || !sessions[i].confirmed) return false;
  WgSession &s = sessions[i];
  out.assign(16 + n + 16, 0);
  out[0] = 4;
  put_le32(out.data() + 4, s.remote);
  for (int b = 0; b < 8; b++) out[8 + b] = (uint8_t) (s.send_counter >> (8 * b));
  vl_seal(out.data() + 16, s.send_key, s.send_counter, plain, n, nullptr, 0);
  s.send_counter++;
  return true;
}

// ---- the initiator --------------------------------------------------------------

void WgInitiator::set_keys(const uint8_t secret[32], const uint8_t pub[32], const uint8_t peer[32]) {
  memcpy(secret_, secret, 32);
  memcpy(pub_, pub, 32);
  memcpy(peer_, peer, 32);
  vl_hash(mac1_key_, (const uint8_t *) LABEL_MAC1, 8, peer_, 32);
  cur_ = WgSession();
  prev_ = WgSession();
  pending_set_ = false;
}

void WgInitiator::initiation(const uint8_t tai64n[12], std::vector<uint8_t> &out) {
  out.assign(148, 0);
  uint8_t *m = out.data();
  m[0] = 1;
  random_bytes((uint8_t *) &pending_, 4);
  pending_set_ = true;
  put_le32(m + 4, pending_);
  uint8_t e_pub[32], k[32], dh[32], h0[32];
  vl_hash(ck_, (const uint8_t *) CONSTRUCTION, strlen(CONSTRUCTION), nullptr, 0);
  vl_hash(h0, ck_, 32, (const uint8_t *) IDENTIFIER, strlen(IDENTIFIER));
  vl_hash(h_, h0, 32, peer_, 32);
  random_bytes(e_, 32);
  crypto_x25519_public_key(e_pub, e_);
  vl_kdf(ck_, nullptr, nullptr, ck_, e_pub, 32);
  memcpy(m + 8, e_pub, 32);
  vl_hash(h_, h_, 32, e_pub, 32);
  crypto_x25519(dh, e_, peer_);
  vl_kdf(ck_, k, nullptr, ck_, dh, 32);
  vl_seal(m + 40, k, 0, pub_, 32, h_, 32);
  vl_hash(h_, h_, 32, m + 40, 48);
  crypto_x25519(dh, secret_, peer_);
  vl_kdf(ck_, k, nullptr, ck_, dh, 32);
  vl_seal(m + 88, k, 0, tai64n, 12, h_, 32);
  vl_hash(h_, h_, 32, m + 88, 28);
  vl_mac(m + 116, mac1_key_, m, 116);
  crypto_wipe(k, 32);
  crypto_wipe(dh, 32);
}

bool WgInitiator::response(const uint8_t *p, size_t n, uint32_t now_ms) {
  if (n != 92 || p[0] != 2 || !pending_set_ || le32(p + 8) != pending_) return false;
  uint8_t mac[16], my_mac1[32];
  vl_hash(my_mac1, (const uint8_t *) LABEL_MAC1, 8, pub_, 32);
  vl_mac(mac, my_mac1, p, 60);
  if (crypto_verify16(mac, p + 60) != 0) return false;
  const uint8_t *e_r = p + 12;
  uint8_t ck[32], h[32], dh[32], tau[32], k[32], empty[1];
  memcpy(ck, ck_, 32);
  memcpy(h, h_, 32);
  vl_kdf(ck, nullptr, nullptr, ck, e_r, 32);
  vl_hash(h, h, 32, e_r, 32);
  crypto_x25519(dh, e_, e_r);
  vl_kdf(ck, nullptr, nullptr, ck, dh, 32);
  crypto_x25519(dh, secret_, e_r);
  vl_kdf(ck, nullptr, nullptr, ck, dh, 32);
  static const uint8_t psk[32] = {0};
  vl_kdf(ck, tau, k, ck, psk, 32);
  vl_hash(h, h, 32, tau, 32);
  if (vl_open(empty, k, 0, p + 44, 16, h, 32) != 0) return false;
  prev_ = cur_;
  cur_ = WgSession();
  cur_.used = true;
  cur_.local = pending_;
  cur_.remote = le32(p + 4);
  cur_.made_ms = now_ms;
  // The initiator sends with the first key, receives with the second.
  vl_kdf(cur_.send_key, cur_.recv_key, nullptr, ck, nullptr, 0);
  pending_set_ = false;
  crypto_wipe(e_, 32);
  crypto_wipe(ck, 32);
  crypto_wipe(dh, 32);
  crypto_wipe(k, 32);
  return true;
}

bool WgInitiator::open_on(WgSession &s, const uint8_t *p, size_t n, std::vector<uint8_t> &plain) {
  if (!s.used || le32(p + 4) != s.local) return false;
  const uint64_t counter = le64(p + 8);
  if (s.confirmed && (counter + 64 <= s.top || (counter <= s.top && ((s.window >> (s.top - counter)) & 1)))) return false;
  plain.resize(n - 32);
  if (vl_open(plain.data(), s.recv_key, counter, p + 16, n - 16, nullptr, 0) != 0) {
    plain.clear();
    return false;
  }
  if (!s.confirmed || counter > s.top) {
    uint64_t shift = s.confirmed ? counter - s.top : 64;
    s.window = shift >= 64 ? 1 : ((s.window << shift) | 1);
    s.top = counter;
  } else {
    s.window |= (uint64_t) 1 << (s.top - counter);
  }
  s.confirmed = true;
  return true;
}

bool WgInitiator::open(const uint8_t *p, size_t n, std::vector<uint8_t> &plain) {
  if (n < 32 || p[0] != 4 || p[1] || p[2] || p[3]) return false;
  return open_on(cur_, p, n, plain) || open_on(prev_, p, n, plain);
}

bool WgInitiator::seal(const uint8_t *plain, size_t n, std::vector<uint8_t> &out) {
  if (!cur_.used) return false;
  out.assign(16 + n + 16, 0);
  out[0] = 4;
  put_le32(out.data() + 4, cur_.remote);
  for (int b = 0; b < 8; b++) out[8 + b] = (uint8_t) (cur_.send_counter >> (8 * b));
  vl_seal(out.data() + 16, cur_.send_key, cur_.send_counter, plain, n, nullptr, 0);
  cur_.send_counter++;
  return true;
}

}  // namespace vl
