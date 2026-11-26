// Primitives the Lite node needs, over Monocypher (X25519, Ed25519,
// ChaCha20, Poly1305) and the BLAKE2s reference code: WireGuard's hash, MAC,
// HMAC/KDF and AEAD (Noise IKpsk2, as boringtun on full nodes), and SHA-256
// for addresses.
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// BLAKE2s-256 of a ‖ b (b may be empty).
void vl_hash(uint8_t out[32], const uint8_t *a, size_t an, const uint8_t *b, size_t bn);
/// Keyed BLAKE2s, 16 bytes: WireGuard's MAC.
void vl_mac(uint8_t out[16], const uint8_t key[32], const uint8_t *in, size_t n);
/// HMAC-BLAKE2s.
void vl_hmac(uint8_t out[32], const uint8_t key[32], const uint8_t *in, size_t n);
/// WireGuard's KDF1..3 of (key, input): t1, t2, t3 (any may be NULL).
void vl_kdf(uint8_t *t1, uint8_t *t2, uint8_t *t3, const uint8_t key[32], const uint8_t *in, size_t n);
/// ChaCha20-Poly1305 (RFC 8439) with WireGuard's nonce (32 zero bits, then
/// the counter little-endian): out gets n + 16 bytes.
void vl_seal(uint8_t *out, const uint8_t key[32], uint64_t counter, const uint8_t *plain, size_t n, const uint8_t *ad, size_t adn);
/// The other way: out gets n - 16 bytes; 0 if it's genuine.
int vl_open(uint8_t *out, const uint8_t key[32], uint64_t counter, const uint8_t *cipher, size_t n, const uint8_t *ad, size_t adn);
void vl_sha256(uint8_t out[32], const uint8_t *a, size_t an, const uint8_t *b, size_t bn);

#ifdef __cplusplus
}
#endif
