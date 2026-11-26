#include "crypto.h"

#include <string.h>

#include "monocypher.h"


#ifndef VL_HOST_TEST
#include "mbedtls/sha256.h"
#endif

static void nonce_of(uint8_t nonce[12], uint64_t counter) {
  memset(nonce, 0, 4);
  for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t) (counter >> (8 * i));
}

static void tag(uint8_t mac[16], const uint8_t poly_key[32], const uint8_t *ad, size_t adn, const uint8_t *ct, size_t n) {
  static const uint8_t zero[16] = {0};
  crypto_poly1305_ctx p;
  crypto_poly1305_init(&p, poly_key);
  crypto_poly1305_update(&p, ad, adn);
  crypto_poly1305_update(&p, zero, (16 - adn % 16) % 16);
  crypto_poly1305_update(&p, ct, n);
  crypto_poly1305_update(&p, zero, (16 - n % 16) % 16);
  uint8_t lens[16];
  for (int i = 0; i < 8; i++) {
    lens[i] = (uint8_t) ((uint64_t) adn >> (8 * i));
    lens[8 + i] = (uint8_t) ((uint64_t) n >> (8 * i));
  }
  crypto_poly1305_update(&p, lens, 16);
  crypto_poly1305_final(&p, mac);
}

void vl_seal(uint8_t *out, const uint8_t key[32], uint64_t counter, const uint8_t *plain, size_t n, const uint8_t *ad, size_t adn) {
  uint8_t nonce[12], block[64] = {0};
  nonce_of(nonce, counter);
  crypto_chacha20_ietf(block, block, 64, key, nonce, 0);
  crypto_chacha20_ietf(out, plain, n, key, nonce, 1);
  tag(out + n, block, ad, adn, out, n);
  crypto_wipe(block, sizeof block);
}

int vl_open(uint8_t *out, const uint8_t key[32], uint64_t counter, const uint8_t *cipher, size_t n, const uint8_t *ad, size_t adn) {
  if (n < 16) return -1;
  size_t m = n - 16;
  uint8_t nonce[12], block[64] = {0}, mac[16];
  nonce_of(nonce, counter);
  crypto_chacha20_ietf(block, block, 64, key, nonce, 0);
  tag(mac, block, ad, adn, cipher, m);
  crypto_wipe(block, sizeof block);
  if (crypto_verify16(mac, cipher + m) != 0) return -1;
  crypto_chacha20_ietf(out, cipher, m, key, nonce, 1);
  return 0;
}

#ifndef VL_HOST_TEST
void vl_sha256(uint8_t out[32], const uint8_t *a, size_t an, const uint8_t *b, size_t bn) {
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, a, an);
  mbedtls_sha256_update(&c, b, bn);
  mbedtls_sha256_finish(&c, out);
  mbedtls_sha256_free(&c);
}
#endif
