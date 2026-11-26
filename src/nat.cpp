#include "nat.h"

#include <string.h>

namespace vl {

/// IPv6 packets stay within the inner MTU (1280): IPv4 TCP segments are kept that much smaller.
static const uint16_t MSS = 1280 - 40 - 20;

static uint16_t be16(const uint8_t *p) { return (uint16_t) (p[0] << 8 | p[1]); }
static void put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t) (v >> 8);
  p[1] = (uint8_t) v;
}

static uint32_t sum(const uint8_t *b, size_t n) {
  uint32_t s = 0;
  for (size_t i = 0; i + 1 < n; i += 2) s += be16(b + i);
  if (n & 1) s += (uint32_t) b[n - 1] << 8;
  return s;
}
static uint16_t fold(uint32_t s) {
  while (s >> 16) s = (s & 0xffff) + (s >> 16);
  return (uint16_t) s;
}
/// Where the transport checksum sits (IPv6 numbering for ICMP; -1: none).
static int checksum_at(uint8_t proto) {
  switch (proto) {
    case 6:
      return 16;
    case 17:
      return 6;
    case 58:
    case 1:
      return 2;
    default:
      return -1;
  }
}

static void clamp_mss(uint8_t *tcp, size_t n) {
  if (!(tcp[13] & 0x02)) return;
  size_t end = (size_t) (tcp[12] >> 4) * 4;
  if (end > n) end = n;
  size_t i = 20;
  while (i < end) {
    uint8_t kind = tcp[i];
    if (kind == 0) break;
    if (kind == 1) {
      i++;
      continue;
    }
    if (i + 1 >= end) break;
    uint8_t len = tcp[i + 1];
    if (len < 2 || i + len > end) break;
    if (kind == 2 && len == 4 && be16(tcp + i + 2) > MSS) put16(tcp + i + 2, MSS);
    i += len;
  }
}

void overlay(const uint8_t node[16], uint8_t out[16]) {
  out[0] = 0xfd;
  memcpy(out + 1, node, 15);
}

void derive_v4(const uint8_t node[16], uint8_t out[4]) {
  uint16_t v = be16(node);
  if (v < 256) v += 256;
  out[0] = 198;
  out[1] = 18;
  out[2] = (uint8_t) (v >> 8);
  out[3] = (uint8_t) v;
}

bool to_v6(const uint8_t *p, size_t n, const uint8_t src[16], const uint8_t dst[16], std::vector<uint8_t> &out) {
  if (n < 20 || p[0] >> 4 != 4) return false;
  size_t ihl = (size_t) (p[0] & 15) * 4, total = be16(p + 2);
  if (ihl < 20 || total > n || total < ihl || (be16(p + 6) & 0x3fff)) return false;
  size_t len = total - ihl;
  uint8_t next;
  switch (p[9]) {
    case 6:
      if (len < 20) return false;
      next = 6;
      break;
    case 17:
      if (len < 8) return false;
      next = 17;
      break;
    case 1:
      if (len < 8 || (p[ihl] != 8 && p[ihl] != 0)) return false;
      next = 58;
      break;
    default:
      return false;
  }
  out.assign(40 + len, 0);
  uint8_t *o = out.data();
  // No flow label: what this device sends are answers (it opens nothing),
  // and the far end gives an answer back the way its conversation began; a
  // node's FROM_V4 label would make it give IPv6 conversations as IPv4.
  o[0] = (uint8_t) (0x60 | (p[1] >> 4));
  o[1] = (uint8_t) (p[1] << 4);
  put16(o + 4, (uint16_t) len);
  o[6] = next;
  o[7] = p[8] ? p[8] : 1;
  memcpy(o + 8, src, 16);
  memcpy(o + 24, dst, 16);
  uint8_t *b = o + 40;
  memcpy(b, p + ihl, len);
  if (next == 6) clamp_mss(b, len);
  if (next == 58) b[0] = b[0] == 8 ? 128 : 129;
  int at = checksum_at(next);
  b[at] = b[at + 1] = 0;
  uint16_t c = (uint16_t) ~fold(sum(o + 8, 32) + (uint32_t) len + next + sum(b, len));
  if (c == 0 && next == 17) c = 0xffff;
  put16(b + at, c);
  return true;
}

bool to_v4(const uint8_t *p, size_t n, const uint8_t src[4], const uint8_t dst[4], std::vector<uint8_t> &out) {
  if (n < 40 || p[0] >> 4 != 6) return false;
  size_t len = be16(p + 4);
  if (n < 40 + len) return false;
  const uint8_t *b = p + 40;
  uint8_t proto;
  switch (p[6]) {
    case 6:
      if (len < 20) return false;
      proto = 6;
      break;
    case 17:
      if (len < 8) return false;
      proto = 17;
      break;
    case 58:
      if (len < 8 || (b[0] != 128 && b[0] != 129)) return false;
      proto = 1;
      break;
    default:
      return false;
  }
  size_t total = 20 + len;
  out.assign(total, 0);
  uint8_t *o = out.data();
  o[0] = 0x45;
  o[1] = (uint8_t) (p[0] << 4 | p[1] >> 4);
  put16(o + 2, (uint16_t) total);
  o[6] = 0x40;  // don't fragment
  o[8] = p[7] ? p[7] : 1;
  o[9] = proto;
  memcpy(o + 12, src, 4);
  memcpy(o + 16, dst, 4);
  put16(o + 10, (uint16_t) ~fold(sum(o, 20)));
  uint8_t *t = o + 20;
  memcpy(t, b, len);
  if (proto == 1) t[0] = t[0] == 128 ? 8 : 0;
  int at = checksum_at(proto);
  t[at] = t[at + 1] = 0;
  uint32_t pseudo = proto == 1 ? 0 : sum(o + 12, 8) + (uint32_t) len + proto;
  uint16_t c = (uint16_t) ~fold(pseudo + sum(t, len));
  if (c == 0 && proto == 17) c = 0xffff;
  put16(t + at, c);
  return true;
}

}  // namespace vl
