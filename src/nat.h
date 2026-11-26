// IP between vØrk and this device's IPv4 stack (vork/src/alias.rs, ADR-0021):
// sessions carry IPv6 between overlay addresses (fd + the first 15 bytes of a
// node's address); lwIP here speaks IPv4 on vØrk's range (198.18.0.0/15),
// and packets are translated on the way in and out, as full nodes do.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include <vector>

namespace vl {

/// A node's overlay IPv6 address.
void overlay(const uint8_t node[16], uint8_t out[16]);
/// A node's own IPv4 address, the same on every machine (198.18.0.0/16).
void derive_v4(const uint8_t node[16], uint8_t out[4]);
/// An IPv4 packet as IPv6 between `src` and `dst` (TCP, UDP, ping); false
/// for anything else (fragments, other protocols).
bool to_v6(const uint8_t *p, size_t n, const uint8_t src[16], const uint8_t dst[16], std::vector<uint8_t> &out);
/// An IPv6 packet as IPv4 between `src` and `dst`.
bool to_v4(const uint8_t *p, size_t n, const uint8_t src[4], const uint8_t dst[4], std::vector<uint8_t> &out);

}  // namespace vl
