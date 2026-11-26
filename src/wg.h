// The inner layer's far end (vØrk ADR-0005): a WireGuard responder without
// a network interface. Full nodes open end-to-end sessions to this node with
// boringtun (Noise_IKpsk2, no preshared key); their packets arrive in DATA
// messages on a path, and what this answers goes back on the same path.
// Openers are anonymous (a fresh static key per session), so any is taken.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include <vector>

namespace vl {

struct WgSession {
  bool used = false;
  uint32_t local = 0, remote = 0;
  uint8_t send_key[32] = {0}, recv_key[32] = {0};
  uint64_t send_counter = 0;
  /// Replay window: the highest counter seen and a bitmap below it.
  uint64_t top = 0, window = 0;
  bool confirmed = false;
  /// The path label it came on (where its answers go).
  uint64_t label = 0;
  uint32_t made_ms = 0;
  /// The opener's static key (fresh for each session: it says who only by identifying).
  uint8_t peer[32] = {0};
};

class WgResponder {
 public:
  static const int MAX_SESSIONS = 16;  // the owner's devices each keep one

  void set_static(const uint8_t secret[32], const uint8_t pub[32]);

  /// What a packet that came on `label` asks for: `out` gets a packet to
  /// send back on it (a handshake response); `plain` the payload of a
  /// transport packet (its session in `session`), empty for a keepalive.
  /// False if it was nothing to take.
  bool receive(uint64_t label, const uint8_t *p, size_t n, uint32_t now_ms, std::vector<uint8_t> &out, std::vector<uint8_t> &plain, int &session);

  /// `plain` sealed for session `s`: the packet to send on its label.
  bool seal(int s, const uint8_t *plain, size_t n, std::vector<uint8_t> &out);

  WgSession sessions[MAX_SESSIONS];

 private:
  bool initiation(uint64_t label, const uint8_t *p, size_t n, uint32_t now_ms, std::vector<uint8_t> &out);
  bool transport(const uint8_t *p, size_t n, std::vector<uint8_t> &plain, int &session);

  uint8_t secret_[32] = {0}, pub_[32] = {0};
  /// The chaining key's and the hash's start (the latter with our public key in it).
  uint8_t ck_start_[32] = {0}, h_start_[32] = {0};
  uint8_t mac1_key_[32] = {0};
};

/// The outer layer's near end (vØrk's link to a full node, as WireGuard
/// between neighbors): this device opens the session (Noise_IKpsk2, no
/// preshared key) with its own static key to the node's, and keeps it fresh.
class WgInitiator {
 public:
  void set_keys(const uint8_t secret[32], const uint8_t pub[32], const uint8_t peer[32]);
  /// A handshake initiation (148 bytes), with the time it's made (TAI64N).
  void initiation(const uint8_t tai64n[12], std::vector<uint8_t> &out);
  /// The node's response: true if it completes the handshake (the session's keys in place).
  bool response(const uint8_t *p, size_t n, uint32_t now_ms);
  /// A transport packet's plaintext (empty for a keepalive); false if it isn't genuine.
  bool open(const uint8_t *p, size_t n, std::vector<uint8_t> &plain);
  bool seal(const uint8_t *plain, size_t n, std::vector<uint8_t> &out);
  bool up() const { return cur_.used; }
  /// When the current session's keys were made (to make new ones in time).
  uint32_t keys_ms() const { return cur_.made_ms; }
  const uint8_t *peer() const { return peer_; }

 private:
  uint8_t secret_[32] = {0}, pub_[32] = {0}, peer_[32] = {0};
  uint8_t mac1_key_[32] = {0};
  /// The handshake under way.
  uint8_t ck_[32] = {0}, h_[32] = {0}, e_[32] = {0};
  uint32_t pending_ = 0;
  bool pending_set_ = false;
  /// The current session, and the one before (packets in flight on it are still taken).
  WgSession cur_, prev_;
  bool open_on(WgSession &s, const uint8_t *p, size_t n, std::vector<uint8_t> &plain);
};

}  // namespace vl
