// vØrk Lite: an ESP32 as a Lite node of vØrk (https://github.com/vooteleaer/vork).
//
// The device links to a full node itself (vØrk's outer WireGuard, its own
// key), speaks vØrk's network layer there, announces itself by its own
// address and answers the end-to-end sessions full nodes open to it. It has
// an IPv4 address on vØrk's range (198.18.x.y) in lwIP, and the owner's
// devices reach its sockets there: anything listening on the device answers
// them over vØrk, wherever they are.
//
//   vorklite::Node node;
//   node.set_name("sensor");
//   // once the network is up:
//   node.start();
//   for (;;) { node.loop(); vTaskDelay(pdMS_TO_TICKS(10)); }
//
// or `node.start_task()`, which does that in a task of its own.
#pragma once

#include <array>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <lwip/netif.h>

namespace vl {
class WgResponder;
class WgInitiator;
}  // namespace vl

namespace vorklite {

namespace detail {
struct Inner;
struct Peer;
struct Candidate;
}  // namespace detail

/// Where the node keeps what outlives a restart: its identity, its owner's
/// devices and a start counter. The default is NVS (namespace "vork_lite").
class Store {
 public:
  virtual ~Store() = default;
  /// The `n` bytes kept under `name` into `data`; false if none are kept.
  virtual bool load(const char *name, void *data, size_t n) = 0;
  virtual void save(const char *name, const void *data, size_t n) = 0;
};

enum class Level { ERROR = 1, WARN, INFO, DEBUG, VERBOSE };

/// A service made known on the owner's devices' local networks for this
/// device (mDNS at its vØrk address), so it's found there as if it were on
/// their LAN: `_http._tcp`, `_esphomelib._tcp`...
struct Service {
  std::string type;
  std::string name;
  uint16_t port = 0;
  std::map<std::string, std::string> txt;
};

class Node {
 public:
  Node();
  ~Node();
  Node(const Node &) = delete;
  Node &operator=(const Node &) = delete;

  // ---- before start() ----

  /// The name it's announced by (the owner's devices call it `<name>.vork`).
  void set_name(const std::string &name) { this->name_ = name; }
  /// Its identity from a vØrk key file (`vork keygen`): 64 bytes as 128 hex
  /// digits, X25519 secret then Ed25519 seed. Without one, the device makes
  /// its own on its first start and keeps it. False if it isn't such a key.
  bool set_key(const std::string &hex);
  /// Full nodes to link to when none is found on the local network
  /// ("host:port"). vØrk's public bootstrap node when none is given.
  void add_upstream(const std::string &hostport) { this->upstreams_.push_back(hostport); }
  /// A node let in by its address (32 hex digits), besides the owner's devices.
  bool add_device(const std::string &hex);
  /// Where the identity and the owner are kept (default: NVS). Not owned.
  void set_store(Store *store) { this->store_ = store; }
  /// Where its log goes (default: ESP-IDF's log, tag "vork_lite").
  void set_logger(std::function<void(Level, const char *)> log) { this->log_ = std::move(log); }
  /// Over a tunnel someone else keeps (the device 10.89.0.2, the full node
  /// 10.89.0.1, as ESPHome's `wireguard:` makes one) instead of its own
  /// link: `up` says whether the tunnel is up.
  void set_tunnel(std::function<bool()> up) { this->tunnel_up_ = std::move(up); }
  /// A service named to the owner's devices (see Service).
  void add_service(const Service &s) { this->services_.push_back(s); }
  /// Services worked out when the owner's devices ask (for values that change).
  void set_services(std::function<void(std::vector<Service> &)> f) { this->services_cb_ = std::move(f); }

  // ---- running ----

  /// Starts it, once the network is up (only with the radio on does the
  /// chip's random number generator give true randomness, and the identity
  /// and the link's code are made of it). Needs about 16 kB of stack.
  bool start();
  /// Its work: call it often (every 10–20 ms) from one task.
  void loop();
  /// start() once the station has an IPv4 address, then loop(), in a task of
  /// its own (16 kB of stack).
  bool start_task(int priority = 5, int core = -1);

  // ---- what it is ----

  bool started() const { return this->started_; }
  /// Its vØrk address (32 hex digits).
  std::string address() const;
  const std::string &name() const { return this->name_; }
  /// Its IPv4 address on vØrk (198.18.x.y).
  std::array<uint8_t, 4> ipv4() const;
  /// What the owner pastes into a vØrk dashboard (Devices) to link it; with
  /// a one-time code while it has no owner.
  std::string link() const;
  /// Whether it's linked to a full node, and that node has said hello.
  bool online() const { return this->heard_hello_ms_ != 0; }
  /// The owner's devices it knows of (and those let in by add_device).
  size_t devices() const { return this->owner_.size() + this->devices_.size(); }
  /// Whether `address` (16 bytes) is one of the owner's devices or let in.
  bool trusted(const uint8_t address[16]) const;

  /// A packet lwIP sends on the vØrk interface (in whichever task sends it).
  void queue_out(const uint8_t *p, size_t n);

 private:
  void logf_(Level level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
  uint32_t now_() const;
  void derive_keys_(const uint8_t k[64]);
  std::string owner_name_() const;
  void load_owner_();
  void save_owner_();
  void new_code_();
  bool owner_has_(const uint8_t who[16]) const;
  bool own_link_() const { return !this->tunnel_up_; }
  bool linked_();
  void send_(const std::vector<uint8_t> &msg);
  void send_to_(uint32_t ip, uint16_t port, const uint8_t *p, size_t n);
  void send_hello_();
  void send_announce_();
  void on_message_(const uint8_t *m, size_t n);
  void on_data_(uint64_t label, const uint8_t *inner, size_t n);
  void on_app_(int session, const uint8_t *body, size_t n);
  void send_app_(int session, const uint8_t *body, size_t n);
  void on_segment_(int session, uint32_t seq, const uint8_t *data, size_t n);
  void on_stream_message_(int session, const uint8_t *m, size_t n);
  void ask_who_(int session);
  void on_ip_(int session, const uint8_t *p, size_t n);
  void send_ip_(const std::vector<uint8_t> &v4);
  bool start_netif_();
  void on_request_(int session, uint32_t id, const std::string &path, const uint8_t *body, size_t n);
  void on_link_request_(int session, uint32_t id, const std::string &body);
  void on_group_(int session, uint32_t id, const std::string &body);
  void on_paths_(int session, uint32_t id);
  void respond_(int session, uint32_t id, uint8_t status, const std::string &body);
  void send_message_(int session, const std::vector<uint8_t> &m);
  void resend_(uint32_t now);
  detail::Inner &inner_(int session);
  detail::Peer *peer_(const uint8_t who[16]);
  // The device's own link to a full node.
  void seek_(uint32_t now);
  void handshake_(uint32_t now);
  void link_down_(const char *why);
  void on_outer_(uint32_t ip, uint16_t port, const uint8_t *p, size_t n);
  void stamp_(uint8_t tai64n[12]);

  std::string name_;
  Store *store_{nullptr};
  Store *own_store_{nullptr};
  std::function<void(Level, const char *)> log_;
  std::function<bool()> tunnel_up_;
  std::vector<Service> services_;
  std::function<void(std::vector<Service> &)> services_cb_;
  std::vector<std::string> upstreams_;
  std::vector<std::array<uint8_t, 16>> devices_;
  std::vector<std::array<uint8_t, 16>> owner_;

  bool started_{false};
  bool key_given_{false}, key_ok_{true};
  uint8_t key_[64]{};
  std::string code_;
  uint8_t ed_secret_[64]{}, ed_pub_[32]{}, x_secret_[32]{}, x_pub_[32]{};
  uint8_t address_[16]{};
  uint8_t v4_[4]{};

  struct netif netif_ {};
  bool netif_up_{false};
  std::mutex out_lock_;
  std::deque<std::vector<uint8_t>> out_;
  uint32_t ip_in_{0}, ip_out_{0};

  int sock_{-1};
  ::vl::WgResponder *wg_;
  ::vl::WgInitiator *outer_;
  detail::Inner *inner_s_;
  detail::Peer *peers_;
  int npeers_{0};
  std::vector<detail::Candidate> *cands_;
  int up_{-1};
  bool link_up_{false};
  uint8_t tries_{0};
  uint32_t init_ms_{0}, last_rx_ms_{0}, last_tx_ms_{0}, seek_ms_{0}, ask_ms_{0};
  /// Starts counted in the store: the handshakes' timestamps and the
  /// announces' sequence numbers grow across restarts without a clock.
  uint32_t boot_{0};
  void *mdns_search_{nullptr};
  uint32_t heard_hello_ms_{0}, last_hello_ms_{0}, last_announce_ms_{0};
  uint32_t pings_{0}, paths_{0};
};

}  // namespace vorklite
