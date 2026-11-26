#include "vork_lite/node.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>

#include <esp_log.h>
#include <esp_netif.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <lwip/inet.h>
#include <lwip/netdb.h>
#include <lwip/pbuf.h>
#include <lwip/sockets.h>
#include <lwip/tcpip.h>
#include <mdns.h>
#include <nvs.h>
#include <nvs_flash.h>

#include "crypto.h"
#include "monocypher-ed25519.h"
#include "monocypher.h"
#include "nat.h"
#include "wg.h"

namespace vorklite {

static const char *const TAG = "vork_lite";

// vØrk's network layer (vork/src/wire.rs, identity.rs).
static const uint16_t L0_PORT = 4799;
static const char *const TUNNEL_PEER = "10.89.0.1";
/// vØrk's bootstrap list (vork/bootstrap.txt).
static const char *const BOOTSTRAP[] = {"88.196.217.196:51821"};
// Asking a node's key at its address (vork node.rs: KEY_ASK, KEY_TELL).
static const char KEY_ASK[] = "VORK?", KEY_TELL[] = "VORK!";
/// The outer link: new keys every two minutes, down after three silent ones; a
/// keepalive through NATs; a handshake asked again after five seconds.
static const uint32_t REKEY_MS = 120000, DEAD_MS = 180000, KEEPALIVE_MS = 25000, RETRY_MS = 5000;
static const char LABEL_BIND[] = "vork/v0/bind";
static const char LABEL_ANNOUNCE[] = "vork/v0/announce";
static const uint8_t T_HELLO = 1, T_ANNOUNCE = 3, T_PATH_OPEN = 6, T_PATH_ACK = 7, T_PATH_ERR = 8, T_DATA = 9, T_PROBE = 10;
/// A Lite node: no RELAY flag (it forwards nothing, and gets no floods).
static const uint8_t FLAGS = 0;
/// Its announce also says it takes no part in linking (wire::FLAG_NO_LINKING):
/// an owner links it on their side alone.
static const uint8_t ANNOUNCE_FLAGS = FLAGS | 2;
static const uint32_t HELLO_EVERY_MS = 60000, HELLO_UNTIL_HEARD_MS = 5000, ANNOUNCE_EVERY_MS = 30000;
// The app messages inside a session (vork/src/node.rs).
static const uint8_t APP_PING = 1, APP_PONG = 2, APP_IP = 5, APP_SEG = 8, APP_ACK = 9, APP_WHO = 10;
// Messages on a session's stream.
static const uint8_t MSG_REQUEST = 1, MSG_RESPONSE = 2, MSG_IDENTIFY = 3;
static const uint8_t STATUS_OK = 0, STATUS_REFUSED = 2;
/// Payload bytes in a stream segment (stream::SEG_DATA).
static const size_t SEG_DATA = 1180;
/// The owner's devices kept.
static const int MAX_OWNER = 16;
struct OwnerBlob {
  uint8_t n;
  uint8_t a[MAX_OWNER][16];
};
struct KeyBlob {
  uint8_t set;
  uint8_t k[64];
};
static const char LABEL_SESSION[] = "vork/v0/session";
static const char LABEL_IDENTIFY[] = "vork/v0/identify";
/// The longest stream message kept (an identification is 129 bytes); longer ones are skipped.
static const size_t MAX_MESSAGE = 2048;
/// The vØrk interface: IPv4 that's 1280 bytes as IPv6.
static const uint16_t NETIF_MTU = 1260;
static const size_t MAX_QUEUED = 32;
static const int MAX_PEERS = 8;

namespace detail {

/// What the inner layer knows of a session beyond WireGuard: its stream
/// (only what comes in order is taken) and who identified in it.
struct Inner {
  uint32_t local = 0;
  uint32_t rcv_next = 0;
  uint32_t inc = 0;
  std::vector<uint8_t> rbuf;
  size_t skip = 0;
  bool identified = false;
  uint8_t who[16]{};
  uint32_t asked_ms = 0;
  /// This end's side of the stream: segments sent until acknowledged.
  uint32_t snd_next = 0;
  struct Seg {
    uint32_t seq;
    std::vector<uint8_t> data;
    uint32_t sent_ms;
    uint8_t tries;
  };
  std::vector<Seg> unacked;
};

/// Nodes IP goes to and from, by their IPv4 address here.
struct Peer {
  uint8_t who[16]{};
  uint8_t v4[4]{};
  int session = -1;
};

/// A full node to link to: found on the local network (mDNS), or an upstream.
struct Candidate {
  uint32_t ip = 0;  // network order
  uint16_t port = 0;
  uint8_t key[32]{};
  bool has_key = false;
  bool lan = false;
  uint8_t fails = 0;
  uint64_t nonce = 0;
};

}  // namespace detail

using detail::Candidate;
using detail::Inner;
using detail::Peer;

// ---- small helpers ------------------------------------------------------------

static void put_be32(std::vector<uint8_t> &b, uint32_t v) {
  for (int i = 3; i >= 0; i--) b.push_back((uint8_t) (v >> (8 * i)));
}
static uint32_t be32(const uint8_t *p) { return (uint32_t) p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static void put_be64(std::vector<uint8_t> &b, uint64_t v) {
  for (int i = 7; i >= 0; i--) b.push_back((uint8_t) (v >> (8 * i)));
}
static uint64_t be64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = v << 8 | p[i];
  return v;
}

static std::string hex(const uint8_t *p, size_t n) {
  static const char d[] = "0123456789abcdef";
  std::string s;
  s.reserve(2 * n);
  for (size_t i = 0; i < n; i++) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}

static int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool unhex(const std::string &s, uint8_t *out, size_t n) {
  if (s.size() != 2 * n) return false;
  for (size_t i = 0; i < n; i++) {
    int a = nibble(s[2 * i]), b = nibble(s[2 * i + 1]);
    if (a < 0 || b < 0) return false;
    out[i] = (uint8_t) (a << 4 | b);
  }
  return true;
}

static std::string quote(const std::string &s) {
  std::string o = "\"";
  for (char ch : s) {
    if (ch == '"' || ch == '\\') o += '\\';
    if ((unsigned char) ch >= 0x20) o += ch;
  }
  return o + "\"";
}

static std::string ip_str(uint32_t ip) {
  struct in_addr a;
  a.s_addr = ip;
  return inet_ntoa(a);
}

/// An IPv4/UDP datagram to port 4799, as vØrk frames messages in a session (wire::frame).
/// `up`: from this device to its full node (10.89.0.2 → 10.89.0.1), as on the outer link.
static std::vector<uint8_t> frame(const uint8_t *payload, size_t n, bool up = false) {
  size_t total = 28 + n;
  uint8_t a = up ? 2 : 1, b = up ? 1 : 2;
  std::vector<uint8_t> p = {0x45, 0, (uint8_t) (total >> 8), (uint8_t) total, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 89, 0, a, 10, 89, 0, b};
  uint32_t sum = 0;
  for (int i = 0; i < 20; i += 2) sum += (uint32_t) p[i] << 8 | p[i + 1];
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  sum = ~sum & 0xffff;
  p[10] = (uint8_t) (sum >> 8);
  p[11] = (uint8_t) sum;
  size_t udp = 8 + n;
  uint8_t h[8] = {L0_PORT >> 8, L0_PORT & 0xff, L0_PORT >> 8, L0_PORT & 0xff, (uint8_t) (udp >> 8), (uint8_t) udp, 0, 0};
  p.insert(p.end(), h, h + 8);
  p.insert(p.end(), payload, payload + n);
  return p;
}

/// The payload of such a datagram (wire::unframe); addresses are ignored.
static bool unframe(const uint8_t *p, size_t n, const uint8_t *&body, size_t &len) {
  if (n < 28 || p[0] >> 4 != 4 || p[9] != 17) return false;
  size_t ihl = (p[0] & 0x0f) * 4;
  if (n < ihl + 8) return false;
  const uint8_t *u = p + ihl;
  if ((u[2] << 8 | u[3]) != L0_PORT) return false;
  size_t l = u[4] << 8 | u[5];
  if (l < 8 || ihl + l > n) return false;
  body = u + 8;
  len = l - 8;
  return true;
}

// ---- the default store: NVS -----------------------------------------------------

namespace {
class NvsStore : public Store {
 public:
  bool load(const char *name, void *data, size_t n) override {
    if (!this->open_()) return false;
    std::string k = key_(name);
    size_t len = n;
    return nvs_get_blob(this->h_, k.c_str(), data, &len) == ESP_OK && len == n;
  }
  void save(const char *name, const void *data, size_t n) override {
    if (!this->open_()) return;
    std::string k = key_(name);
    if (nvs_set_blob(this->h_, k.c_str(), data, n) == ESP_OK) nvs_commit(this->h_);
  }

 private:
  /// NVS keys are 15 characters at most: a name's FNV-1a hash.
  static std::string key_(const char *name) {
    uint32_t h = 2166136261u;
    for (const char *c = name; *c; c++) h = (h ^ (uint8_t) *c) * 16777619u;
    char b[12];
    snprintf(b, sizeof b, "v%08lx", (unsigned long) h);
    return b;
  }
  bool open_() {
    if (this->open_done_) return this->h_ != 0;
    this->open_done_ = true;
    esp_err_t e = nvs_open("vork_lite", NVS_READWRITE, &this->h_);
    if (e == ESP_ERR_NVS_NOT_INITIALIZED) {
      nvs_flash_init();
      e = nvs_open("vork_lite", NVS_READWRITE, &this->h_);
    }
    if (e != ESP_OK) this->h_ = 0;
    return this->h_ != 0;
  }
  nvs_handle_t h_{0};
  bool open_done_{false};
};
}  // namespace

// ---- lwIP's side of the vØrk interface ------------------------------------------

// In lwIP's or a sending task's context. The node isn't the interface's
// `state`: ESP-IDF takes any interface's state for its own interface
// structure (without LWIP_ESP_NETIF_DATA).
static Node *s_node = nullptr;
static err_t netif_output(struct netif *nif, struct pbuf *p, const ip4_addr_t *) {
  uint8_t buf[NETIF_MTU];
  if (p->tot_len > sizeof buf) return ERR_OK;
  uint16_t n = pbuf_copy_partial(p, buf, p->tot_len, 0);
  if (s_node != nullptr) s_node->queue_out(buf, n);
  return ERR_OK;
}
static err_t netif_init_fn(struct netif *nif) {
  nif->name[0] = 'v';
  nif->name[1] = 'k';
  nif->output = netif_output;
  nif->mtu = NETIF_MTU;
  nif->flags = 0;  // point to point: no ARP, no broadcast
  return ERR_OK;
}

struct NetifAdd {
  struct netif *nif;
  ip4_addr_t ip, mask, gw;
  bool ok;
  SemaphoreHandle_t done;
};
static void netif_add_fn(void *arg) {
  auto *a = (NetifAdd *) arg;
  a->ok = netif_add(a->nif, &a->ip, &a->mask, &a->gw, nullptr, netif_init_fn, tcpip_input) != nullptr;
  if (a->ok) {
    netif_set_up(a->nif);
    netif_set_link_up(a->nif);
  }
  if (a->done != nullptr) xSemaphoreGive(a->done);
}

// ---- the node ---------------------------------------------------------------------

Node::Node()
    : wg_(new ::vl::WgResponder()),
      outer_(new ::vl::WgInitiator()),
      inner_s_(new Inner[::vl::WgResponder::MAX_SESSIONS]),
      peers_(new Peer[MAX_PEERS]),
      cands_(new std::vector<Candidate>()) {}

Node::~Node() {
  // The interface and the socket stay: a node lives as long as the firmware.
  delete this->cands_;
  delete[] this->peers_;
  delete[] this->inner_s_;
  delete this->outer_;
  delete this->wg_;
  delete this->own_store_;
}

void Node::logf_(Level level, const char *fmt, ...) {
  char b[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(b, sizeof b, fmt, ap);
  va_end(ap);
  if (this->log_) return this->log_(level, b);
  switch (level) {
    case Level::ERROR:
      ESP_LOGE(TAG, "%s", b);
      break;
    case Level::WARN:
      ESP_LOGW(TAG, "%s", b);
      break;
    case Level::INFO:
      ESP_LOGI(TAG, "%s", b);
      break;
    case Level::DEBUG:
      ESP_LOGD(TAG, "%s", b);
      break;
    default:
      ESP_LOGV(TAG, "%s", b);
      break;
  }
}

uint32_t Node::now_() const { return (uint32_t) (esp_timer_get_time() / 1000); }

bool Node::set_key(const std::string &h) {
  this->key_given_ = true;
  this->key_ok_ = unhex(h, this->key_, 64);
  return this->key_ok_;
}

bool Node::add_device(const std::string &h) {
  std::array<uint8_t, 16> a;
  if (!unhex(h, a.data(), 16)) return false;
  this->devices_.push_back(a);
  return true;
}

std::string Node::address() const { return hex(this->address_, 16); }

std::array<uint8_t, 4> Node::ipv4() const { return {this->v4_[0], this->v4_[1], this->v4_[2], this->v4_[3]}; }

void Node::derive_keys_(const uint8_t k[64]) {
  // A vØrk key file's 64 bytes: X25519 secret, then Ed25519 seed.
  memcpy(this->x_secret_, k, 32);
  uint8_t seed[32];
  memcpy(seed, k + 32, 32);
  crypto_ed25519_key_pair(this->ed_secret_, this->ed_pub_, seed);  // wipes the seed copy
  crypto_x25519_public_key(this->x_pub_, this->x_secret_);
}

void Node::new_code_() {
  uint8_t c[8];
  esp_fill_random(c, sizeof c);
  this->code_ = hex(c, sizeof c);
}

/// The owner is this identity's: kept under its address, so another identity starts with none.
std::string Node::owner_name_() const { return "owner" + hex(this->address_, 16); }

void Node::load_owner_() {
  OwnerBlob b{};
  if (this->store_->load(this->owner_name_().c_str(), &b, sizeof b) && b.n <= MAX_OWNER) {
    for (int i = 0; i < b.n; i++) {
      std::array<uint8_t, 16> a;
      memcpy(a.data(), b.a[i], 16);
      this->owner_.push_back(a);
    }
  }
  std::sort(this->owner_.begin(), this->owner_.end());
}

void Node::save_owner_() {
  OwnerBlob b{};
  b.n = (uint8_t) std::min<size_t>(this->owner_.size(), MAX_OWNER);
  for (int i = 0; i < b.n; i++) memcpy(b.a[i], this->owner_[i].data(), 16);
  this->store_->save(this->owner_name_().c_str(), &b, sizeof b);
}

bool Node::owner_has_(const uint8_t who[16]) const {
  for (auto &d : this->owner_)
    if (memcmp(d.data(), who, 16) == 0) return true;
  return false;
}

bool Node::trusted(const uint8_t who[16]) const {
  for (auto &d : this->devices_)
    if (memcmp(d.data(), who, 16) == 0) return true;
  return this->owner_has_(who);
}

void Node::queue_out(const uint8_t *p, size_t n) {
  std::lock_guard<std::mutex> g(this->out_lock_);
  if (this->out_.size() >= MAX_QUEUED) return;
  this->out_.emplace_back(p, p + n);
}

bool Node::start_netif_() {
  // This device's own address on vØrk's range, the range (198.18.0.0/15) on this interface.
  NetifAdd a{};
  a.nif = &this->netif_;
  IP4_ADDR(&a.ip, this->v4_[0], this->v4_[1], this->v4_[2], this->v4_[3]);
  IP4_ADDR(&a.mask, 255, 254, 0, 0);
  IP4_ADDR(&a.gw, 0, 0, 0, 0);
  s_node = this;
#if LWIP_TCPIP_CORE_LOCKING
  LOCK_TCPIP_CORE();
  netif_add_fn(&a);
  UNLOCK_TCPIP_CORE();
#else
  a.done = xSemaphoreCreateBinary();
  if (a.done == nullptr || tcpip_callback(netif_add_fn, &a) != ERR_OK) {
    if (a.done != nullptr) vSemaphoreDelete(a.done);
    return false;
  }
  xSemaphoreTake(a.done, portMAX_DELAY);
  vSemaphoreDelete(a.done);
#endif
  this->netif_up_ = a.ok;
  if (!a.ok) this->logf_(Level::ERROR, "the vØrk interface couldn't be added");
  return a.ok;
}

Inner &Node::inner_(int session) {
  Inner &in = this->inner_s_[session];
  // A new session in the slot: its stream starts afresh, and nobody's identified in it.
  if (in.local != this->wg_->sessions[session].local) {
    in = Inner();
    in.local = this->wg_->sessions[session].local;
    in.inc = esp_random();
  }
  return in;
}

Peer *Node::peer_(const uint8_t who[16]) {
  for (int i = 0; i < this->npeers_; i++)
    if (memcmp(this->peers_[i].who, who, 16) == 0) return &this->peers_[i];
  if (this->npeers_ == MAX_PEERS) return nullptr;
  Peer &p = this->peers_[this->npeers_];
  memcpy(p.who, who, 16);
  // Its own address, as everywhere; a local one (198.19.0.x) if that's taken here.
  ::vl::derive_v4(who, p.v4);
  bool taken = memcmp(p.v4, this->v4_, 4) == 0;
  for (int i = 0; i < this->npeers_; i++) taken |= memcmp(this->peers_[i].v4, p.v4, 4) == 0;
  if (taken) {
    uint8_t local[4] = {198, 19, 0, (uint8_t) (this->npeers_ + 1)};
    memcpy(p.v4, local, 4);
  }
  this->npeers_++;
  return &p;
}

/// The device's link (as a full node's QR code carries; it takes no part in
/// linking, so an owner's node links it at once).
std::string Node::link() const {
  std::string name;
  for (char ch : this->name_) {
    if (isalnum((unsigned char) ch) || ch == '-' || ch == '.' || ch == '_' || ch == '~') {
      name += ch;
    } else {
      char b[4];
      snprintf(b, sizeof b, "%%%02X", (unsigned char) ch);
      name += b;
    }
  }
  std::string link = "vork-link:" + hex(this->address_, 16);
  // Until it has an owner: the code that makes whoever brings it the owner.
  if (!this->code_.empty()) link += "?c=" + this->code_ + "&n=" + name;
  else link += "?n=" + name;
  return link;
}

bool Node::start() {
  if (this->started_) return true;
  if (!this->key_ok_) {
    this->logf_(Level::ERROR, "the key isn't 128 hex digits");
    return false;
  }
  if (this->store_ == nullptr) this->store_ = this->own_store_ = new NvsStore();
  if (this->name_.empty()) this->name_ = "lite";
  if (this->upstreams_.empty())
    for (const char *b : BOOTSTRAP) this->upstreams_.push_back(b);
  if (!this->key_given_) {
    // Its own identity, made on the first start and kept.
    KeyBlob b{};
    if (!this->store_->load("key", &b, sizeof b) || b.set != 1) {
      b.set = 1;
      esp_fill_random(b.k, sizeof b.k);
      this->store_->save("key", &b, sizeof b);
      this->logf_(Level::INFO, "made this device's vØrk identity");
    }
    memcpy(this->key_, b.k, 64);
    crypto_wipe(b.k, sizeof b.k);
  }
  this->derive_keys_(this->key_);
  crypto_wipe(this->key_, sizeof this->key_);
  // The address: SHA-256(X25519 public ‖ Ed25519 public)[0..16].
  uint8_t h[32];
  vl_sha256(h, this->x_pub_, 32, this->ed_pub_, 32);
  memcpy(this->address_, h, 16);
  this->load_owner_();
  if (this->owner_.empty()) this->new_code_();
  this->wg_->set_static(this->x_secret_, this->x_pub_);
  ::vl::derive_v4(this->address_, this->v4_);
  if (!this->start_netif_()) return false;
  {
    // This start's number.
    uint32_t b = 0;
    this->store_->load("boot", &b, sizeof b);
    this->boot_ = b + 1;
    this->store_->save("boot", &this->boot_, sizeof this->boot_);
  }
  // mDNS to find full nodes on the local network (already started by the firmware, or here).
  if (this->own_link_()) mdns_init();
  this->sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (this->sock_ < 0) {
    this->logf_(Level::ERROR, "no socket");
    return false;
  }
  struct sockaddr_in a {};
  a.sin_family = AF_INET;
  a.sin_port = htons(L0_PORT);
  a.sin_addr.s_addr = htonl(INADDR_ANY);
  if (::bind(this->sock_, (struct sockaddr *) &a, sizeof a) < 0) {
    this->logf_(Level::ERROR, "can't listen on port %u", L0_PORT);
    ::close(this->sock_);
    this->sock_ = -1;
    return false;
  }
  int flags = ::fcntl(this->sock_, F_GETFL, 0);
  ::fcntl(this->sock_, F_SETFL, flags | O_NONBLOCK);
  this->started_ = true;
  this->logf_(Level::INFO, "this device is %s (%u.%u.%u.%u); its link: %s", this->address().c_str(), this->v4_[0],
              this->v4_[1], this->v4_[2], this->v4_[3], this->link().c_str());
  return true;
}

static void node_task(void *arg) {
  auto *node = (Node *) arg;
  // Waits for the station's IPv4 address.
  for (;;) {
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta == nullptr) sta = esp_netif_get_default_netif();
    esp_netif_ip_info_t ip{};
    if (sta != nullptr && esp_netif_get_ip_info(sta, &ip) == ESP_OK && ip.ip.addr != 0) break;
    vTaskDelay(pdMS_TO_TICKS(500));
  }
  if (!node->start()) {
    vTaskDelete(nullptr);
    return;
  }
  for (;;) {
    node->loop();
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

bool Node::start_task(int priority, int core) {
  BaseType_t r;
  if (core < 0) {
    r = xTaskCreate(node_task, "vork_lite", 16384, this, priority, nullptr);
  } else {
    r = xTaskCreatePinnedToCore(node_task, "vork_lite", 16384, this, priority, nullptr, core);
  }
  return r == pdPASS;
}

bool Node::linked_() {
  if (this->tunnel_up_) return this->tunnel_up_();
  return this->link_up_;
}

void Node::send_to_(uint32_t ip, uint16_t port, const uint8_t *p, size_t n) {
  struct sockaddr_in to {};
  to.sin_family = AF_INET;
  to.sin_port = htons(port);
  to.sin_addr.s_addr = ip;
  ::sendto(this->sock_, p, n, 0, (struct sockaddr *) &to, sizeof to);
}

void Node::send_(const std::vector<uint8_t> &msg) {
  if (this->sock_ < 0) return;
  if (this->own_link_()) {
    if (!this->link_up_ || this->up_ < 0) return;
    std::vector<uint8_t> framed = frame(msg.data(), msg.size(), true), sealed;
    if (!this->outer_->seal(framed.data(), framed.size(), sealed)) return;
    Candidate &c = (*this->cands_)[this->up_];
    this->send_to_(c.ip, c.port, sealed.data(), sealed.size());
    this->last_tx_ms_ = this->now_();
    return;
  }
  struct in_addr peer;
  inet_aton(TUNNEL_PEER, &peer);
  this->send_to_(peer.s_addr, L0_PORT, msg.data(), msg.size());
}

void Node::send_hello_() {
  // HELLO binds the link's WireGuard key to the signing key: sign(bind ‖ x_pub ‖ flags).
  uint8_t bound[sizeof(LABEL_BIND) - 1 + 33];
  memcpy(bound, LABEL_BIND, sizeof(LABEL_BIND) - 1);
  memcpy(bound + sizeof(LABEL_BIND) - 1, this->x_pub_, 32);
  bound[sizeof bound - 1] = FLAGS;
  uint8_t sig[64];
  crypto_ed25519_sign(sig, this->ed_secret_, bound, sizeof bound);
  std::vector<uint8_t> m = {T_HELLO};
  m.insert(m.end(), this->ed_pub_, this->ed_pub_ + 32);
  m.push_back(FLAGS);
  m.insert(m.end(), sig, sig + 64);
  this->send_(m);
  this->last_hello_ms_ = this->now_();
}

void Node::send_announce_() {
  // The sequence: this start's number, then the time since it (ms), so a
  // restart's is newer without a clock (and above the times in ms since 1970
  // it was once made of).
  uint64_t seq = ((uint64_t) this->boot_ << 32) * 1000 + this->now_();
  std::string app = "{\"name\":" + quote(this->name_) + "}";
  static const uint8_t no_name[10] = {0};
  // What's signed: announce label ‖ destination ‖ x_pub ‖ name hash ‖ seq ‖ flags ‖ app data.
  std::vector<uint8_t> s(LABEL_ANNOUNCE, LABEL_ANNOUNCE + sizeof(LABEL_ANNOUNCE) - 1);
  s.insert(s.end(), this->address_, this->address_ + 16);
  s.insert(s.end(), this->x_pub_, this->x_pub_ + 32);
  s.insert(s.end(), no_name, no_name + 10);
  put_be64(s, seq);
  s.push_back(ANNOUNCE_FLAGS);
  s.insert(s.end(), app.begin(), app.end());
  uint8_t sig[64];
  crypto_ed25519_sign(sig, this->ed_secret_, s.data(), s.size());
  std::vector<uint8_t> m = {T_ANNOUNCE};
  m.insert(m.end(), this->ed_pub_, this->ed_pub_ + 32);
  m.insert(m.end(), this->x_pub_, this->x_pub_ + 32);
  m.insert(m.end(), no_name, no_name + 10);
  put_be64(m, seq);
  m.push_back(ANNOUNCE_FLAGS);
  m.push_back((uint8_t) (app.size() >> 8));
  m.push_back((uint8_t) app.size());
  m.insert(m.end(), app.begin(), app.end());
  m.insert(m.end(), sig, sig + 64);
  m.push_back(0);  // hops
  this->send_(m);
  this->last_announce_ms_ = this->now_();
}

void Node::loop() {
  if (!this->started_) return;
  uint8_t buf[1600];
  for (int i = 0; i < 8; i++) {
    struct sockaddr_in from {};
    socklen_t fl = sizeof from;
    int n = ::recvfrom(this->sock_, buf, sizeof buf, 0, (struct sockaddr *) &from, &fl);
    if (n <= 0) break;
    if (this->own_link_()) {
      this->on_outer_(from.sin_addr.s_addr, ntohs(from.sin_port), buf, n);
    } else {
      this->on_message_(buf, n);
    }
  }
  uint32_t now = this->now_();
  if (this->own_link_()) this->seek_(now);
  // Nothing into a tunnel before its handshake is done: a packet then makes
  // its WireGuard library start a handshake of its own, in lwIP's thread,
  // alongside the node's, and the two spoil each other's.
  if (!this->linked_()) {
    this->heard_hello_ms_ = 0;
    return;
  }
  uint32_t hello_every = this->heard_hello_ms_ ? HELLO_EVERY_MS : HELLO_UNTIL_HEARD_MS;
  if (now - this->last_hello_ms_ >= hello_every || this->last_hello_ms_ == 0) this->send_hello_();
  if (this->heard_hello_ms_ && (now - this->last_announce_ms_ >= ANNOUNCE_EVERY_MS || this->last_announce_ms_ == 0))
    this->send_announce_();
  this->resend_(now);
  // What lwIP sent on the vØrk interface.
  for (;;) {
    std::vector<uint8_t> p;
    {
      std::lock_guard<std::mutex> g(this->out_lock_);
      if (this->out_.empty()) break;
      p = std::move(this->out_.front());
      this->out_.pop_front();
    }
    this->send_ip_(p);
  }
}

void Node::on_message_(const uint8_t *m, size_t n) {
  if (n < 1) return;
  switch (m[0]) {
    case T_HELLO:
      if (!this->heard_hello_ms_) {
        this->logf_(Level::INFO, "the full node said hello: linked");
        if (this->owner_.empty() && this->devices_.empty())
          this->logf_(Level::INFO, "to make it one of your devices, paste this in your vØrk dashboard (Devices): %s",
                      this->link().c_str());
        this->send_hello_();
        this->send_announce_();
      }
      this->heard_hello_ms_ = this->now_();
      if (this->heard_hello_ms_ == 0) this->heard_hello_ms_ = 1;
      break;
    case T_PATH_OPEN: {
      if (n < 26) return;
      uint64_t label = be64(m + 1);
      std::vector<uint8_t> r = {memcmp(m + 9, this->address_, 16) == 0 ? T_PATH_ACK : T_PATH_ERR};
      put_be64(r, label);
      this->send_(r);
      if (r[0] == T_PATH_ACK) {
        this->paths_++;
        this->logf_(Level::INFO, "a path opened to this device (%u so far)", (unsigned) this->paths_);
      }
      break;
    }
    case T_PROBE:
      // The path's far end echoes its origin's probes.
      if (n >= 18 && m[17] == 0) {
        std::vector<uint8_t> r(m, m + 17);
        r.push_back(1);
        this->send_(r);
      }
      break;
    case T_DATA:
      if (n >= 9) this->on_data_(be64(m + 1), m + 9, n - 9);
      break;
    default:
      break;  // announces of others, observed addresses, reach: nothing a Lite node needs
  }
}

void Node::on_data_(uint64_t label, const uint8_t *inner, size_t n) {
  std::vector<uint8_t> out, plain;
  int session = -1;
  if (!this->wg_->receive(label, inner, n, this->now_(), out, plain, session)) return;
  // Answers go on the path the latest packet came on.
  if (session >= 0) this->wg_->sessions[session].label = label;
  if (!out.empty()) {
    this->logf_(Level::INFO, "an end-to-end session opened");
    std::vector<uint8_t> m = {T_DATA};
    put_be64(m, label);
    m.insert(m.end(), out.begin(), out.end());
    this->send_(m);
  }
  const uint8_t *body;
  size_t len;
  if (!plain.empty() && unframe(plain.data(), plain.size(), body, len)) this->on_app_(session, body, len);
}

void Node::send_app_(int session, const uint8_t *body, size_t n) {
  std::vector<uint8_t> framed = frame(body, n), sealed;
  if (!this->wg_->seal(session, framed.data(), framed.size(), sealed)) return;
  std::vector<uint8_t> m = {T_DATA};
  put_be64(m, this->wg_->sessions[session].label);
  m.insert(m.end(), sealed.begin(), sealed.end());
  this->send_(m);
}

void Node::on_app_(int session, const uint8_t *body, size_t n) {
  if (n == 0) return;
  switch (body[0]) {
    case APP_PING:
      if (n == 9) {
        uint8_t pong[9];
        memcpy(pong, body, 9);
        pong[0] = APP_PONG;
        this->send_app_(session, pong, 9);
        this->pings_++;
        this->logf_(Level::INFO, "ping answered (%u)", (unsigned) this->pings_);
      }
      break;
    case APP_SEG:
      if (n >= 5) this->on_segment_(session, be32(body + 1), body + 5, n - 5);
      break;
    case APP_IP:
      this->on_ip_(session, body + 1, n - 1);
      break;
    case APP_ACK:
      if (n >= 5) {
        Inner &in = this->inner_(session);
        uint32_t next = be32(body + 1);
        auto &u = in.unacked;
        u.erase(std::remove_if(u.begin(), u.end(), [next](const Inner::Seg &s) { return (int32_t) (s.seq - next) < 0; }),
                u.end());
      }
      break;
    default:
      break;  // direct-link offers, exit traffic: nothing a Lite node takes
  }
}

void Node::on_segment_(int session, uint32_t seq, const uint8_t *data, size_t n) {
  Inner &in = this->inner_(session);
  // The other end kept a session this end lost (a restart here): asked who it is, it starts over.
  if (seq > 0 && in.rcv_next == 0) return this->ask_who_(session);
  if (seq == in.rcv_next) {
    in.rcv_next++;
    size_t at = 0;
    if (in.skip) {
      size_t k = in.skip < n ? in.skip : n;
      in.skip -= k;
      at = k;
    }
    in.rbuf.insert(in.rbuf.end(), data + at, data + n);
    // Complete messages, each after its length (u32).
    while (in.rbuf.size() >= 4) {
      size_t len = be32(in.rbuf.data());
      size_t have = in.rbuf.size() - 4;
      if (len > MAX_MESSAGE) {
        in.skip = len > have ? len - have : 0;
        size_t drop = 4 + (len < have ? len : have);
        in.rbuf.erase(in.rbuf.begin(), in.rbuf.begin() + drop);
        continue;
      }
      if (have < len) break;
      std::vector<uint8_t> m(in.rbuf.begin() + 4, in.rbuf.begin() + 4 + len);
      in.rbuf.erase(in.rbuf.begin(), in.rbuf.begin() + 4 + len);
      this->on_stream_message_(session, m.data(), m.size());
    }
  }
  // Everything before rcv_next; what came out of order is sent again by the other end.
  std::vector<uint8_t> ack = {APP_ACK};
  put_be32(ack, in.rcv_next);
  ack.push_back(0);
  put_be32(ack, in.inc);
  this->send_app_(session, ack.data(), ack.size());
}

void Node::on_stream_message_(int session, const uint8_t *m, size_t n) {
  if (n >= 6 && m[0] == MSG_REQUEST) {
    uint32_t id = be32(m + 1);
    size_t plen = m[5];
    if (n < 6 + plen) return;
    std::string path((const char *) m + 6, plen);
    return this->on_request_(session, id, path, m + 6 + plen, n - 6 - plen);
  }
  if (n != 1 + 32 + 32 + 64 || m[0] != MSG_IDENTIFY) return;
  // Who opened the session: proven by a signature over the session's nonce,
  // SHA-256(session label ‖ opener's key ‖ this node's key).
  const uint8_t *ed = m + 1, *x = m + 33, *sig = m + 65;
  uint8_t seed[sizeof(LABEL_SESSION) - 1 + 32];
  memcpy(seed, LABEL_SESSION, sizeof(LABEL_SESSION) - 1);
  memcpy(seed + sizeof(LABEL_SESSION) - 1, this->wg_->sessions[session].peer, 32);
  uint8_t signed_[sizeof(LABEL_IDENTIFY) - 1 + 32];
  memcpy(signed_, LABEL_IDENTIFY, sizeof(LABEL_IDENTIFY) - 1);
  vl_sha256(signed_ + sizeof(LABEL_IDENTIFY) - 1, seed, sizeof seed, this->x_pub_, 32);
  if (crypto_ed25519_check(sig, ed, signed_, sizeof signed_) != 0) {
    this->logf_(Level::WARN, "an identification with a bad signature");
    return;
  }
  uint8_t h[32];
  vl_sha256(h, x, 32, ed, 32);
  Inner &in = this->inner_(session);
  in.identified = true;
  memcpy(in.who, h, 16);
  this->logf_(Level::INFO, "a session identified as %s", hex(h, 4).c_str());
}

void Node::ask_who_(int session) {
  Inner &in = this->inner_(session);
  uint32_t now = this->now_();
  if (in.asked_ms && now - in.asked_ms < 1000) return;
  in.asked_ms = now;
  std::vector<uint8_t> b = {APP_WHO};
  put_be32(b, in.rcv_next);
  put_be32(b, in.inc);
  this->send_app_(session, b.data(), b.size());
}

void Node::on_ip_(int session, const uint8_t *p, size_t n) {
  if (!this->netif_up_ || n < 40 || p[0] >> 4 != 6) return;
  Inner &in = this->inner_(session);
  if (!in.identified) {
    this->logf_(Level::DEBUG, "IP in a session that hasn't identified: asking who");
    return this->ask_who_(session);
  }
  // The walled garden: only the owner's devices, each from its own overlay address to ours.
  if (!this->trusted(in.who)) {
    this->logf_(Level::DEBUG, "IP from %s, not one of the devices: dropped", hex(in.who, 4).c_str());
    return;
  }
  uint8_t src[16], dst[16];
  ::vl::overlay(in.who, src);
  ::vl::overlay(this->address_, dst);
  if (memcmp(p + 8, src, 16) != 0 || memcmp(p + 24, dst, 16) != 0) {
    this->logf_(Level::DEBUG, "IP with other addresses: dropped");
    return;
  }
  Peer *peer = this->peer_(in.who);
  if (peer == nullptr) return;
  peer->session = session;
  std::vector<uint8_t> v4;
  if (!::vl::to_v4(p, n, peer->v4, this->v4_, v4)) {
    this->logf_(Level::VERBOSE, "IP (next header %u) not translated", p[6]);
    return;
  }
  struct pbuf *b = pbuf_alloc(PBUF_RAW, v4.size(), PBUF_POOL);
  if (b == nullptr) return;
  pbuf_take(b, v4.data(), v4.size());
  if (this->netif_.input(b, &this->netif_) != ERR_OK) pbuf_free(b);
  this->ip_in_++;
}

void Node::send_ip_(const std::vector<uint8_t> &v4) {
  if (v4.size() < 20) return;
  Peer *peer = nullptr;
  for (int i = 0; i < this->npeers_; i++)
    if (memcmp(this->peers_[i].v4, v4.data() + 16, 4) == 0) peer = &this->peers_[i];
  // Only answers: to a node that's spoken to this one, in the session it spoke in.
  if (peer == nullptr || peer->session < 0) {
    this->logf_(Level::DEBUG, "IP out to %u.%u.%u.%u: no session", v4[16], v4[17], v4[18], v4[19]);
    return;
  }
  Inner &in = this->inner_(peer->session);
  if (!in.identified || memcmp(in.who, peer->who, 16) != 0) {
    this->logf_(Level::DEBUG, "IP out: its session is gone");
    return;
  }
  uint8_t src[16], dst[16];
  ::vl::overlay(this->address_, src);
  ::vl::overlay(peer->who, dst);
  std::vector<uint8_t> b = {APP_IP}, v6;
  if (!::vl::to_v6(v4.data(), v4.size(), src, dst, v6)) {
    this->logf_(Level::DEBUG, "IP out (protocol %u) not translated", v4[9]);
    return;
  }
  b.insert(b.end(), v6.begin(), v6.end());
  this->send_app_(peer->session, b.data(), b.size());
  this->ip_out_++;
}

// ---- the stream's other side: messages this device sends ----------------------

void Node::send_message_(int session, const std::vector<uint8_t> &m) {
  Inner &in = this->inner_(session);
  std::vector<uint8_t> bytes;
  put_be32(bytes, (uint32_t) m.size());
  bytes.insert(bytes.end(), m.begin(), m.end());
  uint32_t now = this->now_();
  for (size_t at = 0; at < bytes.size(); at += SEG_DATA) {
    size_t k = std::min(SEG_DATA, bytes.size() - at);
    Inner::Seg s{in.snd_next++, std::vector<uint8_t>(bytes.begin() + at, bytes.begin() + at + k), now, 1};
    std::vector<uint8_t> b = {APP_SEG};
    put_be32(b, s.seq);
    b.insert(b.end(), s.data.begin(), s.data.end());
    this->send_app_(session, b.data(), b.size());
    in.unacked.push_back(std::move(s));
  }
}

/// Segments not acknowledged within a second are sent again (ten times at most).
void Node::resend_(uint32_t now) {
  for (int i = 0; i < ::vl::WgResponder::MAX_SESSIONS; i++) {
    if (!this->wg_->sessions[i].used) continue;
    Inner &in = this->inner_(i);
    for (auto it = in.unacked.begin(); it != in.unacked.end();) {
      if (now - it->sent_ms < 1000) {
        ++it;
        continue;
      }
      if (it->tries >= 10) {
        it = in.unacked.erase(it);
        continue;
      }
      std::vector<uint8_t> b = {APP_SEG};
      put_be32(b, it->seq);
      b.insert(b.end(), it->data.begin(), it->data.end());
      this->send_app_(i, b.data(), b.size());
      it->sent_ms = now;
      it->tries++;
      ++it;
    }
  }
}

void Node::respond_(int session, uint32_t id, uint8_t status, const std::string &body) {
  std::vector<uint8_t> r = {MSG_RESPONSE};
  put_be32(r, id);
  r.push_back(status);
  r.insert(r.end(), body.begin(), body.end());
  this->send_message_(session, r);
}

// ---- requests: linking, the owner's group, services -----------------------------

/// A string field of a flat JSON object ("key":"value", no escapes): what links carry.
static std::string json_str(const std::string &j, const char *key) {
  std::string k = std::string("\"") + key + "\"";
  size_t at = j.find(k);
  if (at == std::string::npos) return "";
  at = j.find(':', at + k.size());
  if (at == std::string::npos) return "";
  at = j.find('"', at);
  if (at == std::string::npos) return "";
  size_t end = j.find('"', at + 1);
  return end == std::string::npos ? "" : j.substr(at + 1, end - at - 1);
}

/// A number field after `from` in a JSON text (0 if none).
static uint64_t json_num(const std::string &j, size_t from, size_t to, const char *key) {
  std::string k = std::string("\"") + key + "\"";
  size_t at = j.find(k, from);
  if (at == std::string::npos || at > to) return 0;
  at = j.find(':', at);
  if (at == std::string::npos) return 0;
  return strtoull(j.c_str() + at + 1, nullptr, 10);
}

void Node::on_request_(int session, uint32_t id, const std::string &path, const uint8_t *body, size_t n) {
  std::string b((const char *) body, n);
  if (path == "/vork/link") return this->on_link_request_(session, id, b);
  if (path == "/vork/devices") return this->on_group_(session, id, b);
  if (path == "/vork/paths") return this->on_paths_(session, id);
  this->respond_(session, id, STATUS_REFUSED, "a Lite device");
}

/// What the owner's devices ask now and then: how this one reaches the others
/// (a Lite device reaches them through its full node: nothing to tell), and
/// the services to make known on their local networks for it.
void Node::on_paths_(int session, uint32_t id) {
  Inner &in = this->inner_(session);
  if (!in.identified || !this->trusted(in.who)) return this->respond_(session, id, STATUS_REFUSED, "for the owner's devices");
  std::vector<Service> services = this->services_;
  if (this->services_cb_) this->services_cb_(services);
  std::string j = "{\"paths\":[],\"names\":{},\"destinations\":[]";
  if (!services.empty()) {
    j += ",\"mdns\":[";
    for (size_t i = 0; i < services.size(); i++) {
      const Service &s = services[i];
      if (i) j += ",";
      j += "{\"type\":" + quote(s.type) + ",\"name\":" + quote(s.name.empty() ? this->name_ : s.name) +
           ",\"port\":" + std::to_string(s.port) + ",\"txt\":{";
      bool first = true;
      for (auto &kv : s.txt) {
        if (!first) j += ",";
        first = false;
        j += quote(kv.first) + ":" + quote(kv.second);
      }
      j += "}}";
    }
    j += "]";
  }
  j += "}";
  this->respond_(session, id, STATUS_OK, j);
}

void Node::on_link_request_(int session, uint32_t id, const std::string &body) {
  Inner &in = this->inner_(session);
  if (!in.identified) return this->respond_(session, id, STATUS_REFUSED, "identify first");
  std::string op = json_str(body, "op"), code = json_str(body, "code");
  if (op == "request") {
    if (this->owner_has_(in.who)) return this->respond_(session, id, STATUS_OK, "");
    if (!this->owner_.empty()) return this->respond_(session, id, STATUS_REFUSED, "one of another owner's devices");
    if (this->code_.empty() || code != this->code_) {
      this->logf_(Level::WARN, "%s asked to link without this device's code (it's in the link in this log)",
                  hex(in.who, 4).c_str());
      return this->respond_(session, id, STATUS_REFUSED, "the link's code is needed (in the device's log)");
    }
    std::array<uint8_t, 16> a;
    memcpy(a.data(), in.who, 16);
    this->owner_.push_back(a);
    std::sort(this->owner_.begin(), this->owner_.end());
    this->save_owner_();
    this->code_.clear();
    this->logf_(Level::INFO, "linked: one of %s's owner's devices now", hex(in.who, 4).c_str());
    return this->respond_(session, id, STATUS_OK, "");
  }
  if (op == "remove" && this->owner_has_(in.who)) {
    this->owner_.clear();
    this->save_owner_();
    this->new_code_();
    this->logf_(Level::INFO, "unlinked by its owner; to link it again: %s", this->link().c_str());
  }
  this->respond_(session, id, STATUS_OK, "");
}

void Node::on_group_(int session, uint32_t id, const std::string &body) {
  Inner &in = this->inner_(session);
  if (!in.identified || !this->owner_has_(in.who))
    return this->respond_(session, id, STATUS_REFUSED, "not one of this owner's devices");
  // {"devices":{"<address>":{"added":t,"removed":t},...}}: those linked, this one aside.
  std::vector<std::array<uint8_t, 16>> group;
  bool me_out = false;
  size_t at = body.find("\"devices\"");
  while (at != std::string::npos) {
    at = body.find('"', at + 1);
    if (at == std::string::npos || at + 33 >= body.size() || body[at + 33] != '"') {
      if (at != std::string::npos) at++;
      continue;
    }
    std::array<uint8_t, 16> a;
    if (!unhex(body.substr(at + 1, 32), a.data(), 16)) {
      at++;
      continue;
    }
    size_t end = body.find('}', at);
    if (end == std::string::npos) break;
    bool linked = json_num(body, at, end, "added") > json_num(body, at, end, "removed");
    if (memcmp(a.data(), this->address_, 16) == 0) {
      me_out = !linked;
    } else if (linked && group.size() < MAX_OWNER) {
      group.push_back(a);
    }
    at = end;
  }
  // Kept sorted: devices tell the same group in their own orders, and flash is written only when it changes.
  std::sort(group.begin(), group.end());
  if (me_out) {
    this->owner_.clear();
    this->new_code_();
    this->logf_(Level::INFO, "unlinked by its owner; to link it again: %s", this->link().c_str());
  } else if (!group.empty() && group != this->owner_) {
    this->owner_ = group;
    this->logf_(Level::INFO, "the owner's devices: %u", (unsigned) group.size());
  } else {
    return this->respond_(session, id, STATUS_OK, "");
  }
  this->save_owner_();
  this->respond_(session, id, STATUS_OK, "");
}

// ---- the device's own link to a full node ---------------------------------------

/// TAI64N for a handshake: this start's number, then the time since it; it
/// only has to grow (WireGuard keeps the latest per key against replays).
void Node::stamp_(uint8_t t[12]) {
  uint32_t ms = this->now_();
  uint64_t s = (1ULL << 62) + 37 + ((uint64_t) this->boot_ << 32) + ms / 1000;
  uint32_t ns = (ms % 1000) * 1000000;
  for (int i = 0; i < 8; i++) t[i] = (uint8_t) (s >> (56 - 8 * i));
  for (int i = 0; i < 4; i++) t[8 + i] = (uint8_t) (ns >> (24 - 8 * i));
}

void Node::handshake_(uint32_t now) {
  Candidate &c = (*this->cands_)[this->up_];
  uint8_t tai[12];
  this->stamp_(tai);
  std::vector<uint8_t> init;
  this->outer_->initiation(tai, init);
  this->send_to_(c.ip, c.port, init.data(), init.size());
  this->init_ms_ = now;
  this->tries_++;
}

void Node::link_down_(const char *why) {
  if (this->up_ >= 0) {
    Candidate &c = (*this->cands_)[this->up_];
    this->logf_(Level::WARN, "the link to %s:%u is down: %s", ip_str(c.ip).c_str(), c.port, why);
    c.fails++;
  }
  this->up_ = -1;
  this->link_up_ = false;
  this->heard_hello_ms_ = 0;
  this->tries_ = 0;
}

void Node::seek_(uint32_t now) {
  auto &cands = *this->cands_;
  if (this->up_ >= 0) {
    if (!this->link_up_) {
      // Handshaking: again after a while, another node after three.
      if (now - this->init_ms_ >= RETRY_MS) {
        if (this->tries_ >= 3) {
          this->link_down_("no answer to the handshake");
        } else {
          this->handshake_(now);
        }
      }
      return;
    }
    if (now - this->last_rx_ms_ >= DEAD_MS) return this->link_down_("nothing heard");
    // New keys in time; the old ones still take what's in flight.
    if (now - this->outer_->keys_ms() >= REKEY_MS && now - this->init_ms_ >= RETRY_MS) {
      this->tries_ = 0;
      this->handshake_(now);
    }
    if (now - this->last_tx_ms_ >= KEEPALIVE_MS) {
      std::vector<uint8_t> ka;
      if (this->outer_->seal(nullptr, 0, ka)) {
        this->send_to_(cands[this->up_].ip, cands[this->up_].port, ka.data(), ka.size());
        this->last_tx_ms_ = now;
      }
    }
    return;
  }
  // Full nodes on the local network: their address, port and key (TXT k).
  if (this->mdns_search_ != nullptr) {
    mdns_result_t *results = nullptr;
    uint8_t count = 0;
    if (mdns_query_async_get_results((mdns_search_once_t *) this->mdns_search_, 0, &results, &count)) {
      for (mdns_result_t *r = results; r != nullptr; r = r->next) {
        uint8_t key[32];
        bool has_key = false;
        for (size_t i = 0; i < r->txt_count; i++)
          if (strcmp(r->txt[i].key, "k") == 0 && r->txt[i].value != nullptr) has_key = unhex(r->txt[i].value, key, 32);
        if (!has_key || memcmp(key, this->x_pub_, 32) == 0) continue;
        for (mdns_ip_addr_t *a = r->addr; a != nullptr; a = a->next) {
          if (a->addr.type != ESP_IPADDR_TYPE_V4) continue;
          bool known = false;
          for (auto &c : cands) known |= c.ip == a->addr.u_addr.ip4.addr && c.port == r->port;
          if (known) continue;
          Candidate c;
          c.ip = a->addr.u_addr.ip4.addr;
          c.port = r->port;
          memcpy(c.key, key, 32);
          c.has_key = c.lan = true;
          cands.insert(cands.begin(), c);
          this->logf_(Level::INFO, "found a full node on the local network at %s:%u", ip_str(c.ip).c_str(), c.port);
          break;
        }
      }
      if (results != nullptr) mdns_query_results_free(results);
      mdns_query_async_delete((mdns_search_once_t *) this->mdns_search_);
      this->mdns_search_ = nullptr;
    }
  }
  if (this->seek_ms_ == 0 || now - this->seek_ms_ >= 30000) {
    this->seek_ms_ = now;
    if (this->mdns_search_ == nullptr)
      this->mdns_search_ = mdns_query_async_new(nullptr, "_vork", "_udp", MDNS_TYPE_PTR, 3000, 8, nullptr);
    for (auto &u : this->upstreams_) {
      size_t colon = u.rfind(':');
      if (colon == std::string::npos) continue;
      std::string host = u.substr(0, colon);
      uint16_t port = (uint16_t) atoi(u.c_str() + colon + 1);
      struct addrinfo hints {}, *res = nullptr;
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_DGRAM;
      if (lwip_getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) continue;
      uint32_t ip = ((struct sockaddr_in *) res->ai_addr)->sin_addr.s_addr;
      lwip_freeaddrinfo(res);
      bool known = false;
      for (auto &c : cands) known |= c.ip == ip && c.port == port;
      if (known) continue;
      Candidate c;
      c.ip = ip;
      c.port = port;
      cands.push_back(c);
    }
    // After everyone failed: everyone again.
    bool any = false;
    for (auto &c : cands) any |= c.fails < 1;
    if (!any)
      for (auto &c : cands) c.fails = 0;
  }
  // The first that may do, with its key: a handshake (a node on the local
  // network first: the search for them is waited for).
  if (this->mdns_search_ != nullptr) return;
  for (size_t i = 0; i < cands.size(); i++) {
    Candidate &c = cands[i];
    if (!c.has_key || c.fails >= 1) continue;
    this->up_ = (int) i;
    this->tries_ = 0;
    this->outer_->set_keys(this->x_secret_, this->x_pub_, c.key);
    this->logf_(Level::INFO, "linking to %s:%u", ip_str(c.ip).c_str(), c.port);
    this->handshake_(now);
    return;
  }
  // Those without a key: asked (padded to the answer's size, as nodes ask).
  if (now - this->ask_ms_ >= RETRY_MS) {
    this->ask_ms_ = now;
    for (auto &c : cands) {
      if (c.has_key || c.fails >= 1) continue;
      esp_fill_random(&c.nonce, sizeof c.nonce);
      std::vector<uint8_t> q(KEY_ASK, KEY_ASK + 5);
      put_be64(q, c.nonce);
      q.resize(q.size() + 64, 0);
      this->send_to_(c.ip, c.port, q.data(), q.size());
    }
  }
}

void Node::on_outer_(uint32_t ip, uint16_t port, const uint8_t *p, size_t n) {
  auto &cands = *this->cands_;
  // A node's key, asked of it.
  if (n == 5 + 8 + 64 && memcmp(p, KEY_TELL, 5) == 0) {
    for (auto &c : cands) {
      if (c.ip != ip || c.port != port || c.has_key || be64(p + 5) != c.nonce) continue;
      memcpy(c.key, p + 13, 32);
      c.has_key = true;
    }
    return;
  }
  if (this->up_ < 0 || cands[this->up_].ip != ip || cands[this->up_].port != port || n < 4) return;
  uint32_t now = this->now_();
  if (p[0] == 2) {
    if (!this->outer_->response(p, n, now)) return;
    bool was = this->link_up_;
    this->link_up_ = true;
    this->last_rx_ms_ = now;
    this->tries_ = 0;
    cands[this->up_].fails = 0;
    // The responder's keys count once it hears from this end: a keepalive at once.
    std::vector<uint8_t> ka;
    if (this->outer_->seal(nullptr, 0, ka)) {
      this->send_to_(ip, port, ka.data(), ka.size());
      this->last_tx_ms_ = now;
    }
    if (!was) this->logf_(Level::INFO, "linked to the full node at %s:%u", ip_str(ip).c_str(), port);
    return;
  }
  if (p[0] == 4) {
    std::vector<uint8_t> plain;
    if (!this->outer_->open(p, n, plain)) return;
    this->last_rx_ms_ = now;
    const uint8_t *body;
    size_t len;
    if (!plain.empty() && unframe(plain.data(), plain.size(), body, len)) this->on_message_(body, len);
  }
}

}  // namespace vorklite
