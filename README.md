# vØrk Lite

An ESP32 as a Lite node of [vØrk](https://github.com/vooteleaer/vork), the
serverless, identity-addressed network on WireGuard. The device gets an
address on vØrk, links itself to a full node, and anything listening on it
(a web page, an MQTT client's socket, ESPHome's native API) answers your own
devices over vØrk wherever they are: at home, on mobile data, behind any NAT.
Only your devices get through; nothing else on the network reaches it.

This repository is the library: an ESP-IDF component for your own firmware.
For ESPHome, use [esphome-vork-lite](https://github.com/vooteleaer/esphome-vork-lite),
which is built on it.

**Status:** pre-release (v0.1.0). Tested on an ESP32-S3 with ESP-IDF 5.5.

## How it works

A Lite node is a small vØrk node that relays nothing:

- **Its own identity.** On its first start the device makes a vØrk key
  (X25519 + Ed25519) and keeps it in flash. Its address is the hash of that
  key (32 hex digits), and its IPv4 address on vØrk (`198.18.x.y`) is
  derived from it, the same on every machine.
- **Its own link.** It finds a full node on the local network by mDNS
  (`_vork._udp`), or else uses vØrk's public bootstrap node. It opens vØrk's
  outer WireGuard link to that node with its own key. No WireGuard
  configuration and no clock are needed.
- **End-to-end sessions.** Full nodes open WireGuard sessions to it across
  the network. It answers pings, and IP from the owner's devices goes into
  lwIP on a network interface of its own (`vk`).
- **A walled garden.** Only its owner's devices get IP through: those that
  linked it with the one-time code in its log, and the devices they tell it
  about. Each session proves who opened it with a signature.

## Requirements

- An ESP32, ESP32-S2, -S3, -C3 or -C6 with ESP-IDF 5.1 or newer.
- 16 kB of stack for the task that runs it (signing and key agreement need it).
- vØrk 0.5.0 or newer on at least one of your own devices (a PC, a phone, a
  server; [releases](https://github.com/vooteleaer/vork/releases)): that's where
  you link the device. See
  [vØrk's README](https://github.com/vooteleaer/vork#install).

## Quick start

1. Add the component to your project's `main/idf_component.yml`:

   ```yaml
   dependencies:
     vooteleaer/vork-lite:
       git: https://github.com/vooteleaer/vork-lite.git
       version: v0.1.0
   ```

2. Start a node once Wi-Fi is up:

   ```cpp
   #include <vork_lite/node.h>

   static vorklite::Node node;

   extern "C" void app_main() {
     // ... nvs_flash_init(), Wi-Fi as usual ...
     node.set_name("sensor");
     node.start_task();  // waits for the station's address, then runs
   }
   ```

3. Flash it and watch its log. Once it's linked to a full node it prints its
   link:

   ```
   I (5123) vork_lite: this device is 3c1e9a7fd2486b05e19c7a3f60d84b21 (198.18.60.212); its link: vork-link:3c1e9a7f…?c=4f1c…&n=sensor
   I (6311) vork_lite: the full node said hello: linked
   ```

4. Paste the link into your vØrk dashboard's **Devices** page, or run `vork link '<link>'` on one of your devices. The device logs
   `linked`, and from then on every one of your devices reaches it as
   `sensor.vork` or `198.18.60.212`.

[examples/http-hello](examples/http-hello) is a complete project: Wi-Fi and a
small HTTP server that answers at `http://hello.vork/` once linked.

```sh
cd examples/http-hello
idf.py set-target esp32s3
idf.py menuconfig      # vØrk Lite example: the Wi-Fi network and password
idf.py build flash monitor
```

## Using it in your firmware

### Running the node

There are two ways to run it:

- `node.start_task(priority = 5, core = -1)` starts a task of its own (16 kB
  of stack). The task waits until the Wi-Fi station has an IPv4 address,
  starts the node and then runs it every 10 ms.
- Or run it yourself. Call `node.start()` once the network is up, then
  `node.loop()` every 10–20 ms, always from the same task. That task needs
  about 16 kB of stack.

Start the node only once Wi-Fi is up: the chip's random numbers are true only
with the radio on, and the identity and the link's code are made of them.

### Your services

Nothing is special about serving on vØrk. Bind a socket to `INADDR_ANY` as
usual, and it answers on Wi-Fi and on vØrk alike. On vØrk, the node lets only
the owner's devices through.

To have the owner's devices find a service by mDNS (as if the device were on
their LAN), name it before `start()`:

```cpp
vorklite::Service web;
web.type = "_http._tcp";
web.port = 80;
web.txt["path"] = "/";
node.add_service(web);
```

For values that change while it runs, use `node.set_services(...)`: the
callback is asked each time the owner's devices ask. Each of the owner's full
nodes that has mDNS announces these services on its own local network, at
the device's vØrk address.

### API

All of these are set before `start()`:

| Call | What it does |
|---|---|
| `set_name(name)` | The name it's announced by: `<name>.vork` on the owner's devices. Default `lite`. |
| `set_key(hex)` | Use an identity from a vØrk key file (`vork keygen`, 128 hex digits) instead of making one. |
| `add_upstream("host:port")` | A full node to link to when none is found on the local network. The default is vØrk's bootstrap list. |
| `add_device(hex)` | Let in a node by its address, besides the owner's devices. |
| `set_store(Store *)` | Where the identity, owner and start counter are kept. The default is NVS, namespace `vork_lite`. |
| `set_logger(fn)` | Where the log goes. The default is ESP-IDF's log with the tag `vork_lite`. |
| `set_tunnel(fn)` | Use a WireGuard tunnel someone else keeps (device `10.89.0.2`, node `10.89.0.1`) instead of its own link. |
| `add_service(s)`, `set_services(fn)` | Services named to the owner's devices (see above). |

These tell you what it is once it runs:

| Call | Returns |
|---|---|
| `started()` | Whether `start()` has succeeded. |
| `online()` | Whether a full node has said hello. |
| `address()` | Its vØrk address as 32 hex digits. |
| `ipv4()` | Its vØrk IPv4 address. |
| `link()` | What the owner pastes to link it. It carries a one-time code while there's no owner. |
| `devices()` | How many of the owner's devices it knows. |
| `trusted(addr)` | Whether a 16-byte address is let in. |

### Linking and unlinking

The first owner to bring the link's code owns the device. The owner's other
devices then tell it about each other, and it keeps that list in flash. When
the owner removes it from their devices, it forgets them and shows a new code
in its log. To start over with a new identity, erase its NVS (or call
`set_store` with a fresh store).

## Limits

- IPv4 only inside the device. vØrk carries IPv6 between nodes, and the node
  translates TCP, UDP and ping (the same as full nodes do for `198.18`
  addresses). Fragments and other protocols are dropped.
- It only answers. The device can't open connections to the owner's devices
  until they have spoken to it first.
- No exit node, no relaying, no DNS for `.vork` names on the device itself.
- At most 16 sessions and 8 peers at a time.

## Troubleshooting

| What you see | What it means |
|---|---|
| `found a full node … linking to …` and then `no answer to the handshake` | That node didn't answer. Usually it's on another VLAN or behind a firewall. The device tries the next node. |
| No `the full node said hello` line | The link never came up. Check that UDP to the bootstrap node (or to a full node on the LAN) isn't blocked. |
| `asked to link without this device's code` | The link was pasted without its `?c=` part, or it's an old link. Copy the latest one from the log. |
| `IP from …, not one of the devices: dropped` | A node that isn't one of the owner's devices tried to reach it. |
| A stack overflow on start | The task running the node needs 16 kB of stack. |

## Layout

- `include/vork_lite/node.h`: the API.
- `src/node.cpp`: the node, which covers the network layer, linking, sessions
  and lwIP. `wg.cpp` holds WireGuard's responder (sessions to the device) and
  its initiator (its own link). `nat.cpp` translates IPv4 to and from IPv6.
  `crypto.c` holds the AEAD, HMAC/KDF and SHA-256. `vl_blake2s.c` is BLAKE2s,
  with its names changed so it can sit beside other copies. Monocypher
  (BSD-2/CC0, `src/LICENCE-monocypher.md`) provides X25519, Ed25519,
  ChaCha20 and Poly1305.
- `test/interop`: checks against what full nodes use. boringtun opens
  sessions to the responder and answers the initiator, and ed25519-dalek
  checks the signatures. Run it with
  `cargo run --bin vork-lite-interop` and `cargo run --bin outer` on Linux.
- `examples/http-hello`: a complete ESP-IDF project.

## Licence

MIT (see [LICENSE](LICENSE)). Monocypher's licence is in
`src/LICENCE-monocypher.md`.
