// A vØrk Lite device that answers HTTP: once linked to its owner, it's
// http://hello.vork/ (or its 198.18 address) on every one of the owner's
// devices, wherever they are.
#include <string.h>

#include <esp_event.h>
#include <esp_log.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lwip/sockets.h>
#include <nvs_flash.h>

#include <vork_lite/node.h>

static const char *TAG = "hello";
static vorklite::Node node;

static void wifi_start() {
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  esp_netif_create_default_wifi_sta();
  wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&init));
  wifi_config_t c{};
  strncpy((char *) c.sta.ssid, CONFIG_EXAMPLE_WIFI_SSID, sizeof c.sta.ssid);
  strncpy((char *) c.sta.password, CONFIG_EXAMPLE_WIFI_PASSWORD, sizeof c.sta.password);
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &c));
  // Connect again whenever the station drops.
  esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, [](void *, esp_event_base_t, int32_t id, void *) {
    if (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED) esp_wifi_connect();
  }, nullptr);
  ESP_ERROR_CHECK(esp_wifi_start());
}

/// A plain socket server: it answers on Wi-Fi and on vØrk alike, and the
/// node lets only the owner's devices through to it over vØrk.
static void http_task(void *) {
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(80);
  bind(s, (sockaddr *) &a, sizeof a);
  listen(s, 2);
  for (;;) {
    int c = accept(s, nullptr, nullptr);
    if (c < 0) continue;
    char req[512];
    recv(c, req, sizeof req, 0);
    std::string body = "Hello from " + node.name() + " (" + node.address() + ") over vØrk\n";
    std::string r = "HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " +
                    std::to_string(body.size()) + "\r\n\r\n" + body;
    send(c, r.data(), r.size(), 0);
    close(c);
  }
}

extern "C" void app_main() {
  if (nvs_flash_init() != ESP_OK) {
    nvs_flash_erase();
    nvs_flash_init();
  }
  wifi_start();

  node.set_name(CONFIG_EXAMPLE_NAME);
  // Made known on the owner's devices' local networks (mDNS at its vØrk address).
  vorklite::Service web;
  web.type = "_http._tcp";
  web.port = 80;
  node.add_service(web);
  // Starts once Wi-Fi has an address; its log then shows the link to paste
  // into your vØrk dashboard (Devices).
  node.start_task();

  xTaskCreate(http_task, "http", 4096, nullptr, 5, nullptr);
  ESP_LOGI(TAG, "started");
}
