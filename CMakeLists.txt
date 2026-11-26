# vØrk Lite as an ESP-IDF component (also a managed component: idf_component.yml).
idf_component_register(
  SRCS
    "src/node.cpp"
    "src/wg.cpp"
    "src/nat.cpp"
    "src/crypto.c"
    "src/vl_blake2s.c"
    "src/monocypher.c"
    "src/monocypher-ed25519.c"
  INCLUDE_DIRS "include"
  PRIV_INCLUDE_DIRS "src"
  REQUIRES lwip
  PRIV_REQUIRES esp_timer esp_netif esp_hw_support nvs_flash mbedtls freertos
)
