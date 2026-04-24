/**
 * @file stage_bootstrap.hpp
 * @brief **STAGE 2 — First-field-boot bootstrap.**
 *
 * ## What this stage does
 *  1. Brings up ESP-IDF's NVS, netif, event-loop subsystems.
 *  2. Associates to a WiFi AP using the credentials in `lifecycle_config.hpp`.
 *  3. Signals "link up" once IP and default gateway are acquired.
 *
 * ## Why this is its own stage
 *
 * The provisioning stage only touches the SE050. The telemetry stage only
 * cares about "is there a cloud connection?". Bootstrap is the glue that
 * turns "box with provisioned chip" into "box with a network path to
 * AWS IoT" — separating it makes failure-mode triage trivial:
 *
 *   - Stage 1 fails -> SE050/factory problem.
 *   - Stage 2 fails -> RF/WiFi/DNS/DHCP problem.
 *   - Stage 3 fails -> AWS credentials/endpoint problem.
 *   - Stage 4 fails -> application-level bug.
 *
 * ## What this stage deliberately skips
 *  - Ethernet: the pattern is identical (`esp_eth_*` instead of
 *    `esp_wifi_*`). Swap the transport if your medical hub uses wired.
 *  - Static IP: DHCP is assumed (AWS IoT endpoints are always DNS names).
 *  - WPA3: uses WPA2-PSK default, which is the highest common denominator
 *    for HIPAA networks today.
 *
 * @note This file uses real ESP-IDF WiFi APIs. If you compile the example
 *       with `HF_SE050_LIFECYCLE_ENABLE_NETWORK=0` the whole stage is
 *       replaced by a stub that logs "network disabled".
 */

#pragma once

#include "esp_log.h"
#include "lifecycle_config.hpp"

#if HF_SE050_LIFECYCLE_ENABLE_NETWORK
#  include "esp_event.h"
#  include "esp_netif.h"
#  include "esp_wifi.h"
#  include "nvs_flash.h"
#  include "freertos/FreeRTOS.h"
#  include "freertos/event_groups.h"
#  include "freertos/task.h"
#  include <cstring>
#endif

namespace hf_se050_lifecycle::bootstrap {

inline constexpr const char* kTag = "se050_lc.boot";

#if HF_SE050_LIFECYCLE_ENABLE_NETWORK

// -----------------------------------------------------------------------------
// Event-group bits used to signal the associate/connect result back to the
// blocking bootstrap function.
// -----------------------------------------------------------------------------
inline constexpr int kWifiConnectedBit = BIT0;  ///< Got IP.
inline constexpr int kWifiFailedBit    = BIT1;  ///< Gave up after retries.

/** @brief One WiFi event-group owned by the bootstrap logic. */
inline EventGroupHandle_t& WifiEvents()
{
    static EventGroupHandle_t s_evt = nullptr;
    return s_evt;
}

/**
 * @brief WiFi / IP event callback — translates ESP-IDF events into bits on
 *        the event group that `ConnectWifi()` is blocked on.
 */
inline void OnEvent(void* /*arg*/, esp_event_base_t base, std::int32_t id, void* data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        ESP_LOGI(kTag, "WiFi driver started — kicking off association.");
        (void)esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(kTag, "WiFi disconnected — retrying…");
        (void)esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const auto* evt = static_cast<const ip_event_got_ip_t*>(data);
        ESP_LOGI(kTag, "Got IP: " IPSTR, IP2STR(&evt->ip_info.ip));
        xEventGroupSetBits(WifiEvents(), kWifiConnectedBit);
    }
}

/** @brief Bring up ESP-IDF subsystems that the WiFi stack needs. */
inline bool InitCoreServices()
{
    // NVS is required by the WiFi driver (calibration, station save).
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        (void)nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "nvs_flash_init failed: %d", static_cast<int>(err));
        return false;
    }

    // netif + default event loop are one-shot — ignore "already initialized".
    (void)esp_netif_init();
    (void)esp_event_loop_create_default();
    (void)esp_netif_create_default_wifi_sta();
    return true;
}

/**
 * @brief Blocking WiFi associate.
 *
 * Returns `true` once an IP is acquired; `false` on timeout.
 */
inline bool ConnectWifi()
{
    WifiEvents() = xEventGroupCreate();
    if (WifiEvents() == nullptr) {
        ESP_LOGE(kTag, "Cannot allocate WiFi event group.");
        return false;
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &OnEvent, nullptr, nullptr));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &OnEvent, nullptr, nullptr));

    wifi_config_t wc{};
    std::strncpy(reinterpret_cast<char*>(wc.sta.ssid), wifi::kSsid, sizeof(wc.sta.ssid) - 1);
    std::strncpy(reinterpret_cast<char*>(wc.sta.password), wifi::kPassword, sizeof(wc.sta.password) - 1);
    wc.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(kTag, "Associating to SSID \"%s\"…", wifi::kSsid);
    const EventBits_t bits = xEventGroupWaitBits(WifiEvents(),
                                                 kWifiConnectedBit | kWifiFailedBit,
                                                 pdFALSE, pdFALSE,
                                                 pdMS_TO_TICKS(wifi::kAssociateTimeoutMs));
    if ((bits & kWifiConnectedBit) != 0) {
        ESP_LOGI(kTag, "WiFi link UP.");
        return true;
    }
    ESP_LOGW(kTag, "WiFi association timed out / failed.");
    return false;
}

#endif  // HF_SE050_LIFECYCLE_ENABLE_NETWORK

/**
 * @brief Stage 2 entry point. Returns `true` if the device is ready to
 *        proceed to AWS-IoT TLS handshake.
 */
inline bool RunStage()
{
    ESP_LOGI(kTag, "==================== STAGE 2 — BOOTSTRAP =======================");

#if HF_SE050_LIFECYCLE_ENABLE_NETWORK
    if (!InitCoreServices()) {
        return false;
    }
    const bool ok = ConnectWifi();
    ESP_LOGI(kTag, "==================== STAGE 2 — %s =============", ok ? "COMPLETE" : "FAILED  ");
    return ok;
#else
    ESP_LOGW(kTag, "Network disabled at compile time — skipping WiFi bring-up.");
    ESP_LOGI(kTag, "==================== STAGE 2 — SKIPPED =========================");
    return true;
#endif
}

}  // namespace hf_se050_lifecycle::bootstrap
