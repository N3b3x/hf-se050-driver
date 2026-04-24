/**
 * @file se050_minimal_example.cpp
 * @brief ESP32 bring-up: electrical reset, T=1 **GET ATR**, optional **SELECT** default IoT applet.
 *
 * @note Requires a wired SE050. Logged `se050::Error` values diagnose transport vs protocol layers.
 */
#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_apdu.hpp"
#include "se050_device.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>

static const char* TAG = "se050_minimal";

static void log_hex(const char* label, const std::uint8_t* data, std::size_t len)
{
    if (len == 0U || data == nullptr) {
        ESP_LOGI(TAG, "%s: <empty>", label);
        return;
    }
    constexpr std::size_t kChunk = 48U;
    std::size_t off = 0;
    while (off < len) {
        const std::size_t n = (len - off > kChunk) ? kChunk : (len - off);
        char line[3U * kChunk + 1U]{};
        std::size_t p = 0;
        for (std::size_t i = 0; i < n && p + 3U < sizeof(line); ++i) {
            (void)snprintf(&line[p], sizeof(line) - p, "%02X ", static_cast<unsigned>(data[off + i]));
            p += 3U;
        }
        ESP_LOGI(TAG, "%s [%u]: %s", label, static_cast<unsigned>(off), line);
        off += n;
    }
}

extern "C" void app_main(void)
{
    hf_se050_examples::HfSe050EspIdfI2c transport{};
    se050::Device chip(transport);

    if (!chip.EnsureInitialized()) {
        ESP_LOGE(TAG, "Transport init failed");
        return;
    }

    (void)chip.HardwareReset();
    chip.T1().SetInterFrameDelayMs(3U);

    const se050::Error wr = chip.T1().ChipWarmReset(150U);
    ESP_LOGI(TAG, "T1::ChipWarmReset -> se050::Error=%u", static_cast<unsigned>(wr));

    std::uint8_t atr[96]{};
    std::size_t atr_len = 0;
    const se050::Error ar = chip.T1().GetAnswerToReset(atr, sizeof(atr), &atr_len, 250U);
    ESP_LOGI(TAG, "T1::GetAnswerToReset -> se050::Error=%u atr_len=%u", static_cast<unsigned>(ar),
             static_cast<unsigned>(atr_len));
    if (ar == se050::Error::Ok) {
        log_hex("ATR / profile INF", atr, atr_len);
    }

    std::uint8_t rapdu[128]{};
    std::size_t rapdu_len = 0;
    const se050::Error se = chip.SelectDefaultIoTApplet(rapdu, sizeof(rapdu), &rapdu_len, 300U);
    ESP_LOGI(TAG, "SelectDefaultIoTApplet -> se050::Error=%u rapdu_len=%u", static_cast<unsigned>(se),
             static_cast<unsigned>(rapdu_len));
    if (se == se050::Error::Ok && rapdu_len >= 2U) {
        log_hex("SELECT R-APDU", rapdu, rapdu_len);
        const std::uint8_t* payload = nullptr;
        std::size_t payload_len = 0;
        se050::apdu::StatusWords sw{};
        (void)se050::apdu::ParseResponse(rapdu, rapdu_len, &payload, &payload_len, &sw);
        ESP_LOGI(TAG, "SELECT SW=%02X%02X ok=%d", static_cast<unsigned>(sw.sw1), static_cast<unsigned>(sw.sw2),
                 se050::apdu::IsSuccess(sw) ? 1 : 0);
    }

    ESP_LOGI(TAG, "HF-SE050 driver: T=1 + APDU path exercised (SCP03 not enabled)");
}
