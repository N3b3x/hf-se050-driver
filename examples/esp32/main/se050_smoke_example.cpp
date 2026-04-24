/**
 * @file se050_smoke_example.cpp
 * @brief ESP32 smoke test: init/reset/ATR/select/version/random/memory.
 */
#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_atr.hpp"
#include "se050_device.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>

static const char* TAG = "se050_smoke";

static void log_hex(const char* label, const std::uint8_t* data, std::size_t len)
{
    if (len == 0U || data == nullptr) {
        ESP_LOGI(TAG, "%s: <empty>", label);
        return;
    }
    constexpr std::size_t kChunk = 32U;
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
    chip.T1().SetReadRetries(8U);
    chip.T1().SetMaxWtxRequests(10U);

    const se050::Error wr = chip.T1().ChipWarmReset(200U);
    ESP_LOGI(TAG, "WarmReset -> %u", static_cast<unsigned>(wr));

    std::uint8_t atr_inf[96]{};
    std::size_t atr_inf_len = 0;
    const se050::Error atr_e = chip.T1().GetAnswerToReset(atr_inf, sizeof(atr_inf), &atr_inf_len, 300U);
    ESP_LOGI(TAG, "GetATR -> %u len=%u", static_cast<unsigned>(atr_e), static_cast<unsigned>(atr_inf_len));
    if (atr_e == se050::Error::Ok) {
        log_hex("ATR-INF", atr_inf, atr_inf_len);
        se050::atr::Profile prof{};
        const se050::Error pe = se050::atr::Parse(atr_inf, atr_inf_len, &prof);
        ESP_LOGI(TAG, "ATR parse -> %u pver=%u ifsc=%u segt_us=%u max_i2c_khz=%u", static_cast<unsigned>(pe),
                 static_cast<unsigned>(prof.protocol_version), static_cast<unsigned>(prof.ifsc),
                 static_cast<unsigned>(prof.segt_us), static_cast<unsigned>(prof.max_i2c_khz));
    }

    std::uint8_t sel_rapdu[128]{};
    std::size_t sel_rapdu_len = 0;
    const se050::Error sel = chip.SelectDefaultIoTApplet(sel_rapdu, sizeof(sel_rapdu), &sel_rapdu_len, 300U);
    ESP_LOGI(TAG, "SelectDefaultIoTApplet -> %u len=%u", static_cast<unsigned>(sel),
             static_cast<unsigned>(sel_rapdu_len));

    se050::cmd::VersionInfo version{};
    const se050::Error ve = chip.GetVersion(&version, 300U);
    ESP_LOGI(TAG, "GetVersion -> %u v=%u.%u.%u applet_cfg=0x%04X secure_box=0x%04X", static_cast<unsigned>(ve),
             static_cast<unsigned>(version.applet_major), static_cast<unsigned>(version.applet_minor),
             static_cast<unsigned>(version.applet_patch), static_cast<unsigned>(version.applet_config),
             static_cast<unsigned>(version.secure_box));

    std::uint8_t random_buf[32]{};
    std::size_t random_len = 0;
    const se050::Error re = chip.GetRandom(16U, random_buf, sizeof(random_buf), &random_len, 300U);
    ESP_LOGI(TAG, "GetRandom -> %u len=%u", static_cast<unsigned>(re), static_cast<unsigned>(random_len));
    if (re == se050::Error::Ok) {
        log_hex("Random", random_buf, random_len);
    }

    std::uint16_t free_persistent = 0;
    const se050::Error me = chip.GetFreeMemory(se050::cmd::MemoryType::Persistent, &free_persistent, 300U);
    ESP_LOGI(TAG, "GetFreeMemory(Persistent) -> %u bytes=%u", static_cast<unsigned>(me),
             static_cast<unsigned>(free_persistent));
}
