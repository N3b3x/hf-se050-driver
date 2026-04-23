/**
 * @file se050_minimal_example.cpp
 * @brief Phase 1 — CRTP I2C transport + `se050::Device`; optional bus probe (no valid T=1 yet).
 */
#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_device.hpp"

static const char* TAG = "se050_minimal";

extern "C" void app_main(void)
{
    hf_se050_examples::HfSe050EspIdfI2c transport{};
    se050::Device chip(transport);

    if (!chip.EnsureInitialized()) {
        ESP_LOGE(TAG, "Transport init failed");
        return;
    }

    std::uint8_t rx[4]{};
    std::size_t rx_len = 0;
    // Intentionally minimal: zero-length write + short read may NACK without SE050 — ignored for bring-up.
    const se050::Error e = chip.TransceiveRaw(nullptr, 0U, rx, sizeof(rx), &rx_len, 50U);
    ESP_LOGI(TAG, "TransceiveRaw(probe) -> se050::Error=%u rx_len=%u", static_cast<unsigned>(e),
             static_cast<unsigned>(rx_len));

    ESP_LOGI(TAG, "HF-SE050 Phase 1 transport ready (T=1 / APDU next)");
}
