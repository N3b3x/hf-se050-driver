/**
 * @file se050_object_lifecycle_example.cpp
 * @brief ESP32 object lifecycle test: write/read/delete binary object.
 */
#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_device.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

static const char* TAG = "se050_obj_lc";

extern "C" void app_main(void)
{
    hf_se050_examples::HfSe050EspIdfI2c transport{};
    se050::Device chip(transport);

    if (!chip.EnsureInitialized()) {
        ESP_LOGE(TAG, "Transport init failed");
        return;
    }

    chip.T1().SetInterFrameDelayMs(3U);
    chip.T1().SetReadRetries(8U);
    chip.T1().SetMaxWtxRequests(10U);

    std::uint8_t rapdu[128]{};
    std::size_t rapdu_len = 0;
    const se050::Error sel = chip.SelectDefaultIoTApplet(rapdu, sizeof(rapdu), &rapdu_len, 300U);
    if (sel != se050::Error::Ok) {
        ESP_LOGE(TAG, "Select applet failed: %u", static_cast<unsigned>(sel));
        return;
    }

    const se050::cmd::ObjectId object_id{0xF0U, 0x01U, 0x02U, 0x03U};
    const std::array<std::uint8_t, 20> sample = {
        0x48U, 0x46U, 0x2DU, 0x53U, 0x45U, 0x30U, 0x35U, 0x30U, 0x2DU, 0x4FU,
        0x42U, 0x4AU, 0x45U, 0x43U, 0x54U, 0x2DU, 0x54U, 0x45U, 0x53U, 0x54U,
    };

    const se050::Error we = chip.WriteBinary(object_id, sample.data(), sample.size(), false, 0U, true,
                                             static_cast<std::uint16_t>(sample.size()), 400U);
    ESP_LOGI(TAG, "WriteBinary(create) -> %u", static_cast<unsigned>(we));
    if (we != se050::Error::Ok) {
        return;
    }

    std::uint8_t out[64]{};
    std::size_t out_len = 0;
    const se050::Error re = chip.ReadObject(object_id, true, 0U, true, static_cast<std::uint16_t>(sample.size()), out,
                                            sizeof(out), &out_len, 400U);
    ESP_LOGI(TAG, "ReadObject -> %u len=%u", static_cast<unsigned>(re), static_cast<unsigned>(out_len));
    if (re != se050::Error::Ok) {
        return;
    }
    if (out_len != sample.size() || std::memcmp(out, sample.data(), sample.size()) != 0) {
        ESP_LOGE(TAG, "Data mismatch after readback");
        return;
    }

    const se050::Error de = chip.DeleteSecureObject(object_id, 400U);
    ESP_LOGI(TAG, "DeleteSecureObject -> %u", static_cast<unsigned>(de));
}
