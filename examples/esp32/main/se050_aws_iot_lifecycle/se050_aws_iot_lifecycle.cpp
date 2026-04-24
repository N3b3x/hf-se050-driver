/**
 * @file se050_aws_iot_lifecycle.cpp
 * @brief **Complete IoT device lifecycle** on the NXP SE050 + ESP32, end-to-end.
 *
 * This is the headline example that ties every capability of the HF-SE050
 * driver together into the exact sequence a medical-grade, HIPAA-audited
 * IoT device goes through in its lifetime:
 *
 * ```
 *   ┌─────────┐   ┌───────────┐   ┌─────────────┐   ┌──────────┐   ┌─────────┐
 *   │  BOOT   │──▶│ STAGE 1   │──▶│ STAGE 2     │──▶│ STAGE 3  │──▶│ STAGE 4 │
 *   │  init   │   │ PROVISION │   │ BOOTSTRAP   │   │ TLS ID   │   │ TLMTRY  │
 *   │  SE050  │   │ (factory) │   │ (WiFi)      │   │ (mbedTLS)│   │ (MQTT)  │
 *   └─────────┘   └───────────┘   └─────────────┘   └──────────┘   └─────────┘
 *                                                                       │
 *                                                                  ┌────▼────┐
 *                                                                  │ STAGE 5 │
 *                                                                  │ OTA     │
 *                                                                  │ VERIFY  │
 *                                                                  └─────────┘
 * ```
 *
 * ## Stage contract
 *
 *   | Stage                  | Runs on every boot?           | Header file                |
 *   |------------------------|-------------------------------|----------------------------|
 *   | 0. Device bring-up     | yes                           | (this file)                |
 *   | 1. Provisioning        | yes, skipped if sentinel set  | stage_provisioning.hpp     |
 *   | 2. Bootstrap (WiFi)    | yes                           | stage_bootstrap.hpp        |
 *   | 3. TLS identity demo   | yes                           | stage_tls_identity.hpp     |
 *   | 4. Telemetry loop      | yes (steady state)            | stage_telemetry.hpp        |
 *   | 5. OTA verify          | on-demand                     | stage_ota_verify.hpp       |
 *
 * ## Why header-only stage files?
 *
 * ESP-IDF's `idf_component_register` wants a single source file listed in
 * `app_config.yml`. Splitting logical stages into sibling `*.hpp` files in
 * the same directory lets us keep the code modular *without* needing an
 * extra CMake target per stage. Each header has inline functions in a
 * dedicated `hf_se050_lifecycle::<stage>` namespace. The compiler inlines
 * them into this one translation unit.
 *
 * ## How to read this file
 *
 * `app_main()` below is deliberately linear and un-clever: it just walks
 * the stages in order, logging what it is doing. The *substance* of each
 * stage lives in the corresponding header. Start here for the flow, jump
 * into a stage header for the mechanics.
 */

// =============================================================================
//  1) INCLUDES — ESP-IDF, the SE050 driver facade, and our stage headers.
// =============================================================================

#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_device.hpp"

#include "se050_aws_iot_lifecycle/lifecycle_config.hpp"
#include "se050_aws_iot_lifecycle/stage_provisioning.hpp"
#include "se050_aws_iot_lifecycle/stage_bootstrap.hpp"
#include "se050_aws_iot_lifecycle/stage_tls_identity.hpp"
#include "se050_aws_iot_lifecycle/stage_telemetry.hpp"
#include "se050_aws_iot_lifecycle/stage_ota_verify.hpp"

#include <cstddef>
#include <cstdint>

namespace {

constexpr const char* kTag = "se050_lc";

/**
 * @brief STAGE 0 — bring the SE050 up to the point every other stage
 *        can assume a working link + selected applet.
 *
 * Mirrors the sequence from `se050_smoke_example.cpp` but inlined so we
 * can keep every stage in one translation unit.
 */
template <class DeviceT>
bool BringUpDevice(DeviceT& chip)
{
    ESP_LOGI(kTag, "==================== STAGE 0 — DEVICE BRING-UP =================");

    if (!chip.EnsureInitialized()) {
        ESP_LOGE(kTag, "Transport init failed — check I2C wiring / pull-ups.");
        return false;
    }

    // Tune the T=1 engine for production reliability.
    (void)chip.HardwareReset();
    chip.T1().SetInterFrameDelayMs(3U);
    chip.T1().SetReadRetries(8U);
    chip.T1().SetMaxWtxRequests(10U);

    const se050::Error wr = chip.T1().ChipWarmReset(200U);
    ESP_LOGI(kTag, "ChipWarmReset -> %u", static_cast<unsigned>(wr));

    // Grab ATR (don't fail boot on this — some fixtures skip the reset pulse).
    std::uint8_t atr[96]{};
    std::size_t atr_len = 0;
    (void)chip.T1().GetAnswerToReset(atr, sizeof(atr), &atr_len, 300U);

    // Select the IoT applet so every subsequent APDU is meaningful.
    std::uint8_t sel_rapdu[128]{};
    std::size_t sel_len = 0;
    const se050::Error sel = chip.SelectDefaultIoTApplet(sel_rapdu, sizeof(sel_rapdu),
                                                         &sel_len, 300U);
    if (sel != se050::Error::Ok) {
        ESP_LOGE(kTag, "SelectDefaultIoTApplet failed: %u", static_cast<unsigned>(sel));
        return false;
    }
    ESP_LOGI(kTag, "==================== STAGE 0 — COMPLETE ========================");
    return true;
}

}  // namespace

/**
 * @brief ESP-IDF entry point — walks the full IoT lifecycle in order.
 */
extern "C" void app_main(void)
{
    ESP_LOGI(kTag, " ");
    ESP_LOGI(kTag, "##################################################################");
    ESP_LOGI(kTag, "# HF-SE050 — AWS IoT FULL LIFECYCLE DEMO                          ");
    ESP_LOGI(kTag, "# Stages: 0 bring-up -> 1 provision -> 2 bootstrap -> 3 tls-id    ");
    ESP_LOGI(kTag, "#         -> 4 telemetry -> 5 ota-verify                          ");
    ESP_LOGI(kTag, "##################################################################");

    // -------------------------------------------------------------------------
    //  STAGE 0 — construct transport + device, open applet
    // -------------------------------------------------------------------------
    hf_se050_examples::HfSe050EspIdfI2c transport{};
    se050::Device chip(transport);

    if (!BringUpDevice(chip)) {
        ESP_LOGE(kTag, "Device bring-up failed — aborting lifecycle demo.");
        return;
    }

    // -------------------------------------------------------------------------
    //  STAGE 1 — factory / first-boot provisioning
    // -------------------------------------------------------------------------
    if (!hf_se050_lifecycle::provisioning::RunStage(chip)) {
        ESP_LOGE(kTag, "Provisioning failed — device not safe to deploy.");
        return;
    }

    // -------------------------------------------------------------------------
    //  STAGE 2 — WiFi / network bring-up
    // -------------------------------------------------------------------------
    const bool net_up = hf_se050_lifecycle::bootstrap::RunStage();
    if (!net_up) {
        ESP_LOGW(kTag, "Network unavailable — continuing in offline demo mode.");
    }

    // -------------------------------------------------------------------------
    //  STAGE 3 — mbedTLS ↔ SE050 signing hook (demo)
    // -------------------------------------------------------------------------
    (void)hf_se050_lifecycle::tls_identity::RunStage(chip);

    // -------------------------------------------------------------------------
    //  STAGE 4 — continuous secure telemetry loop
    // -------------------------------------------------------------------------
    hf_se050_lifecycle::telemetry::RunStage(chip, /*iterations=*/5U);

    // -------------------------------------------------------------------------
    //  STAGE 5 — OTA manifest verify demo
    // -------------------------------------------------------------------------
    (void)hf_se050_lifecycle::ota::RunStage(chip);

    ESP_LOGI(kTag, " ");
    ESP_LOGI(kTag, "##################################################################");
    ESP_LOGI(kTag, "# LIFECYCLE DEMO COMPLETE — device provisioned, keys exercised,  ");
    ESP_LOGI(kTag, "# telemetry signed, OTA trust-anchor verified.                   ");
    ESP_LOGI(kTag, "##################################################################");
}
