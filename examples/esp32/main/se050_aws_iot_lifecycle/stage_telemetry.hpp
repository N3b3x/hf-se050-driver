/**
 * @file stage_telemetry.hpp
 * @brief **STAGE 4 — Continuous secure telemetry** (ADC → signed JSON → MQTT).
 *
 * ## What this stage does
 *
 * Once the device is provisioned and network-up, this stage runs the steady-
 * state "field" loop:
 *
 *   1. Sample ADC1 channel `telemetry::kAdcChannel`, oversampled
 *      `telemetry::kOversampleCount` times to reduce white noise.
 *   2. Format a compact JSON-like payload:
 *
 *        `{"t":<uptime_ms>,"n":<counter>,"v":<mV>,"dev":"<thing>"}`
 *
 *   3. **Sign** the payload bytes with the SE050 identity key (ECDSA-P256,
 *      SHA-256). This is a defense-in-depth layer on top of the already-
 *      encrypted TLS transport: even if the cloud endpoint is compromised,
 *      a stored payload still carries tamper evidence that only the
 *      original device could have produced.
 *   4. Publish to the AWS-IoT topic
 *      `<kTelemetryTopicPrefix>/<thingName>/data`.
 *
 * ## Why per-message signing in addition to TLS?
 *
 * For medical-grade audit trails (HIPAA, ISO 13485, IEC 62304 / 81001-5-1)
 * you need **non-repudiation** — an auditor must be able to prove a given
 * byte-blob originated from a specific device's secure element. TLS proves
 * this only *in transit*; once the payload lands in S3 or Timestream, the
 * TLS MAC is gone. Attaching an SE050 signature to every message preserves
 * origin evidence indefinitely.
 *
 * ## What this stage stubs out
 *
 *  - MQTT publish: commented as a TODO so the example builds without the
 *    `mqtt` component. To enable, `#include "mqtt_client.h"` and call
 *    `esp_mqtt_client_publish()` at the marked line.
 *  - Actual ADC calibration: we use the raw curve-fitted reading. For
 *    medical accuracy, plug in `esp_adc/adc_cali_scheme.h` with either the
 *    line-fitting or curve-fitting scheme your MCU supports.
 */

#pragma once

#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "se050_device.hpp"

#include "lifecycle_config.hpp"

#if HF_SE050_LIFECYCLE_ENABLE_NETWORK
#  include "esp_adc/adc_oneshot.h"
#  include "freertos/FreeRTOS.h"
#  include "freertos/task.h"
#endif

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace hf_se050_lifecycle::telemetry {

inline constexpr const char* kTag = "se050_lc.tlm";

/**
 * @brief Read the ADC once, oversampled, and return the averaged mV value.
 *
 * Uses ADC1 single-shot mode — sufficient for slow sensor cadence.
 * Replace with DMA-continuous mode if you need > 10 kHz sampling.
 */
#if HF_SE050_LIFECYCLE_ENABLE_NETWORK
inline int SampleAdcMillivolts(adc_oneshot_unit_handle_t handle)
{
    int acc = 0;
    int raw = 0;
    for (std::size_t i = 0; i < kOversampleCount; ++i) {
        if (adc_oneshot_read(handle, static_cast<adc_channel_t>(kAdcChannel), &raw) == ESP_OK) {
            acc += raw;
        }
    }
    const int avg = acc / static_cast<int>(kOversampleCount);
    // Rough mV approximation for 12-bit ADC @ 11 dB attenuation on ESP32-S3.
    // Replace with calibration-based conversion for clinical accuracy.
    return (avg * 3300) / 4095;
}
#endif

/**
 * @brief Build the textual telemetry payload.
 *
 * Keeping it ASCII-JSON (rather than CBOR/MessagePack) makes cloud-side
 * debugging trivial: you can paste it into any AWS-IoT rule / Lambda /
 * QuickSight analysis without a schema file.
 */
inline std::size_t FormatPayload(char* buf, std::size_t cap,
                                 std::uint64_t t_ms, std::uint32_t counter, int mv,
                                 const char* thing_name)
{
    return static_cast<std::size_t>(std::snprintf(
        buf, cap,
        "{\"t\":%llu,\"n\":%u,\"v\":%d,\"dev\":\"%s\"}",
        static_cast<unsigned long long>(t_ms),
        static_cast<unsigned>(counter),
        mv,
        thing_name));
}

/**
 * @brief Sign the payload with the SE050 identity key.
 *
 * We sign the SHA-256 of the **raw payload bytes** (including the braces
 * and whitespace). Any change to the bytes in flight invalidates the
 * signature — the cloud verifier must hash the exact same bytes it
 * received.
 */
template <class DeviceT>
inline bool SignPayload(DeviceT& chip,
                        const char* payload, std::size_t len,
                        std::uint8_t* sig, std::size_t cap, std::size_t* sig_len)
{
    std::array<std::uint8_t, 32> digest{};
    (void)mbedtls_sha256(reinterpret_cast<const std::uint8_t*>(payload), len,
                         digest.data(), /*is224=*/0);

    const se050::Error sg = chip.EcdsaSign(slot::kDeviceIdentityKey,
                                           se050::cmd::EcdsaAlgo::Sha256,
                                           digest.data(), digest.size(),
                                           sig, cap, sig_len, 500U);
    return sg == se050::Error::Ok;
}

/**
 * @brief Stub: publish the payload + signature to AWS-IoT over MQTT.
 *
 * Replace with `esp_mqtt_client_publish()` once you link the `mqtt`
 * component. Example:
 *
 * ```cpp
 *   esp_mqtt_client_publish(mqtt_handle, topic, payload, len, 1, 0);
 * ```
 *
 * You can piggy-back the signature either as a second topic (`/sig`) or
 * as a property in AWS IoT Core for LoRaWAN / message metadata.
 */
inline void PublishStub(const char* topic, const char* payload, std::size_t payload_len,
                        const std::uint8_t* sig, std::size_t sig_len)
{
    ESP_LOGI(kTag, "MQTT publish -> %s", topic);
    ESP_LOGI(kTag, "  payload (%u B): %.*s",
             static_cast<unsigned>(payload_len), static_cast<int>(payload_len), payload);
    ESP_LOGI(kTag, "  sig     (%u B): first 8 bytes = %02X %02X %02X %02X %02X %02X %02X %02X",
             static_cast<unsigned>(sig_len),
             sig_len > 0 ? sig[0] : 0, sig_len > 1 ? sig[1] : 0,
             sig_len > 2 ? sig[2] : 0, sig_len > 3 ? sig[3] : 0,
             sig_len > 4 ? sig[4] : 0, sig_len > 5 ? sig[5] : 0,
             sig_len > 6 ? sig[6] : 0, sig_len > 7 ? sig[7] : 0);
}

/**
 * @brief Stage 4 entry point — runs a finite number of iterations so the
 *        example terminates cleanly. In production, loop forever (or on a
 *        FreeRTOS task) and handle MQTT reconnect.
 */
template <class DeviceT>
inline void RunStage(DeviceT& chip, std::uint32_t iterations = 5U)
{
    ESP_LOGI(kTag, "==================== STAGE 4 — TELEMETRY LOOP ==================");

#if HF_SE050_LIFECYCLE_ENABLE_NETWORK
    // -- ADC setup ------------------------------------------------------------
    adc_oneshot_unit_init_cfg_t unit_cfg{};
    unit_cfg.unit_id = ADC_UNIT_1;
    unit_cfg.ulp_mode = ADC_ULP_MODE_DISABLE;

    adc_oneshot_unit_handle_t adc_handle = nullptr;
    if (adc_oneshot_new_unit(&unit_cfg, &adc_handle) != ESP_OK) {
        ESP_LOGE(kTag, "ADC unit init failed.");
        return;
    }
    adc_oneshot_chan_cfg_t chan_cfg{};
    chan_cfg.atten = ADC_ATTEN_DB_12;     // 0..~3.1 V input range on S3.
    chan_cfg.bitwidth = ADC_BITWIDTH_DEFAULT;
    (void)adc_oneshot_config_channel(adc_handle,
                                     static_cast<adc_channel_t>(kAdcChannel), &chan_cfg);
#endif

    char topic[128]{};
    (void)std::snprintf(topic, sizeof(topic), "%s/%s/data",
                        aws::kTelemetryTopicPrefix, aws::kDefaultThingName);

    for (std::uint32_t n = 0; n < iterations; ++n) {
        // -- 1) sample sensor -----------------------------------------------
#if HF_SE050_LIFECYCLE_ENABLE_NETWORK
        const int mv = SampleAdcMillivolts(adc_handle);
#else
        const int mv = 1234 + static_cast<int>(n);  // synthetic
#endif

        // -- 2) format payload ---------------------------------------------
        char payload[160]{};
        const std::size_t plen = FormatPayload(payload, sizeof(payload),
                                               /*t_ms=*/static_cast<std::uint64_t>(n) * kSamplePeriodMs,
                                               /*counter=*/n,
                                               /*mv=*/mv,
                                               /*thing=*/aws::kDefaultThingName);

#if HF_SE050_LIFECYCLE_SIGN_EVERY_MESSAGE
        // -- 3) sign with SE050 --------------------------------------------
        std::uint8_t sig[96]{};
        std::size_t sig_len = 0;
        const bool signed_ok = SignPayload(chip, payload, plen, sig, sizeof(sig), &sig_len);
        if (!signed_ok) {
            ESP_LOGE(kTag, "SE050 payload-sign failed; dropping message.");
            continue;
        }
#else
        std::uint8_t sig[1]{};
        std::size_t sig_len = 0;
#endif

        // -- 4) publish (stub today; real mqtt call once linked) ------------
        PublishStub(topic, payload, plen, sig, sig_len);

#if HF_SE050_LIFECYCLE_ENABLE_NETWORK
        vTaskDelay(pdMS_TO_TICKS(kSamplePeriodMs));
#endif
    }

#if HF_SE050_LIFECYCLE_ENABLE_NETWORK
    (void)adc_oneshot_del_unit(adc_handle);
#endif

    ESP_LOGI(kTag, "==================== STAGE 4 — CYCLE DONE ======================");
}

}  // namespace hf_se050_lifecycle::telemetry
