/**
 * @file se050_cloud_onboarding_example.cpp
 * @brief Core Identity Primitive generation and cryptographic validation demo.
 *
 * Simulates the primary enrollment step for securing a device identity:
 * forcing the Hardware Root of Trust to generate a persistent Elliptic Curve
 * private key. It verifies the key generation by simulating a cryptographic
 * challenge, requesting an ECDSA signature, and validating the returned ASN.1 DER signature.
 *
 * **Identity Flow:**
 * 1. Generate an internal non-exportable NIST-P256 Elliptic Curve Key inside SE050.
 * 2. Create a "fake" custom digest on the MCU to act as a challenge payload.
 * 3. `EcdsaSign`: Issue an APDU instructing the SE050 to sign the digest.
 * 4. `EcdsaVerify`: (Sanity Check) Supply the signature back to the SE050 to verify it locally.
 *
 * @note Ensures the device has legitimately derived identity materials.
 */
#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_device.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

static const char* TAG = "se050_onboard";

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

    chip.T1().SetInterFrameDelayMs(3U);
    chip.T1().SetReadRetries(8U);
    chip.T1().SetMaxWtxRequests(10U);

    std::uint8_t rapdu[128]{};
    std::size_t rapdu_len = 0;
    const se050::Error sel = chip.SelectDefaultIoTApplet(rapdu, sizeof(rapdu), &rapdu_len, 350U);
    if (sel != se050::Error::Ok) {
        ESP_LOGE(TAG, "Select applet failed: %u", static_cast<unsigned>(sel));
        return;
    }

    se050::cmd::VersionInfo version{};
    const se050::Error ve = chip.GetVersion(&version, 350U);
    ESP_LOGI(TAG, "GetVersion -> %u v=%u.%u.%u cfg=0x%04X", static_cast<unsigned>(ve),
             static_cast<unsigned>(version.applet_major), static_cast<unsigned>(version.applet_minor),
             static_cast<unsigned>(version.applet_patch), static_cast<unsigned>(version.applet_config));

    const se050::cmd::ObjectId key_id{0xF0U, 0x10U, 0x20U, 0x30U};
    const se050::Error ge = chip.GenerateEcKeyPair(key_id, se050::cmd::EcCurve::NistP256, 500U);
    ESP_LOGI(TAG, "GenerateEcKeyPair(P-256) -> %u", static_cast<unsigned>(ge));
    if (ge != se050::Error::Ok) {
        ESP_LOGE(TAG, "If key already exists, delete object and retry provisioning flow");
        return;
    }

    std::array<std::uint8_t, 32> registration_challenge_digest{};
    for (std::size_t i = 0; i < registration_challenge_digest.size(); ++i) {
        registration_challenge_digest[i] = static_cast<std::uint8_t>(0xA0U + i);
    }

    std::uint8_t signature[128]{};
    std::size_t signature_len = 0;
    const se050::Error se = chip.EcdsaSign(key_id, se050::cmd::EcdsaAlgo::Sha256,
                                           registration_challenge_digest.data(), registration_challenge_digest.size(),
                                           signature, sizeof(signature), &signature_len, 500U);
    ESP_LOGI(TAG, "EcdsaSign -> %u sig_len=%u", static_cast<unsigned>(se), static_cast<unsigned>(signature_len));
    if (se != se050::Error::Ok) {
        return;
    }

    bool verified = false;
    const se050::Error ve2 = chip.EcdsaVerify(key_id, se050::cmd::EcdsaAlgo::Sha256,
                                              registration_challenge_digest.data(), registration_challenge_digest.size(),
                                              signature, signature_len, &verified, 500U);
    ESP_LOGI(TAG, "EcdsaVerify -> %u verified=%d", static_cast<unsigned>(ve2), verified ? 1 : 0);

    log_hex("Cloud Registration Digest (SHA-256)", registration_challenge_digest.data(),
            registration_challenge_digest.size());
    log_hex("ECDSA Signature (ASN.1 DER)", signature, signature_len);

    ESP_LOGI(TAG,
             "Onboarding artifact: send {key_id, digest, signature, applet_version} to your registration backend");
}
