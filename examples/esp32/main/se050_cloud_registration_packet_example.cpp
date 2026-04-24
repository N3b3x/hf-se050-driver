/**
 * @file se050_cloud_registration_packet_example.cpp
 * @brief Hardware Cloud Registration Payload Generation.
 *
 * Demonstrates producing a backend-ready identity artifact (JSON/struct data)
 * capable of proving cryptographic identity to an external cloud or device registry.
 * It queries existence, exports public key parameters, and actively signs a challenge.
 *
 * **Execution Flow:**
 * 1. Perform an idempotent check with `CheckObjectExists`.
 * 2. Generate or ensure the ECDSA Key Pair is populated.
 * 3. Invoke `ReadPublicEcKey` to grab the exportable public component for the cloud server.
 * 4. Execute `GetRandom` to generate a 32-byte session challenge.
 * 5. Sign the challenge mathematically using the protected private key via `EcdsaSign`.
 * 6. Display the resulting payload values to be encapsulated in a cloud API structure.
 */
#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_device.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

static const char* TAG = "se050_reg_pkt";

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

    const se050::cmd::ObjectId key_id{0xF0U, 0x20U, 0x30U, 0x40U};
    bool exists = false;
    const se050::Error ce = chip.CheckObjectExists(key_id, &exists, 350U);
    ESP_LOGI(TAG, "CheckObjectExists -> %u exists=%d", static_cast<unsigned>(ce), exists ? 1 : 0);
    if (ce != se050::Error::Ok) {
        return;
    }

    if (!exists) {
        const se050::Error ge = chip.GenerateEcKeyPair(key_id, se050::cmd::EcCurve::NistP256, 500U);
        ESP_LOGI(TAG, "GenerateEcKeyPair -> %u", static_cast<unsigned>(ge));
        if (ge != se050::Error::Ok) {
            return;
        }
    }

    std::uint8_t pubkey[192]{};
    std::size_t pubkey_len = 0;
    const se050::Error pe = chip.ReadPublicEcKey(key_id, pubkey, sizeof(pubkey), &pubkey_len, 500U);
    ESP_LOGI(TAG, "ReadPublicEcKey -> %u len=%u", static_cast<unsigned>(pe), static_cast<unsigned>(pubkey_len));
    if (pe != se050::Error::Ok) {
        ESP_LOGW(TAG, "Public key format depends on applet/object policy; continue with signature path");
    }

    std::array<std::uint8_t, 32> challenge{};
    std::size_t challenge_len = 0;
    const se050::Error re = chip.GetRandom(static_cast<std::uint16_t>(challenge.size()), challenge.data(),
                                           challenge.size(), &challenge_len, 350U);
    ESP_LOGI(TAG, "GetRandom challenge -> %u len=%u", static_cast<unsigned>(re), static_cast<unsigned>(challenge_len));
    if (re != se050::Error::Ok || challenge_len != challenge.size()) {
        return;
    }

    std::uint8_t signature[128]{};
    std::size_t signature_len = 0;
    const se050::Error se = chip.EcdsaSign(key_id, se050::cmd::EcdsaAlgo::Sha256, challenge.data(), challenge.size(),
                                           signature, sizeof(signature), &signature_len, 500U);
    ESP_LOGI(TAG, "EcdsaSign -> %u sig_len=%u", static_cast<unsigned>(se), static_cast<unsigned>(signature_len));
    if (se != se050::Error::Ok) {
        return;
    }

    bool verified = false;
    const se050::Error ve = chip.EcdsaVerify(key_id, se050::cmd::EcdsaAlgo::Sha256, challenge.data(), challenge.size(),
                                             signature, signature_len, &verified, 500U);
    ESP_LOGI(TAG, "EcdsaVerify -> %u verified=%d", static_cast<unsigned>(ve), verified ? 1 : 0);

    log_hex("registration.key_id", key_id.data(), key_id.size());
    log_hex("registration.pubkey", pubkey, pubkey_len);
    log_hex("registration.challenge", challenge.data(), challenge.size());
    log_hex("registration.signature_der", signature, signature_len);

    ESP_LOGI(TAG, "Send registration.{key_id,pubkey,challenge,signature_der} to cloud enrollment service");
}
