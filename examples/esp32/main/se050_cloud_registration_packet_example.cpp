/**
 * @file se050_cloud_registration_packet_example.cpp
 * @brief Full "registration packet" producer for cloud/fleet onboarding.
 *
 * ## Purpose
 * Where `se050_cloud_onboarding_example.cpp` covers the *bare primitive*
 * (generate a key and sign a digest), this example builds the **end-to-end
 * payload** you would POST to a real device-registration HTTP API:
 *
 *   - `key_id`           - 4-byte slot identifier inside the SE050.
 *   - `pubkey`           - exported public key (for the backend to trust).
 *   - `challenge`        - 32 random bytes pulled from the SE050 TRNG so the
 *                           signature proves *liveness*, not replay.
 *   - `signature_der`    - ECDSA(P-256, SHA-256) signature of the challenge
 *                           made with the non-exportable private key.
 *
 * The sequence is **idempotent**: if the key already exists it is reused.
 * That matches a factory workflow where the key is generated once, then the
 * MCU re-registers at every boot using the same identity.
 *
 * ## Flow summary
 *   1. `SelectDefaultIoTApplet`   — make APDUs reachable.
 *   2. `CheckObjectExists`        — does this device already have an ID key?
 *   3. `GenerateEcKeyPair`        — only if the slot is empty.
 *   4. `ReadPublicEcKey`          — export the public component for the cloud.
 *   5. `GetRandom`                — pull a 32-byte TRNG challenge.
 *   6. `EcdsaSign`                — sign the challenge with the private key.
 *   7. `EcdsaVerify`              — on-chip self-check (optional but cheap).
 *   8. Log the four fields the backend will ingest.
 *
 * @note The exact on-wire public-key format is applet/policy dependent.
 *       If `ReadPublicEcKey` returns non-`Ok`, the example intentionally
 *       continues: many production flows only send the signature (the cloud
 *       already knows the device's public key from the factory CSV).
 */

// =============================================================================
//  1) INCLUDES
// =============================================================================
#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_device.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>

static const char* TAG = "se050_reg_pkt";

/** @brief 32-byte-per-line hex dumper — see other examples for the pattern. */
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

/**
 * @brief ESP-IDF entry point — assembles a full registration artifact.
 */
extern "C" void app_main(void)
{
    // -------------------------------------------------------------------------
    //  STEP 1 — Bring up transport + SELECT the IoT Applet
    // -------------------------------------------------------------------------
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

    // -------------------------------------------------------------------------
    //  STEP 2 — Ensure the identity key pair exists (idempotent)
    // -------------------------------------------------------------------------
    //  `CheckObjectExists` is an inexpensive APDU — call it every boot to
    //  decide whether to re-generate (first boot) or reuse (subsequent).
    // -------------------------------------------------------------------------
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

    // -------------------------------------------------------------------------
    //  STEP 3 — Export the public key for the cloud backend
    // -------------------------------------------------------------------------
    //  The cloud needs this to later verify any signature the device sends.
    //  Store/transmit it in your DER/PEM format of choice.
    // -------------------------------------------------------------------------
    std::uint8_t pubkey[192]{};
    std::size_t pubkey_len = 0;
    const se050::Error pe = chip.ReadPublicEcKey(key_id, pubkey, sizeof(pubkey), &pubkey_len, 500U);
    ESP_LOGI(TAG, "ReadPublicEcKey -> %u len=%u", static_cast<unsigned>(pe), static_cast<unsigned>(pubkey_len));
    if (pe != se050::Error::Ok) {
        ESP_LOGW(TAG, "Public key format depends on applet/object policy; continuing with signature-only path");
    }

    // -------------------------------------------------------------------------
    //  STEP 4 — Ask the SE050 TRNG for a 32-byte challenge
    // -------------------------------------------------------------------------
    //  Using on-chip entropy prevents the MCU PRNG (or lack thereof) from
    //  weakening the registration material.
    // -------------------------------------------------------------------------
    std::array<std::uint8_t, 32> challenge{};
    std::size_t challenge_len = 0;
    const se050::Error re = chip.GetRandom(static_cast<std::uint16_t>(challenge.size()),
                                           challenge.data(), challenge.size(),
                                           &challenge_len, 350U);
    ESP_LOGI(TAG, "GetRandom challenge -> %u len=%u",
             static_cast<unsigned>(re), static_cast<unsigned>(challenge_len));
    if (re != se050::Error::Ok || challenge_len != challenge.size()) {
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 5 — Sign the challenge with the device's private key
    // -------------------------------------------------------------------------
    std::uint8_t signature[128]{};
    std::size_t signature_len = 0;
    const se050::Error se = chip.EcdsaSign(key_id, se050::cmd::EcdsaAlgo::Sha256,
                                           challenge.data(), challenge.size(),
                                           signature, sizeof(signature), &signature_len, 500U);
    ESP_LOGI(TAG, "EcdsaSign -> %u sig_len=%u",
             static_cast<unsigned>(se), static_cast<unsigned>(signature_len));
    if (se != se050::Error::Ok) {
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 6 — On-chip self-verify (sanity check before transmission)
    // -------------------------------------------------------------------------
    //  If this fails but Sign succeeded, suspect applet corruption or a
    //  mismatched curve/algorithm choice.
    // -------------------------------------------------------------------------
    bool verified = false;
    const se050::Error ve = chip.EcdsaVerify(key_id, se050::cmd::EcdsaAlgo::Sha256,
                                             challenge.data(), challenge.size(),
                                             signature, signature_len, &verified, 500U);
    ESP_LOGI(TAG, "EcdsaVerify -> %u verified=%d", static_cast<unsigned>(ve), verified ? 1 : 0);

    // -------------------------------------------------------------------------
    //  STEP 7 — Dump the payload fields the backend will ingest
    // -------------------------------------------------------------------------
    log_hex("registration.key_id",        key_id.data(),  key_id.size());
    log_hex("registration.pubkey",        pubkey,         pubkey_len);
    log_hex("registration.challenge",     challenge.data(), challenge.size());
    log_hex("registration.signature_der", signature,      signature_len);

    ESP_LOGI(TAG, "Send registration.{key_id,pubkey,challenge,signature_der} "
                  "to cloud enrollment service");
}
