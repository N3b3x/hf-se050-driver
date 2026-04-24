/**
 * @file se050_cloud_onboarding_example.cpp
 * @brief Device **identity generation** + self-verification.
 *
 * ## Purpose
 * Before a device can enroll with a cloud (AWS IoT, Azure IoT Hub, a private
 * fleet backend, …) it needs a **hardware-rooted** cryptographic identity.
 * This example performs the core of that step:
 *
 *   1. Generate an **NIST P-256** ECC key pair **inside** the SE050. The
 *      private half **never** leaves the chip — it cannot be extracted by
 *      firmware, JTAG, or a malicious attacker with physical access.
 *   2. Build a test digest on the MCU to act as a "challenge".
 *   3. Ask the SE050 to **sign** the digest (`EcdsaSign`). This produces an
 *      ASN.1 DER-encoded ECDSA signature.
 *   4. Ask the SE050 to **verify** its own signature (`EcdsaVerify`) as a
 *      sanity check that the key pair is usable end-to-end.
 *
 * In a real onboarding workflow you would send the **public key**, the
 * **digest**, the **signature** and the applet version to your registration
 * backend; the backend would verify the signature and associate the public
 * key with the device's serial number.
 *
 * ## Why ECDSA P-256?
 *  - Supported by essentially every cloud / TLS stack.
 *  - 72-byte (max) signatures — fits easily in constrained payloads.
 *  - Hardware-accelerated inside the SE050.
 *
 * @note This example uses a fixed slot ID (`0xF0102030`). If the slot
 *       already contains a key, `GenerateEcKeyPair` will fail — delete the
 *       object first (see `se050_object_lifecycle_example`) or change the
 *       slot ID.
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

static const char* TAG = "se050_onboard";

/** @brief Reusable 32-bytes-per-line hex dumper — see the other examples. */
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
 * @brief ESP-IDF entry point — generates a P-256 key, signs, verifies.
 */
extern "C" void app_main(void)
{
    // -------------------------------------------------------------------------
    //  STEP 1 — Bring up transport and SELECT the IoT Applet
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
    //  STEP 2 — Log the applet version (makes bug reports actionable)
    // -------------------------------------------------------------------------
    se050::cmd::VersionInfo version{};
    const se050::Error ve = chip.GetVersion(&version, 350U);
    ESP_LOGI(TAG, "GetVersion -> %u v=%u.%u.%u cfg=0x%04X",
             static_cast<unsigned>(ve),
             static_cast<unsigned>(version.applet_major),
             static_cast<unsigned>(version.applet_minor),
             static_cast<unsigned>(version.applet_patch),
             static_cast<unsigned>(version.applet_config));

    // -------------------------------------------------------------------------
    //  STEP 3 — Generate the device identity key pair (P-256)
    // -------------------------------------------------------------------------
    //  The SE050 creates the key material internally. The private key has
    //  the "non-exportable" policy by default — `ReadPublicEcKey` can still
    //  fetch the public component for sharing with your cloud backend.
    // -------------------------------------------------------------------------
    const se050::cmd::ObjectId key_id{0xF0U, 0x10U, 0x20U, 0x30U};
    const se050::Error ge = chip.GenerateEcKeyPair(key_id, se050::cmd::EcCurve::NistP256, 500U);
    ESP_LOGI(TAG, "GenerateEcKeyPair(P-256) -> %u", static_cast<unsigned>(ge));
    if (ge != se050::Error::Ok) {
        ESP_LOGE(TAG, "If key already exists, delete object and retry provisioning flow");
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 4 — Build a 32-byte "challenge" digest
    // -------------------------------------------------------------------------
    //  In production the digest would be SHA-256(nonce_from_cloud) — a
    //  fresh value provided by your backend so the signature proves
    //  *liveness*, not just key ownership. Here we just fill with 0xA0..0xBF
    //  to keep the example self-contained.
    // -------------------------------------------------------------------------
    std::array<std::uint8_t, 32> registration_challenge_digest{};
    for (std::size_t i = 0; i < registration_challenge_digest.size(); ++i) {
        registration_challenge_digest[i] = static_cast<std::uint8_t>(0xA0U + i);
    }

    // -------------------------------------------------------------------------
    //  STEP 5 — Sign the digest with the freshly-generated private key
    // -------------------------------------------------------------------------
    //  `EcdsaSign` is chip-side: the APDU carries only the digest, never the
    //  key. The returned buffer is an ASN.1 DER ECDSA signature, usually
    //  70–72 bytes for P-256.
    // -------------------------------------------------------------------------
    std::uint8_t signature[128]{};
    std::size_t signature_len = 0;
    const se050::Error se = chip.EcdsaSign(key_id, se050::cmd::EcdsaAlgo::Sha256,
                                           registration_challenge_digest.data(),
                                           registration_challenge_digest.size(),
                                           signature, sizeof(signature), &signature_len, 500U);
    ESP_LOGI(TAG, "EcdsaSign -> %u sig_len=%u", static_cast<unsigned>(se), static_cast<unsigned>(signature_len));
    if (se != se050::Error::Ok) {
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 6 — Verify the signature on-chip (self-check)
    // -------------------------------------------------------------------------
    //  Real clients would verify on the cloud/back-end side using the
    //  exported public key. Doing it locally here simply proves that the
    //  (key, digest, signature) tuple is internally consistent.
    // -------------------------------------------------------------------------
    bool verified = false;
    const se050::Error ve2 = chip.EcdsaVerify(key_id, se050::cmd::EcdsaAlgo::Sha256,
                                              registration_challenge_digest.data(),
                                              registration_challenge_digest.size(),
                                              signature, signature_len, &verified, 500U);
    ESP_LOGI(TAG, "EcdsaVerify -> %u verified=%d", static_cast<unsigned>(ve2), verified ? 1 : 0);

    // -------------------------------------------------------------------------
    //  STEP 7 — Dump the artifacts you would ship to your backend
    // -------------------------------------------------------------------------
    log_hex("Cloud Registration Digest (SHA-256)",
            registration_challenge_digest.data(),
            registration_challenge_digest.size());
    log_hex("ECDSA Signature (ASN.1 DER)", signature, signature_len);

    ESP_LOGI(TAG,
             "Onboarding artifact: send {key_id, digest, signature, applet_version} "
             "to your registration backend");
}
