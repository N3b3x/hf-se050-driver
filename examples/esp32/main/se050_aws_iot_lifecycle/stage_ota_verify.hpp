/**
 * @file stage_ota_verify.hpp
 * @brief **STAGE 5 — OTA manifest verification.**
 *
 * ## What this stage does
 *
 * Before the bootloader hands control to a new firmware image, we ask the
 * SE050 to verify an ECDSA-P256 signature over that image's SHA-256 hash,
 * using the vendor public key planted in `slot::kOtaVendorPublicKey` at
 * manufacturing time.
 *
 * This stage is the "trust root" of the update path — if the vendor key
 * in the SE050 doesn't sign off on the manifest, the update is rejected
 * regardless of how it arrived (OTA-A/B, USB, SD, LoRa, etc.).
 *
 * ## Typical manifest layout (recommended)
 *
 *   ```
 *   struct OtaManifest {
 *       uint32_t magic;            // 0x48464F54  ('HFOT')
 *       uint32_t version;          // semver packed
 *       uint32_t image_size;       // bytes
 *       uint8_t  image_sha256[32]; // sha256 of the binary
 *       uint8_t  signature[72];    // ECDSA-P256 DER signature over image_sha256
 *   };
 *   ```
 *
 * The bootloader:
 *   1. Reads the manifest from the staging partition.
 *   2. Hashes the staged binary and confirms it matches `image_sha256`.
 *   3. Calls `VerifyManifest(...)` below. If it returns `true`, the
 *      update is committed; otherwise rolled back.
 */

#pragma once

#include "esp_log.h"
#include "se050_device.hpp"

#include "lifecycle_config.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace hf_se050_lifecycle::ota {

inline constexpr const char* kTag = "se050_lc.ota";

/**
 * @brief Verify a manifest: (image_hash32, signature) -> vendor key.
 *
 * The caller has already confirmed that the staged binary's SHA-256 equals
 * `image_hash`. We do not re-hash here — that's the bootloader's job (we
 * may not even have enough RAM to hold the full image).
 *
 * @return `true` iff the SE050 reports the signature as valid under
 *         `slot::kOtaVendorPublicKey`.
 */
template <class DeviceT>
inline bool VerifyManifest(DeviceT& chip,
                           const std::uint8_t* image_hash, std::size_t hash_len,
                           const std::uint8_t* signature,  std::size_t sig_len)
{
    bool is_valid = false;
    const se050::Error ve = chip.EcdsaVerify(slot::kOtaVendorPublicKey,
                                             se050::cmd::EcdsaAlgo::Sha256,
                                             image_hash, hash_len,
                                             signature,  sig_len,
                                             &is_valid, 800U);
    if (ve != se050::Error::Ok) {
        ESP_LOGE(kTag, "EcdsaVerify error: %u", static_cast<unsigned>(ve));
        return false;
    }
    ESP_LOGI(kTag, "Manifest signature verdict: %s", is_valid ? "VALID" : "REJECTED");
    return is_valid;
}

/**
 * @brief Stage 5 demo run — constructs a fake manifest and asks the SE050
 *        to verify it. Expected outcome is `REJECTED` unless you install a
 *        real vendor signature.
 */
template <class DeviceT>
inline bool RunStage(DeviceT& chip)
{
    ESP_LOGI(kTag, "==================== STAGE 5 — OTA VERIFY ======================");

    std::array<std::uint8_t, 32> fake_hash{};
    for (std::size_t i = 0; i < fake_hash.size(); ++i) {
        fake_hash[i] = static_cast<std::uint8_t>(0xAAU ^ i);
    }
    std::array<std::uint8_t, 72> fake_sig{};
    // Minimal DER shell: SEQUENCE { INTEGER, INTEGER } -- bytes are nonsense
    // on purpose; SE050 must reject.
    fake_sig[0] = 0x30; fake_sig[1] = 0x44;
    fake_sig[2] = 0x02; fake_sig[3] = 0x20;
    fake_sig[36] = 0x02; fake_sig[37] = 0x20;

    const bool ok = VerifyManifest(chip,
                                   fake_hash.data(), fake_hash.size(),
                                   fake_sig.data(),  fake_sig.size());

    // "ok == false" is the EXPECTED happy path for this demo — the vendor
    // key should reject a garbage signature. We log that clearly.
    ESP_LOGI(kTag, "Demo result: %s  (expected REJECTED for demo inputs)",
             ok ? "VALID" : "REJECTED");
    ESP_LOGI(kTag, "==================== STAGE 5 — COMPLETE ========================");
    return true;
}

}  // namespace hf_se050_lifecycle::ota
