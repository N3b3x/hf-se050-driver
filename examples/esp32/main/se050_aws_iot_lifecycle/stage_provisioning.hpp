/**
 * @file stage_provisioning.hpp
 * @brief **STAGE 1 — Manufacturing / first-boot provisioning.**
 *
 * ## What this stage does
 *  1. Check if the device already carries a "provisioned" sentinel.
 *  2. If not:
 *     a. Generate a P-256 ECC key-pair **inside** the SE050
 *        (`GenerateEcKeyPair`). Private half is non-exportable.
 *     b. Export the public key (`ReadPublicEcKey`) — the only thing the
 *        factory PC ever sees.
 *     c. Build a **Certificate Signing Request (CSR)** on the factory PC
 *        using the exported public key. The CSR is signed by the SE050.
 *     d. Factory PC hands the CSR to the vendor CA (or AWS IoT
 *        `RegisterCertificateWithoutCA`) and gets back a device certificate.
 *     e. Install the certificate into `slot::kDeviceCertificate` via
 *        `WriteBinary`.
 *     f. Install the AWS IoT root CA into `slot::kServerRootCa` so the TLS
 *        chain-of-trust can be verified offline.
 *     g. Install the vendor OTA public key into `slot::kOtaVendorPublicKey`.
 *     h. Write the "provisioned" sentinel so subsequent boots skip this.
 *
 * ## Production provisioning architecture — the answer
 *
 * After surveying NXP Plug&Trust, AWS Fleet Provisioning, and Microchip
 * TrustFLEX guidance, the **industry-standard** path is:
 *
 *   **MCU-as-middleman with end-of-line test fixture.**
 *
 * The ESP32 is flashed with "factory firmware" (this example, built with a
 * `HF_FACTORY_MODE` define) that accepts commands over USB/UART from the
 * factory PC. The PC drives the workflow:
 *
 * ```
 *   Factory PC  <--USB-->  ESP32  <--I2C-->  SE050
 *      |  1) "GENKEY"         |                |
 *      | -------------------> |  GenerateEc--> |
 *      |                      | <--OK--------- |
 *      |  2) "READPUB"        |                |
 *      | -------------------> | ReadPublic---> |
 *      | <-- PUB_BYTES ------ | <--pubkey----- |
 *      |                                       |
 *      |  3) Sign CSR locally with pubkey      |
 *      |     Send CSR to internal CA / AWS     |
 *      |  4) "INSTALL_CERT" + bytes            |
 *      | -------------------> | WriteBinary--> |
 *      |                                       |
 *      |  5) "INSTALL_CA" + bytes              |
 *      | -------------------> | WriteBinary--> |
 *      |  6) "LOCK"           |                |
 *      | -------------------> | SetSentinel--> |
 * ```
 *
 * **Why not a bed-of-nails directly on the SE050 I2C lines?**
 *  - The SE050 supports SCP03 (secure-channel) which requires session keys
 *    — those need to live *somewhere*, and the MCU is the natural home.
 *  - You pay for a second fixture and still have to test the MCU/board
 *    afterwards; might as well do both in one station.
 *  - Bed-of-nails cannot re-provision a field-returned device.
 *  - MCU proxy reuses the exact same I2C/T=1 code path that the field
 *    firmware uses — so you test the thing you ship.
 *
 * Bed-of-nails is worth it only when:
 *  - The CM pre-provisions SE050 chips **before** board assembly, OR
 *  - You buy SE050 in the `IoT-A` pre-provisioned profile (no factory
 *    work at all, but you don't own the identity).
 *
 * ## How this example *simulates* the factory
 *
 * We can't ship a real CA / AWS credential pair in open-source code. So
 * this header:
 *  - Runs the **SE050 side verbatim** (real APDUs, real keygen).
 *  - **Stubs** the factory-PC side with clearly-marked `TODO(factory)`
 *    placeholders showing exactly where to plug your CA.
 *  - Logs every step so you can diff the serial trace against your real
 *    factory tool.
 */

#pragma once

#include "esp_log.h"
#include "se050_device.hpp"

#include "lifecycle_config.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace hf_se050_lifecycle::provisioning {

// -----------------------------------------------------------------------------
// Logging tag dedicated to this stage (lets you filter `idf.py monitor`).
// -----------------------------------------------------------------------------
inline constexpr const char* kTag = "se050_lc.prov";

/**
 * @brief Quick idempotency check — has provisioning already completed?
 *
 * Reads the 1-byte sentinel object. If present AND value is 0x01, the
 * device is considered provisioned. Anything else (missing, wrong value)
 * means "still needs factory work".
 */
template <class DeviceT>
inline bool IsProvisioned(DeviceT& chip)
{
    bool exists = false;
    if (chip.CheckObjectExists(slot::kProvisionedFlag, &exists, 300U) != se050::Error::Ok) {
        return false;  // Treat "can't query" as "not provisioned" — fail safe.
    }
    if (!exists) {
        return false;
    }

    std::uint8_t value = 0U;
    std::size_t out_len = 0U;
    const se050::Error re = chip.ReadObject(slot::kProvisionedFlag,
                                            /*use_offset=*/true, /*offset=*/0U,
                                            /*use_length=*/true, /*length=*/1U,
                                            &value, sizeof(value), &out_len, 300U);
    return (re == se050::Error::Ok) && (out_len == 1U) && (value == 0x01U);
}

/**
 * @brief SUB-STEP 1a: Create the device identity key pair in SE050 NVRAM.
 *
 * After this call the chip permanently contains a P-256 private key that
 * never leaves silicon.
 */
template <class DeviceT>
inline bool CreateIdentityKeyPair(DeviceT& chip)
{
    bool exists = false;
    (void)chip.CheckObjectExists(slot::kDeviceIdentityKey, &exists, 300U);
    if (exists) {
        ESP_LOGI(kTag, "[1a] Identity key already present (will reuse).");
        return true;
    }

    ESP_LOGI(kTag, "[1a] Generating device identity ECC-P256 key pair (SE050-internal).");
    const se050::Error ge = chip.GenerateEcKeyPair(slot::kDeviceIdentityKey,
                                                   se050::cmd::EcCurve::NistP256, 600U);
    if (ge != se050::Error::Ok) {
        ESP_LOGE(kTag, "[1a] GenerateEcKeyPair failed: %u", static_cast<unsigned>(ge));
        return false;
    }
    ESP_LOGI(kTag, "[1a] Identity key pair created OK.");
    return true;
}

/**
 * @brief SUB-STEP 1b: Read out the public half for the factory PC / CA.
 *
 * Only the public component is ever exposed. In a real factory the PC
 * would now build a CSR from these bytes and ship it to the internal CA.
 */
template <class DeviceT>
inline bool ExportPublicKey(DeviceT& chip,
                            std::uint8_t* out_pub, std::size_t out_cap, std::size_t* out_len)
{
    const se050::Error pe = chip.ReadPublicEcKey(slot::kDeviceIdentityKey,
                                                 out_pub, out_cap, out_len, 400U);
    if (pe != se050::Error::Ok) {
        ESP_LOGW(kTag, "[1b] ReadPublicEcKey -> %u (format depends on applet policy)",
                 static_cast<unsigned>(pe));
        return false;
    }
    ESP_LOGI(kTag, "[1b] Exported public key (%u bytes) for CSR.",
             static_cast<unsigned>(*out_len));
    return true;
}

/**
 * @brief SUB-STEP 1c/d: Produce + sign a CSR (STUB).
 *
 * In a real factory:
 *   - The PC builds a `CertificationRequestInfo` ASN.1 structure using
 *     the public key retrieved in step 1b.
 *   - It hashes that blob (SHA-256).
 *   - It calls `EcdsaSign` **through the MCU** against the SE050.
 *   - It wraps everything into an RFC 2986 CSR and submits it to the CA.
 *
 * This example just signs a fixed 32-byte "CSR digest" so you can see the
 * SE050 participating. The signature bytes are logged so you can compare
 * against a real CSR built offline.
 */
template <class DeviceT>
inline bool SignCsrDigest(DeviceT& chip,
                          std::uint8_t* out_sig, std::size_t cap, std::size_t* out_len)
{
    // TODO(factory): replace this digest with sha256(DER-encoded CRI).
    std::array<std::uint8_t, 32> csr_digest{};
    for (std::size_t i = 0; i < csr_digest.size(); ++i) {
        csr_digest[i] = static_cast<std::uint8_t>(0xC5U ^ i);  // stable demo bytes
    }

    const se050::Error sg = chip.EcdsaSign(slot::kDeviceIdentityKey,
                                           se050::cmd::EcdsaAlgo::Sha256,
                                           csr_digest.data(), csr_digest.size(),
                                           out_sig, cap, out_len, 600U);
    if (sg != se050::Error::Ok) {
        ESP_LOGE(kTag, "[1c] CSR signing failed: %u", static_cast<unsigned>(sg));
        return false;
    }
    ESP_LOGI(kTag, "[1c] CSR digest signed (%u-byte DER signature).",
             static_cast<unsigned>(*out_len));
    return true;
}

/**
 * @brief SUB-STEP 1e: Install a DER-encoded X.509 device cert into the SE050.
 *
 * `cert_der` / `cert_len` would normally come from the CA response. Demo
 * bytes here simulate a 4-byte "certificate" so the flow still exercises
 * `WriteBinary`.
 */
template <class DeviceT>
inline bool InstallCertificate(DeviceT& chip,
                               const std::uint8_t* cert_der, std::size_t cert_len)
{
    // If a cert is already stored, delete before rewriting (certificate rotation).
    bool present = false;
    (void)chip.CheckObjectExists(slot::kDeviceCertificate, &present, 300U);
    if (present) {
        ESP_LOGI(kTag, "[1e] Deleting existing device cert before rotation.");
        (void)chip.DeleteSecureObject(slot::kDeviceCertificate, 400U);
    }

    const se050::Error we = chip.WriteBinary(slot::kDeviceCertificate,
                                             cert_der, cert_len,
                                             /*update=*/false, /*offset=*/0U,
                                             /*last_chunk=*/true,
                                             /*total_size=*/static_cast<std::uint16_t>(cert_len),
                                             /*timeout_ms=*/500U);
    if (we != se050::Error::Ok) {
        ESP_LOGE(kTag, "[1e] Install device cert failed: %u", static_cast<unsigned>(we));
        return false;
    }
    ESP_LOGI(kTag, "[1e] Device certificate installed (%u bytes).",
             static_cast<unsigned>(cert_len));
    return true;
}

/**
 * @brief SUB-STEP 1f: Install the server-side root CA (e.g. Amazon RSA 2048).
 *
 * Stored inside the SE050 so no attacker with MCU-flash access can swap
 * the trust anchor for a rogue CA.
 */
template <class DeviceT>
inline bool InstallServerRootCa(DeviceT& chip,
                                const std::uint8_t* ca_der, std::size_t ca_len)
{
    const se050::Error we = chip.WriteBinary(slot::kServerRootCa, ca_der, ca_len,
                                             false, 0U, true,
                                             static_cast<std::uint16_t>(ca_len), 500U);
    if (we != se050::Error::Ok) {
        ESP_LOGW(kTag, "[1f] Install root CA -> %u (possibly pre-installed)",
                 static_cast<unsigned>(we));
        return false;
    }
    ESP_LOGI(kTag, "[1f] Server root CA installed (%u bytes).",
             static_cast<unsigned>(ca_len));
    return true;
}

/**
 * @brief SUB-STEP 1g: Install the OTA vendor public key trust anchor.
 */
template <class DeviceT>
inline bool InstallOtaVendorKey(DeviceT& chip,
                                const std::uint8_t* vendor_pub, std::size_t vendor_len)
{
    const se050::Error we = chip.WriteBinary(slot::kOtaVendorPublicKey,
                                             vendor_pub, vendor_len,
                                             false, 0U, true,
                                             static_cast<std::uint16_t>(vendor_len), 500U);
    if (we != se050::Error::Ok) {
        ESP_LOGW(kTag, "[1g] Install OTA vendor key -> %u", static_cast<unsigned>(we));
        return false;
    }
    ESP_LOGI(kTag, "[1g] OTA vendor public key installed (%u bytes).",
             static_cast<unsigned>(vendor_len));
    return true;
}

/**
 * @brief SUB-STEP 1h: Set the "provisioned" sentinel so subsequent boots
 *        skip this expensive stage.
 */
template <class DeviceT>
inline bool MarkProvisioned(DeviceT& chip)
{
    constexpr std::uint8_t kSentinel = 0x01U;
    const se050::Error we = chip.WriteBinary(slot::kProvisionedFlag,
                                             &kSentinel, sizeof(kSentinel),
                                             false, 0U, true, 1U, 400U);
    if (we != se050::Error::Ok) {
        ESP_LOGE(kTag, "[1h] MarkProvisioned failed: %u", static_cast<unsigned>(we));
        return false;
    }
    ESP_LOGI(kTag, "[1h] Device marked as PROVISIONED.");
    return true;
}

/**
 * @brief Orchestrates the full factory provisioning sequence.
 *
 * Safe to call every boot — if already provisioned it returns immediately.
 */
template <class DeviceT>
inline bool RunStage(DeviceT& chip)
{
    ESP_LOGI(kTag, "==================== STAGE 1 — PROVISIONING ====================");

    if (IsProvisioned(chip)) {
        ESP_LOGI(kTag, "Device is already provisioned. Skipping factory stage.");
        return true;
    }

    // -- 1a: keygen inside SE050 ------------------------------------------------
    if (!CreateIdentityKeyPair(chip)) {
        return false;
    }

    // -- 1b: export public component ------------------------------------------
    std::uint8_t pubkey[192]{};
    std::size_t pub_len = 0U;
    (void)ExportPublicKey(chip, pubkey, sizeof(pubkey), &pub_len);

    // -- 1c/d: CSR signing (stubbed digest) ------------------------------------
    std::uint8_t csr_sig[128]{};
    std::size_t csr_sig_len = 0U;
    (void)SignCsrDigest(chip, csr_sig, sizeof(csr_sig), &csr_sig_len);

    // -- 1e: install device cert (stubbed bytes) -------------------------------
    // TODO(factory): Replace with real bytes returned by your CA.
    constexpr std::array<std::uint8_t, 4> placeholder_cert = {
        'C', 'R', 'T', '0'
    };
    (void)InstallCertificate(chip, placeholder_cert.data(), placeholder_cert.size());

    // -- 1f: install AWS root CA (stubbed) -------------------------------------
    // TODO(factory): Replace with the real Amazon ATS root PEM->DER bytes.
    constexpr std::array<std::uint8_t, 4> placeholder_ca = {'C', 'A', '0', '0'};
    (void)InstallServerRootCa(chip, placeholder_ca.data(), placeholder_ca.size());

    // -- 1g: install OTA vendor public key (stubbed) ---------------------------
    // TODO(factory): Replace with the actual vendor ECDSA P-256 public key
    // (65 bytes uncompressed point 0x04 || X || Y).
    std::array<std::uint8_t, 65> placeholder_vendor{};
    placeholder_vendor[0] = 0x04U;
    (void)InstallOtaVendorKey(chip, placeholder_vendor.data(), placeholder_vendor.size());

    // -- 1h: mark device as provisioned ----------------------------------------
    if (!MarkProvisioned(chip)) {
        return false;
    }

    ESP_LOGI(kTag, "==================== STAGE 1 — COMPLETE ========================");
    return true;
}

}  // namespace hf_se050_lifecycle::provisioning
