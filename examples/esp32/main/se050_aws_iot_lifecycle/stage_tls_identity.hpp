/**
 * @file stage_tls_identity.hpp
 * @brief **STAGE 3 — mbedTLS ↔ SE050 private-key hook.**
 *
 * ## What this stage does
 *
 * Wires mbedTLS so that, during the TLS handshake's `CertificateVerify`
 * step, the private-key signature is delegated to the SE050 instead of
 * being computed on the MCU from a RAM-resident key.
 *
 * This is the single most important piece of code for "private key never
 * leaves the chip" — everything else (provisioning, telemetry, OTA) is
 * built on top of this hook.
 *
 * ## How it works (mbedTLS internals, 3 minutes)
 *
 * `mbedtls_pk_context` is a tagged union of key implementations. By default
 * it holds the raw key bytes and `mbedtls_pk_sign()` does the ECDSA math in
 * the CPU. mbedTLS exposes an escape hatch:
 *
 *   ```c
 *   int mbedtls_pk_setup_opaque(mbedtls_pk_context*, mbedtls_svc_key_id_t);
 *   // OR, for a fully custom implementation:
 *   int mbedtls_pk_setup(mbedtls_pk_context*, const mbedtls_pk_info_t*);
 *   ```
 *
 * We provide an `mbedtls_pk_info_t` struct whose `sign_func` routes the
 * hash to `chip.EcdsaSign(slot::kDeviceIdentityKey, ...)`. The rest of the
 * TLS machinery never realises it's talking to hardware.
 *
 * ## Why this file only sketches the hook instead of implementing it
 *
 * Wiring the full `mbedtls_pk_info_t` vtable into ESP-IDF's mbedTLS build
 * requires:
 *   - `CONFIG_MBEDTLS_PK_ALT` or `CONFIG_MBEDTLS_ECDSA_SIGN_ALT` enabled,
 *   - a minor Kconfig change in `sdkconfig.defaults`,
 *   - careful lifetime management of the `pk_info` struct (must outlive
 *     every `mbedtls_ssl_context` that references it).
 *
 * That configuration is **board-specific**, so we document the exact
 * snippet here and provide a ready-to-paste implementation. The example
 * still demonstrates the **signing path** end-to-end by performing a
 * standalone ECDSA sign that the user can capture and feed into any
 * custom TLS stack.
 */

#pragma once

#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "se050_device.hpp"

#include "lifecycle_config.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace hf_se050_lifecycle::tls_identity {

inline constexpr const char* kTag = "se050_lc.tls";

/**
 * @brief Demo: sign a synthetic "TLS CertificateVerify transcript hash"
 *        using the SE050 identity key.
 *
 * In a real TLS session mbedTLS would compute a SHA-256 transcript hash of
 * the handshake so far and hand it to our hook. We simulate that step so
 * you can see the latency of an SE050-backed handshake on your bench.
 *
 * @return `true` on success, with signature bytes dumped to the log.
 */
template <class DeviceT>
inline bool DemoSignHandshakeTranscript(DeviceT& chip)
{
    ESP_LOGI(kTag, "Simulating TLS CertificateVerify -> SE050 sign.");

    // 1) Build an arbitrary 128-byte buffer that looks like a handshake
    //    transcript; hash it with SHA-256 to produce the 32-byte digest
    //    that a real TLS 1.2 stack would pass to `pk_sign()`.
    std::array<std::uint8_t, 128> fake_transcript{};
    for (std::size_t i = 0; i < fake_transcript.size(); ++i) {
        fake_transcript[i] = static_cast<std::uint8_t>(i ^ 0x55U);
    }
    std::array<std::uint8_t, 32> hash{};
    (void)mbedtls_sha256(fake_transcript.data(), fake_transcript.size(), hash.data(), /*is224=*/0);

    // 2) Ask the SE050 to sign the digest.
    std::uint8_t sig[128]{};
    std::size_t sig_len = 0U;
    const se050::Error sg = chip.EcdsaSign(slot::kDeviceIdentityKey,
                                           se050::cmd::EcdsaAlgo::Sha256,
                                           hash.data(), hash.size(),
                                           sig, sizeof(sig), &sig_len, 600U);
    if (sg != se050::Error::Ok) {
        ESP_LOGE(kTag, "SE050 handshake-sign failed: %u", static_cast<unsigned>(sg));
        return false;
    }
    ESP_LOGI(kTag, "Handshake signature produced (%u bytes DER).",
             static_cast<unsigned>(sig_len));
    return true;
}

/**
 * @brief Pseudo-C snippet describing the real PK-opaque vtable (logged
 *        once at boot for user reference — no runtime effect).
 */
inline void LogMbedTlsIntegrationRecipe()
{
    ESP_LOGI(kTag,
             "RECIPE — wire SE050 into mbedTLS ECDSA sign:\n"
             "  1) menuconfig: MBEDTLS_PK_ALT=y  OR  MBEDTLS_ECDSA_SIGN_ALT=y\n"
             "  2) Provide mbedtls_pk_info_t::sign_func that calls\n"
             "     chip.EcdsaSign(slot::kDeviceIdentityKey, SHA256, hash, ..)\n"
             "  3) mbedtls_pk_setup(&pk, &se050_pk_info);\n"
             "     mbedtls_ssl_conf_own_cert(&conf, &dev_cert, &pk);\n"
             "  4) TLS 1.2/1.3 handshake now delegates to the SE050.\n"
             "  Full reference impl in docs/security_iot_ota_comms.md.");
}

/**
 * @brief Stage 3 entry point.
 *
 * Logs the integration recipe and performs one SE050 sign to measure
 * end-to-end latency (you can watch the `ESP_LOGI` timestamps).
 */
template <class DeviceT>
inline bool RunStage(DeviceT& chip)
{
    ESP_LOGI(kTag, "==================== STAGE 3 — TLS IDENTITY ====================");
    LogMbedTlsIntegrationRecipe();
    const bool ok = DemoSignHandshakeTranscript(chip);
    ESP_LOGI(kTag, "==================== STAGE 3 — %s =============",
             ok ? "COMPLETE" : "FAILED  ");
    return ok;
}

}  // namespace hf_se050_lifecycle::tls_identity
