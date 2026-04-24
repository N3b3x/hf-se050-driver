/**
 * @file lifecycle_config.hpp
 * @brief Central configuration for the SE050 AWS-IoT full-lifecycle example.
 *
 * This header is the **single source of truth** for every tunable in the
 * lifecycle example:
 *   - SE050 object-ID (slot) map
 *   - AWS IoT endpoint / thing-name / provisioning template
 *   - WiFi credentials (development defaults — override via menuconfig)
 *   - Telemetry cadence and topics
 *   - Compile-time feature gates
 *
 * ## Slot-ID layout (why these specific IDs)
 *
 * The NXP IoT Applet reserves `0xF0xx_xxxx` for *user* objects. Within that
 * range, production-quality firmware should carve out a **stable namespace**
 * so every stage of the lifecycle can find its artifacts even if the
 * firmware image changes. We use the following convention:
 *
 * ```
 *   0xF000_0001   Device identity ECC key-pair (P-256, non-exportable)
 *   0xF000_0002   Device X.509 certificate (DER, installed at provisioning)
 *   0xF000_0003   AWS IoT Root CA (Amazon RSA 2048 root, for TLS chain verify)
 *   0xF000_0004   Provisioning / config blob (endpoint, region, thing name)
 *   0xF000_0005   OTA vendor public key (ECDSA-P256) — firmware trust anchor
 *   0xF000_0010   "Device provisioned" sentinel (1 byte = 0x01)
 * ```
 *
 * Keep this map under version control; NEVER reuse a slot-ID for a different
 * purpose across firmware versions. Doing so will brick already-deployed
 * devices.
 *
 * ## Security posture (medical-grade baseline)
 *  - Private key: **non-exportable**, stays in SE050 NVRAM for life.
 *  - Device cert: installed exactly once, rotated only via secure channel.
 *  - TLS: 1.2 minimum, ECDHE-ECDSA-AES128-GCM-SHA256 (AWS IoT default).
 *  - All MQTT payloads: additionally **signed per-message** with SE050 for
 *    defense-in-depth (HIPAA "secure audit trail" posture).
 *
 * @note All values marked `OVERRIDE_ME` MUST be replaced for a real
 *       deployment. They are harmless defaults that keep the example
 *       building without external credentials.
 */

#pragma once

#include "se050_device.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace hf_se050_lifecycle {

// =============================================================================
//  1) SE050 SLOT MAP  (the "filesystem" of the secure element)
// =============================================================================
namespace slot {

/// Device identity key-pair (ECC NIST P-256). Private half **never** leaves
/// the chip. Public half is exported once at provisioning to build the CSR.
inline constexpr se050::cmd::ObjectId kDeviceIdentityKey{0xF0U, 0x00U, 0x00U, 0x01U};

/// X.509 device certificate (DER encoded). Installed once, read every TLS
/// handshake so the ESP32 can send it in the `Certificate` message.
inline constexpr se050::cmd::ObjectId kDeviceCertificate{0xF0U, 0x00U, 0x00U, 0x02U};

/// Root CA used to verify the AWS IoT server's certificate chain. Amazon
/// RSA 2048 root for Public endpoints, or your private-CA root.
inline constexpr se050::cmd::ObjectId kServerRootCa{0xF0U, 0x00U, 0x00U, 0x03U};

/// Config blob (endpoint hostname, thing name, region). Stored on-chip so
/// it cannot be modified by unauthenticated firmware replacement.
inline constexpr se050::cmd::ObjectId kProvisioningConfig{0xF0U, 0x00U, 0x00U, 0x04U};

/// OTA trust anchor — ECDSA P-256 *public* key of the build-farm signer.
/// Bootloader checks every incoming firmware image against this key.
inline constexpr se050::cmd::ObjectId kOtaVendorPublicKey{0xF0U, 0x00U, 0x00U, 0x05U};

/// Single-byte "device has been provisioned" sentinel. Presence + value
/// = 0x01 means the provisioning stage already completed successfully.
inline constexpr se050::cmd::ObjectId kProvisionedFlag{0xF0U, 0x00U, 0x00U, 0x10U};

}  // namespace slot

// =============================================================================
//  2) AWS-IoT CONFIGURATION
// =============================================================================
//  These are compile-time placeholders. In production, read them from the
//  `kProvisioningConfig` blob so a single firmware image serves every SKU.
// =============================================================================
namespace aws {

/// AWS IoT Core endpoint hostname (ATS). Format:
///   <prefix>-ats.iot.<region>.amazonaws.com
/// Get yours via: `aws iot describe-endpoint --endpoint-type iot:Data-ATS`
inline constexpr const char* kEndpointHost = "EXAMPLE-ats.iot.us-east-1.amazonaws.com"; /* OVERRIDE_ME */
inline constexpr std::uint16_t kEndpointPort = 8883U;  // MQTT over TLS

/// Fleet-Provisioning-by-Claim template name.
/// Pre-create it via the AWS IoT console or `aws iot create-provisioning-template`.
inline constexpr const char* kProvisioningTemplateName = "HfSE050MedicalFleet"; /* OVERRIDE_ME */

/// "Thing name" used when this device is fully registered. For Fleet
/// Provisioning this is the template output; for one-shot JITR you set it
/// to a stable ID derived from the SE050 serial.
inline constexpr const char* kDefaultThingName = "hf-se050-dev-0001"; /* OVERRIDE_ME */

/// MQTT topic prefix for telemetry. Matches the pattern of an AWS IoT
/// Basic Ingest route or a standard publish-to-topic rule.
inline constexpr const char* kTelemetryTopicPrefix = "hf/medical/telemetry";

/// Command / config topic (device-subscribed). Used by the cloud to push
/// per-device configuration or firmware-update triggers.
inline constexpr const char* kControlTopicPrefix = "hf/medical/control";

}  // namespace aws

// =============================================================================
//  3) WIFI CONFIGURATION (development defaults)
// =============================================================================
namespace wifi {

/// WiFi SSID. In production, store in the `kProvisioningConfig` blob or a
/// dedicated encrypted NVS partition — NEVER hard-code customer credentials.
inline constexpr const char* kSsid = "hardfoc-dev"; /* OVERRIDE_ME */

/// WiFi PSK. Same warning as above.
inline constexpr const char* kPassword = "changeme123"; /* OVERRIDE_ME */

/// How long to wait for association before considering the attempt failed.
inline constexpr std::uint32_t kAssociateTimeoutMs = 20000U;

}  // namespace wifi

// =============================================================================
//  4) TELEMETRY / ADC CONFIGURATION
// =============================================================================
namespace telemetry {

/// How often to sample the sensor and publish. 1000 ms is a sensible
/// balance between responsiveness and cloud-side ingest cost.
inline constexpr std::uint32_t kSamplePeriodMs = 1000U;

/// Number of ADC samples to average per published message (oversampling
/// reduces white noise and is basically free on the ESP32).
inline constexpr std::size_t kOversampleCount = 8U;

/// ADC1 channel that carries the sensor signal. Map to your board.
/// (ESP32-S3: GPIO1=CH0, GPIO2=CH1, ...). Replace for your hardware.
inline constexpr int kAdcChannel = 0;

}  // namespace telemetry

// =============================================================================
//  5) FEATURE GATES (set to 0 to compile out a stage)
// =============================================================================
/// Attempt to bring up WiFi + connect to AWS IoT. Set to 0 on the bench to
/// exercise the SE050 path without needing a real AP / account.
#ifndef HF_SE050_LIFECYCLE_ENABLE_NETWORK
#  define HF_SE050_LIFECYCLE_ENABLE_NETWORK 1
#endif

/// Sign every telemetry payload with the SE050 identity key before
/// publishing (defense-in-depth on top of TLS). Small runtime cost.
#ifndef HF_SE050_LIFECYCLE_SIGN_EVERY_MESSAGE
#  define HF_SE050_LIFECYCLE_SIGN_EVERY_MESSAGE 1
#endif

}  // namespace hf_se050_lifecycle
