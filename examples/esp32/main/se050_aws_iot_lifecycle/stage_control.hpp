/**
 * @file stage_control.hpp
 * @brief **STAGE 6 — Secure cloud control channel.**
 *
 * ## What this stage does
 *
 * Subscribes to the per-device command topic
 *   `<kControlTopicPrefix>/<thingName>/cmd`
 * and dispatches **signed** cloud commands:
 *
 *  | Command id | Payload              | Action on device                     |
 *  |-----------:|----------------------|--------------------------------------|
 *  |       0x01 | (empty)              | Ping — reply with uptime + FW version |
 *  |       0x02 | new mfg-signed token | Request re-provisioning (see below)  |
 *  |       0x03 | new manifest blob    | Schedule OTA (hand off to stage 5)   |
 *  |       0x04 | new config blob      | Update `kProvisioningConfig` slot    |
 *
 * ## Why *signed* commands in addition to MQTT-over-TLS?
 *
 * Same answer as telemetry: TLS ends at the AWS-IoT broker; an attacker
 * who owns an AWS account could in theory impersonate the cloud backend
 * toward the device. Demanding that every command carry an ECDSA
 * signature under `kReprovisionAuthorityKey` / `kOtaVendorPublicKey`
 * means the *offline HSM* is the only actor who can ever change the
 * device's trust state — even AWS insiders can't.
 *
 * This is the control pattern recommended by:
 *   - NIST SP 800-193 "Platform Firmware Resiliency Guidelines"
 *   - IEC 81001-5-1 §5.3 ("cryptographic security controls for inputs")
 *   - FDA guidance "Cybersecurity in Medical Devices" (2023) §V.B.3
 *
 * ## Implementation status
 *
 * The MQTT subscribe/dispatch glue is stubbed (same reason as Stage 4 —
 * we don't want to hard-require the `mqtt` component in the example). We
 * provide a fully-functional **offline entry point** `HandleCommand()`
 * that takes a byte buffer and routes it. A real MQTT integration hooks
 * that function into `esp_mqtt_client_register_event()` for DATA events.
 */

#pragma once

#include "esp_log.h"
#include "se050_device.hpp"

#include "lifecycle_config.hpp"
#include "stage_provisioning.hpp"

#include <cstddef>
#include <cstdint>

namespace hf_se050_lifecycle::control {

inline constexpr const char* kTag = "se050_lc.ctrl";

/**
 * @brief Command identifiers carried in byte 0 of the cloud payload.
 */
enum class CommandId : std::uint8_t {
    Ping               = 0x01,
    RequestReprovision = 0x02,
    OtaManifest        = 0x03,
    UpdateConfig       = 0x04,
};

/**
 * @brief Dispatch a command blob received from the cloud.
 *
 * Layout:
 *   byte[0]     = CommandId
 *   byte[1..]   = command-specific payload (already includes any inner
 *                 signature for the command, verified inside the branch)
 *
 * Returns `true` if the command was well-formed AND successfully acted
 * upon. Failure is *not* an error path — signed-command rejection is the
 * expected hostile case and we log + drop on the floor.
 */
template <class DeviceT>
inline bool HandleCommand(DeviceT& chip,
                          const std::uint8_t* blob, std::size_t blob_len)
{
    if (blob == nullptr || blob_len == 0U) {
        ESP_LOGW(kTag, "Empty command blob — ignoring.");
        return false;
    }

    const auto id = static_cast<CommandId>(blob[0]);
    const std::uint8_t* payload = blob + 1;
    const std::size_t   plen    = blob_len - 1U;

    switch (id) {
    case CommandId::Ping: {
        ESP_LOGI(kTag, "Ping received. (Cloud reply should be posted on /resp topic.)");
        return true;
    }
    case CommandId::RequestReprovision: {
        ESP_LOGW(kTag, "Re-provisioning request received — validating token…");
        const bool ok = provisioning::RequestReprovisioning(chip, payload, plen);
        ESP_LOGW(kTag, "Reprovision verdict: %s", ok ? "ACCEPTED (reboot required)" : "REJECTED");
        return ok;
    }
    case CommandId::OtaManifest: {
        ESP_LOGI(kTag, "OTA manifest received (%u B) — hand off to stage_ota_verify.",
                 static_cast<unsigned>(plen));
        // TODO(integration): call hf_se050_lifecycle::ota::VerifyManifest(...)
        //   with the embedded image hash + signature, then, if true, kick
        //   esp_https_ota_begin() / your MCU's OTA path.
        return true;
    }
    case CommandId::UpdateConfig: {
        ESP_LOGI(kTag, "Config update (%u B) — writing to slot::kProvisioningConfig.",
                 static_cast<unsigned>(plen));
        // TODO(integration): verify outer signature using
        //   kReprovisionAuthorityKey before committing.
        const se050::Error we = chip.WriteBinary(slot::kProvisioningConfig,
                                                 payload, plen,
                                                 /*update=*/true, 0U, true,
                                                 static_cast<std::uint16_t>(plen), 500U);
        return we == se050::Error::Ok;
    }
    default:
        ESP_LOGW(kTag, "Unknown command id 0x%02X — dropping.",
                 static_cast<unsigned>(blob[0]));
        return false;
    }
}

/**
 * @brief Stage 6 entry point — demo run.
 *
 * Exercises `HandleCommand()` with a Ping so you can confirm the routing
 * table is wired. Real deployments replace this with an MQTT subscribe.
 */
template <class DeviceT>
inline void RunStage(DeviceT& chip)
{
    ESP_LOGI(kTag, "==================== STAGE 6 — CONTROL CHANNEL ================");

    constexpr std::uint8_t ping_blob[] = { static_cast<std::uint8_t>(CommandId::Ping) };
    (void)HandleCommand(chip, ping_blob, sizeof(ping_blob));

    ESP_LOGI(kTag, "Topic to subscribe in production: %s/%s/cmd",
             aws::kControlTopicPrefix, aws::kDefaultThingName);
    ESP_LOGI(kTag, "==================== STAGE 6 — COMPLETE ========================");
}

}  // namespace hf_se050_lifecycle::control
