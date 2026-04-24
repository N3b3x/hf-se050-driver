/**
 * @file se050_object_lifecycle_example.cpp
 * @brief End-to-end **Create / Read / Delete** lifecycle for a Secure Object
 *        stored in the SE050 NVRAM file-system.
 *
 * ## Purpose
 * The SE050 holds key material and trust-anchor blobs (X.509 certificates,
 * policies, vendor public keys, …) in a tamper-resistant NVRAM store. Each
 * blob is a *Secure Object* referenced by a 4-byte `ObjectId`.
 *
 * This example walks through the three operations you need on day one:
 *
 *   1. **Create** — `WriteBinary` allocates a slot and writes the payload.
 *   2. **Read**   — `ReadObject` retrieves it back and we byte-compare it
 *                    to confirm integrity.
 *   3. **Delete** — `DeleteSecureObject` frees the slot and zeroises it.
 *
 * ## When to use this example
 *  - Verifying that the NVRAM is writable on a new board.
 *  - Sanity-checking your own provisioning tooling before you flash a real
 *    certificate into a production slot.
 *  - Reclaiming slot space in development (just delete, do not write).
 *
 * ## Slot-ID convention used here
 * The IoT Applet reserves the `0xF0xx_xxxx` range for *user* objects. We
 * use `0xF001_0203` as a harmless throwaway ID — pick your own range and
 * document it in your fleet's provisioning spec.
 *
 * @warning Every `WriteBinary`/`DeleteSecureObject` pair performs physical
 *          flash writes. Do **not** put this example in a tight loop: the
 *          SE050 NVRAM has finite endurance (datasheet-specified cycles).
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
#include <cstring>

static const char* TAG = "se050_obj_lc";

/**
 * @brief ESP-IDF entry point — runs the CRUD lifecycle once.
 */
extern "C" void app_main(void)
{
    // -------------------------------------------------------------------------
    //  STEP 1 — Bring up transport + T=1 tuning
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

    // -------------------------------------------------------------------------
    //  STEP 2 — SELECT the IoT Applet (all NVRAM APDUs are routed to it)
    // -------------------------------------------------------------------------
    std::uint8_t rapdu[128]{};
    std::size_t rapdu_len = 0;
    const se050::Error sel = chip.SelectDefaultIoTApplet(rapdu, sizeof(rapdu), &rapdu_len, 300U);
    if (sel != se050::Error::Ok) {
        ESP_LOGE(TAG, "Select applet failed: %u", static_cast<unsigned>(sel));
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 3 — Declare the slot ID and payload we will test with
    // -------------------------------------------------------------------------
    //  The payload below spells "HF-SE050-OBJECT-TEST" in ASCII so you can
    //  recognise it in a logic-analyser capture of the T=1 traffic.
    // -------------------------------------------------------------------------
    const se050::cmd::ObjectId object_id{0xF0U, 0x01U, 0x02U, 0x03U};
    const std::array<std::uint8_t, 20> sample = {
        0x48U, 0x46U, 0x2DU, 0x53U, 0x45U, 0x30U, 0x35U, 0x30U, 0x2DU, 0x4FU,
        0x42U, 0x4AU, 0x45U, 0x43U, 0x54U, 0x2DU, 0x54U, 0x45U, 0x53U, 0x54U,
    };

    // -------------------------------------------------------------------------
    //  STEP 4 — CREATE: `WriteBinary` with create-semantics
    // -------------------------------------------------------------------------
    //  Parameters (most interesting ones):
    //   - `object_id`                : 4-byte slot identifier.
    //   - `sample.data(), sample.size()` : bytes to store.
    //   - `false`                    : "update existing?" -> no, create new.
    //   - `0U`                       : write offset into the slot (0 = start).
    //   - `true`                     : "is this the last chunk?" -> yes.
    //   - `(uint16_t)sample.size()`  : total final size of the object.
    //   - `400U`                     : timeout in ms.
    //
    //  SE050 will refuse if the slot already exists — run the smoke or
    //  a previous delete first if that happens during development.
    // -------------------------------------------------------------------------
    const se050::Error we = chip.WriteBinary(object_id, sample.data(), sample.size(),
                                             /*update=*/false, /*offset=*/0U,
                                             /*last_chunk=*/true,
                                             /*total_size=*/static_cast<std::uint16_t>(sample.size()),
                                             /*timeout_ms=*/400U);
    ESP_LOGI(TAG, "WriteBinary(create) -> %u", static_cast<unsigned>(we));
    if (we != se050::Error::Ok) {
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 5 — READ: `ReadObject` and byte-compare
    // -------------------------------------------------------------------------
    //  Parameters mirror the write call. We ask for the exact length we
    //  just stored and assert the returned bytes match.
    // -------------------------------------------------------------------------
    std::uint8_t out[64]{};
    std::size_t out_len = 0;
    const se050::Error re = chip.ReadObject(object_id,
                                            /*use_offset=*/true, /*offset=*/0U,
                                            /*use_length=*/true,
                                            /*length=*/static_cast<std::uint16_t>(sample.size()),
                                            out, sizeof(out), &out_len, 400U);
    ESP_LOGI(TAG, "ReadObject -> %u len=%u", static_cast<unsigned>(re), static_cast<unsigned>(out_len));
    if (re != se050::Error::Ok) {
        return;
    }
    if (out_len != sample.size() || std::memcmp(out, sample.data(), sample.size()) != 0) {
        ESP_LOGE(TAG, "Data mismatch after readback — NVRAM corruption or wrong slot.");
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 6 — DELETE: release the slot
    // -------------------------------------------------------------------------
    //  `DeleteSecureObject` zeroises the payload and frees the slot. After
    //  this call a subsequent `WriteBinary` with the same `object_id` and
    //  `update=false` will succeed again.
    // -------------------------------------------------------------------------
    const se050::Error de = chip.DeleteSecureObject(object_id, 400U);
    ESP_LOGI(TAG, "DeleteSecureObject -> %u", static_cast<unsigned>(de));
}
