/**
 * @file se050_minimal_example.cpp
 * @brief Minimal "does my SE050 work?" electrical + protocol bring-up example.
 *
 * ## Purpose
 * This example is the **first thing to run** on a freshly wired NXP SE050
 * secure element. It proves, in order of increasing complexity:
 *   1. The ESP32 can talk to the SE050 **over I2C** (electrical layer).
 *   2. The SE050 can complete an **ISO/IEC 7816-3 T=1 warm reset**
 *      (link-layer handshake).
 *   3. The SE050 will emit a valid **Answer-To-Reset (ATR)** / Profile-INF
 *      frame (protocol handshake complete).
 *   4. The default **NXP IoT Applet** can be selected via an **APDU**
 *      (application layer reachable — ready for crypto commands).
 *
 * ## What this example does NOT do
 *  - It does not open a secure SCP03 session (no encryption of APDUs).
 *  - It does not generate keys, write objects, or perform crypto.
 *  - It does not authenticate to the chip.
 *
 * Those steps are covered in the `cloud_onboarding`, `object_lifecycle`,
 * and `secure_board_comms` examples.
 *
 * ## Typical use cases
 *  - New PCB bring-up: confirm I2C wiring is correct.
 *  - Production-line go/no-go test for the SE050 IC.
 *  - Diagnosing a suspected silicon/transport/protocol failure.
 *
 * ## Interpreting the logs
 * Every SE050 API call returns a `se050::Error` value. When non-zero, it
 * narrows down the failure layer:
 *   - Transport-level (I2C NACK, bus stuck) -> wiring/pull-ups/VCC issue.
 *   - T=1-level (no ATR, bad CRC) -> clock/timing, inter-frame delays, or
 *     a chip that never left the reset state.
 *   - APDU-level (SW != 0x9000) -> applet not loaded, wrong AID, or the
 *     chip is in a provisioning state that forbids anonymous SELECT.
 *
 * @note Requires: a physically present SE050, correct I2C wiring
 *       (SDA/SCL with pull-ups), VCC in spec, and the RESET line wired
 *       to the GPIO declared in `hf_se050_esp_i2c.hpp` (optional but
 *       recommended for a deterministic hardware reset).
 */

// =============================================================================
//  1) INCLUDES
// =============================================================================
//  - esp_log.h              : ESP-IDF logging macros (ESP_LOGI / ESP_LOGE...)
//  - hf_se050_esp_i2c.hpp   : Concrete I2C transport adapter that connects the
//                              portable hf-se050 driver to ESP-IDF's I2C stack.
//  - se050_apdu.hpp         : Tiny helpers to parse APDU response status words.
//  - se050_device.hpp       : High-level `se050::Device` façade (owns T=1 +
//                              APDU layering) — the main class used here.
// =============================================================================

#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_apdu.hpp"
#include "se050_device.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>

/// Tag used by all `ESP_LOGx` calls in this example so you can filter logs
/// (e.g. `idf.py monitor` + `set TAG se050_minimal`).
static const char* TAG = "se050_minimal";

/**
 * @brief Pretty-print a byte buffer as hex, chunked so it fits cleanly in a
 *        serial terminal (48 bytes per log line by default).
 *
 * @param label  Human-readable tag prepended to every hex line.
 * @param data   Pointer to buffer. May be null when @p len is 0.
 * @param len    Number of bytes to print.
 *
 * The function is intentionally dependency-free (no `<iomanip>` / iostream)
 * so it remains cheap in a freestanding ESP32 image.
 */
static void log_hex(const char* label, const std::uint8_t* data, std::size_t len)
{
    if (len == 0U || data == nullptr) {
        ESP_LOGI(TAG, "%s: <empty>", label);
        return;
    }
    constexpr std::size_t kChunk = 48U;
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
 * @brief ESP-IDF application entry point.
 *
 * Executes the minimal bring-up sequence end-to-end. Each stage logs its
 * result so failures pinpoint exactly which layer is misbehaving.
 */
extern "C" void app_main(void)
{
    // -------------------------------------------------------------------------
    //  STEP 1 — Build the transport and device objects
    // -------------------------------------------------------------------------
    //  `HfSe050EspIdfI2c` wraps the ESP-IDF I2C master driver and implements
    //  the abstract `se050::II2cTransport` interface. `se050::Device` takes
    //  this transport by reference and layers T=1 + APDU on top of it.
    //  Nothing actually touches the bus until `EnsureInitialized()` runs.
    // -------------------------------------------------------------------------
    hf_se050_examples::HfSe050EspIdfI2c transport{};
    se050::Device chip(transport);

    // -------------------------------------------------------------------------
    //  STEP 2 — Bring up the I2C transport (electrical layer)
    // -------------------------------------------------------------------------
    //  `EnsureInitialized()` installs the I2C driver, configures clock speed,
    //  and probes the configured SE050 address. A `false` here means the
    //  ESP32 cannot even see the chip (wiring, pull-ups, power, or address).
    // -------------------------------------------------------------------------
    if (!chip.EnsureInitialized()) {
        ESP_LOGE(TAG, "Transport init failed — check SDA/SCL wiring, pull-ups, VCC and I2C address.");
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 3 — Hardware reset (if RESET GPIO is wired)
    // -------------------------------------------------------------------------
    //  Pulses the SE050 RESET line to force a known state. This is a no-op
    //  (returns non-fatal) when the pin is not wired — the subsequent T=1
    //  warm reset can still recover the link.
    // -------------------------------------------------------------------------
    (void)chip.HardwareReset();

    // Give the T=1 state-machine a conservative inter-frame delay. The SE050
    // tolerates 0 ms on healthy boards, but 3 ms is friendlier to noisy PCBs.
    chip.T1().SetInterFrameDelayMs(3U);

    // -------------------------------------------------------------------------
    //  STEP 4 — ISO-7816-3 T=1 WARM RESET
    // -------------------------------------------------------------------------
    //  Sends the T=1 resynchronisation / warm-reset sequence. On success the
    //  chip internally prepares its ATR frame and is ready for the first
    //  APDU. Timeout is in milliseconds.
    // -------------------------------------------------------------------------
    const se050::Error wr = chip.T1().ChipWarmReset(150U);
    ESP_LOGI(TAG, "T1::ChipWarmReset -> se050::Error=%u", static_cast<unsigned>(wr));

    // -------------------------------------------------------------------------
    //  STEP 5 — Fetch the Answer-To-Reset (ATR) / Profile INF frame
    // -------------------------------------------------------------------------
    //  The ATR advertises protocol version, IFSC (max information-field
    //  size), SEGT (extra guard time) and the negotiated max I2C clock.
    //  We print it raw; parsing is shown in the smoke-test example.
    // -------------------------------------------------------------------------
    std::uint8_t atr[96]{};
    std::size_t atr_len = 0;
    const se050::Error ar = chip.T1().GetAnswerToReset(atr, sizeof(atr), &atr_len, 250U);
    ESP_LOGI(TAG, "T1::GetAnswerToReset -> se050::Error=%u atr_len=%u",
             static_cast<unsigned>(ar), static_cast<unsigned>(atr_len));
    if (ar == se050::Error::Ok) {
        log_hex("ATR / profile INF", atr, atr_len);
    }

    // -------------------------------------------------------------------------
    //  STEP 6 — SELECT the default NXP IoT Applet (APDU layer)
    // -------------------------------------------------------------------------
    //  Sends the ISO-7816-4 `SELECT by AID` APDU for the NXP IoT Applet.
    //  Status Word 0x9000 means "command succeeded" — the applet is now the
    //  active context and any subsequent crypto APDU will be routed to it.
    //  Anything else (e.g. 0x6A82, "file not found") signals a provisioning
    //  state mismatch.
    // -------------------------------------------------------------------------
    std::uint8_t rapdu[128]{};
    std::size_t rapdu_len = 0;
    const se050::Error se = chip.SelectDefaultIoTApplet(rapdu, sizeof(rapdu), &rapdu_len, 300U);
    ESP_LOGI(TAG, "SelectDefaultIoTApplet -> se050::Error=%u rapdu_len=%u",
             static_cast<unsigned>(se), static_cast<unsigned>(rapdu_len));

    if (se == se050::Error::Ok && rapdu_len >= 2U) {
        log_hex("SELECT R-APDU", rapdu, rapdu_len);

        // Parse out the 2-byte trailing status word from the response APDU.
        // `IsSuccess()` is simply "SW == 0x9000".
        const std::uint8_t* payload = nullptr;
        std::size_t payload_len = 0;
        se050::apdu::StatusWords sw{};
        (void)se050::apdu::ParseResponse(rapdu, rapdu_len, &payload, &payload_len, &sw);

        ESP_LOGI(TAG, "SELECT SW=%02X%02X ok=%d",
                 static_cast<unsigned>(sw.sw1),
                 static_cast<unsigned>(sw.sw2),
                 se050::apdu::IsSuccess(sw) ? 1 : 0);
    }

    // -------------------------------------------------------------------------
    //  DONE — the T=1 + APDU path has been exercised end-to-end without SCP03.
    // -------------------------------------------------------------------------
    ESP_LOGI(TAG, "HF-SE050 driver: T=1 + APDU path exercised (SCP03 not enabled)");
}
