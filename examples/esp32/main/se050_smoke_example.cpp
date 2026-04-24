/**
 * @file se050_smoke_example.cpp
 * @brief Full system "smoke test" — exercises every routine bring-up primitive
 *        that a healthy SE050 must support.
 *
 * ## Purpose
 * Where `se050_minimal_example.cpp` answers *"is my SE050 reachable?"*, this
 * example answers the follow-up question: *"is my SE050 fundamentally
 * healthy?"*. It performs a diagnostic sweep of every "must work" primitive:
 *
 *   1. **Link bring-up**              - I2C + T=1 with tuned retries/WTX.
 *   2. **ATR parsing**                - decode IFSC / SEGT / max I2C speed.
 *   3. **Applet selection**           - reach the NXP IoT Applet via APDU.
 *   4. **`GetVersion`**               - reads applet version + secure-box ID.
 *   5. **`GetRandom`**                - exercises the on-chip hardware TRNG.
 *   6. **`GetFreeMemory` (Persistent)** - confirms the NVRAM file-system is
 *                                          reachable and reports free bytes.
 *
 * Any failure above the link layer points at a different root cause than the
 * minimal example, so the two programs form a layered diagnostic ladder.
 *
 * ## When to run
 *  - Factory/incoming inspection.
 *  - Regression test after firmware updates.
 *  - Suspected field failure — tells you whether the chip is alive, whether
 *    its TRNG and NVRAM are functional, and which applet version is loaded.
 *
 * @note Unlike the minimal example, this one tunes T=1 read retries and the
 *       maximum number of Wait-Time-Extension (WTX) requests, because some
 *       commands (e.g. TRNG warmup) can take longer than the default.
 */

// =============================================================================
//  1) INCLUDES
// =============================================================================
//  - esp_log.h              : ESP-IDF logging.
//  - hf_se050_esp_i2c.hpp   : ESP-IDF I2C adapter for the SE050 transport.
//  - se050_atr.hpp          : ATR parser — decodes the Profile-INF bytes into
//                              a structured `se050::atr::Profile`.
//  - se050_device.hpp       : Top-level `se050::Device` façade.
// =============================================================================

#include "esp_log.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_atr.hpp"
#include "se050_device.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>

static const char* TAG = "se050_smoke";

/**
 * @brief Hex-dump helper (32-byte lines). See the minimal example for the
 *        rationale behind the hand-rolled formatter.
 */
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
 * @brief ESP-IDF entry point — runs the full smoke sequence.
 */
extern "C" void app_main(void)
{
    // -------------------------------------------------------------------------
    //  STEP 1 — Construct transport + device
    // -------------------------------------------------------------------------
    hf_se050_examples::HfSe050EspIdfI2c transport{};
    se050::Device chip(transport);

    if (!chip.EnsureInitialized()) {
        ESP_LOGE(TAG, "Transport init failed — see se050_minimal_example for wiring checks.");
        return;
    }

    // -------------------------------------------------------------------------
    //  STEP 2 — Tune the T=1 engine for "diagnostic" operation
    // -------------------------------------------------------------------------
    //  - Hardware reset line toggle (best-effort).
    //  - 3 ms of inter-frame idle for wiring headroom.
    //  - 8 read retries to tolerate transient NACK from a busy chip.
    //  - 10 WTX requests so long crypto ops don't trip the timeout.
    // -------------------------------------------------------------------------
    (void)chip.HardwareReset();
    chip.T1().SetInterFrameDelayMs(3U);
    chip.T1().SetReadRetries(8U);
    chip.T1().SetMaxWtxRequests(10U);

    // -------------------------------------------------------------------------
    //  STEP 3 — T=1 warm reset + ATR capture
    // -------------------------------------------------------------------------
    const se050::Error wr = chip.T1().ChipWarmReset(200U);
    ESP_LOGI(TAG, "WarmReset -> %u", static_cast<unsigned>(wr));

    std::uint8_t atr_inf[96]{};
    std::size_t atr_inf_len = 0;
    const se050::Error atr_e = chip.T1().GetAnswerToReset(atr_inf, sizeof(atr_inf), &atr_inf_len, 300U);
    ESP_LOGI(TAG, "GetATR -> %u len=%u", static_cast<unsigned>(atr_e), static_cast<unsigned>(atr_inf_len));

    if (atr_e == se050::Error::Ok) {
        log_hex("ATR-INF", atr_inf, atr_inf_len);

        // Parse the Profile-INF into human-readable fields. These govern how
        // the T=1 engine negotiates frame sizes and clocking for every future
        // exchange, so it is worth logging them explicitly.
        se050::atr::Profile prof{};
        const se050::Error pe = se050::atr::Parse(atr_inf, atr_inf_len, &prof);
        ESP_LOGI(TAG, "ATR parse -> %u pver=%u ifsc=%u segt_us=%u max_i2c_khz=%u",
                 static_cast<unsigned>(pe),
                 static_cast<unsigned>(prof.protocol_version),
                 static_cast<unsigned>(prof.ifsc),
                 static_cast<unsigned>(prof.segt_us),
                 static_cast<unsigned>(prof.max_i2c_khz));
    }

    // -------------------------------------------------------------------------
    //  STEP 4 — SELECT the default IoT Applet
    // -------------------------------------------------------------------------
    //  Same semantics as the minimal example: after this call, APDUs route
    //  to the NXP IoT Applet so crypto queries (version, random, memory,
    //  keys, objects…) become valid.
    // -------------------------------------------------------------------------
    std::uint8_t sel_rapdu[128]{};
    std::size_t sel_rapdu_len = 0;
    const se050::Error sel = chip.SelectDefaultIoTApplet(sel_rapdu, sizeof(sel_rapdu), &sel_rapdu_len, 300U);
    ESP_LOGI(TAG, "SelectDefaultIoTApplet -> %u len=%u",
             static_cast<unsigned>(sel), static_cast<unsigned>(sel_rapdu_len));

    // -------------------------------------------------------------------------
    //  STEP 5 — GetVersion: which applet/secure-box is running?
    // -------------------------------------------------------------------------
    //  Always log this. When filing a bug with NXP, these fields are the
    //  single most useful identifier after the chip's unique ID.
    // -------------------------------------------------------------------------
    se050::cmd::VersionInfo version{};
    const se050::Error ve = chip.GetVersion(&version, 300U);
    ESP_LOGI(TAG, "GetVersion -> %u v=%u.%u.%u applet_cfg=0x%04X secure_box=0x%04X",
             static_cast<unsigned>(ve),
             static_cast<unsigned>(version.applet_major),
             static_cast<unsigned>(version.applet_minor),
             static_cast<unsigned>(version.applet_patch),
             static_cast<unsigned>(version.applet_config),
             static_cast<unsigned>(version.secure_box));

    // -------------------------------------------------------------------------
    //  STEP 6 — GetRandom: exercise the hardware TRNG
    // -------------------------------------------------------------------------
    //  If this call succeeds but the bytes look like zeros / a repeating
    //  pattern, the TRNG has failed its entropy health check — treat the
    //  chip as untrusted.
    // -------------------------------------------------------------------------
    std::uint8_t random_buf[32]{};
    std::size_t random_len = 0;
    const se050::Error re = chip.GetRandom(16U, random_buf, sizeof(random_buf), &random_len, 300U);
    ESP_LOGI(TAG, "GetRandom -> %u len=%u", static_cast<unsigned>(re), static_cast<unsigned>(random_len));
    if (re == se050::Error::Ok) {
        log_hex("Random", random_buf, random_len);
    }

    // -------------------------------------------------------------------------
    //  STEP 7 — GetFreeMemory(Persistent): NVRAM file-system reachable?
    // -------------------------------------------------------------------------
    //  Reports the number of free bytes in the persistent object store. A
    //  very small number here is a leading indicator that a previous test
    //  never cleaned up its keys/blobs — see `se050_object_lifecycle_example`.
    // -------------------------------------------------------------------------
    std::uint16_t free_persistent = 0;
    const se050::Error me = chip.GetFreeMemory(se050::cmd::MemoryType::Persistent, &free_persistent, 300U);
    ESP_LOGI(TAG, "GetFreeMemory(Persistent) -> %u bytes=%u",
             static_cast<unsigned>(me), static_cast<unsigned>(free_persistent));
}
