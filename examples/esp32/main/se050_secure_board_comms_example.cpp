/**
 * @file se050_secure_board_comms_example.cpp
 * @brief Application-layer **board-to-board** authenticated-datagram demo.
 *
 * ## Purpose
 * When you control both endpoints and cannot run a full TLS/DTLS stack
 * (raw Ethernet, UART, LoRa, CAN…) you still need:
 *
 *   - **Authenticity**   — the packet really came from Board A.
 *   - **Integrity**      — the packet was not altered in flight.
 *   - **Anti-replay**    — an attacker cannot re-send an old captured packet.
 *
 * This example shows a minimal but sound recipe that delivers all three
 * properties using only the SE050 + mbedTLS already on the ESP32:
 *
 *   - SE050 holds a non-exportable **P-256 ECDSA** identity key.
 *   - Each packet carries a **monotonic counter** to block replays.
 *   - Each packet carries a TRNG-sourced **12-byte nonce**.
 *   - The sender signs `counter || nonce || payload` with the SE050.
 *   - The receiver re-hashes the same blob and asks the SE050 to verify
 *     the signature before trusting the payload.
 *
 * The example simulates both Board A (sender) and Board B (receiver) in the
 * same `app_main()` for clarity. In a real deployment Board B would run an
 * identical program, receive the bytes over its physical link, and apply
 * the same verification path.
 *
 * ## What this demo purposely skips
 *  - **Confidentiality.** Adding AES-GCM on top is a one-liner with
 *    `mbedtls_gcm_crypt_and_tag` once you have an agreed symmetric key.
 *    See `docs/security_iot_ota_comms.md` for the full packet shape.
 *  - **Key agreement.** Both boards are assumed to share a common
 *    `ObjectId` pointing at the *same* ECDSA key for demo simplicity. In
 *    production each board has its own key and the peer knows the public
 *    half (after cloud registration).
 *
 * @warning The anti-replay check uses a static local counter here purely
 *          because the sender and receiver live in the same process. A
 *          real receiver must store the last accepted counter in NVS /
 *          SE050 NVRAM so it persists across reboots.
 */

// =============================================================================
//  1) INCLUDES
// =============================================================================
//  - mbedtls/sha256.h : ESP-IDF mbedTLS for the SHA-256 of the packet blob.
//  - se050_device.hpp : SE050 façade (sign + verify APDUs).
// =============================================================================

#include "esp_log.h"
#include "mbedtls/sha256.h"

#include "hf_se050_esp_i2c.hpp"
#include "se050_device.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

static const char* TAG = "se050_comms";

// =============================================================================
//  2) ON-THE-WIRE PACKET SHAPE
// =============================================================================
/**
 * @brief Simplified packet shape used on the wire.
 *
 * Layout (all fields big-endian):
 *   [ counter  : 4 bytes ]  -- monotonic, used for anti-replay.
 *   [ nonce    : 12 bytes ] -- TRNG-sourced freshness.
 *   [ payload  : N bytes ]  -- application data (here: ASCII text).
 *   [ sig_der  : 70–72 B ]  -- ECDSA(P-256, SHA-256) signature over the
 *                              concatenation of the three fields above.
 *
 * In a production protocol you would also add a 1-byte version tag and a
 * 4-byte `key_id` so the receiver can pick the right verification key.
 */
struct SecurePacket {
    std::uint32_t counter;                ///< Monotonically increasing.
    std::array<std::uint8_t, 12> nonce;   ///< Random per-packet.
    std::vector<std::uint8_t> payload;    ///< Application bytes.
    std::vector<std::uint8_t> signature_der; ///< SE050 ECDSA signature (ASN.1 DER).
};

/** @brief Pretty-print a packet so you can compare sender / receiver views. */
static void log_secure_packet(const char* label, const SecurePacket& pkg)
{
    ESP_LOGI(TAG, "--- %s ---", label);
    ESP_LOGI(TAG, "  Counter:          %u", static_cast<unsigned>(pkg.counter));
    ESP_LOGI(TAG, "  Payload (%u B):   %.*s",
             static_cast<unsigned>(pkg.payload.size()),
             static_cast<int>(pkg.payload.size()), pkg.payload.data());
    ESP_LOGI(TAG, "  Signature length: %u", static_cast<unsigned>(pkg.signature_der.size()));
    ESP_LOGI(TAG, "-------------------");
}

/**
 * @brief Serialize the authenticated blob: `counter || nonce || payload`.
 *
 * Both sender and receiver run this *bit-identically* so that the hash they
 * sign/verify is the same. Any mismatch (field ordering, endianness, extra
 * padding) will produce a cryptographically valid but useless signature.
 */
static std::vector<std::uint8_t> serialize_auth_blob(const SecurePacket& pkt)
{
    std::vector<std::uint8_t> blob;
    blob.reserve(4U + pkt.nonce.size() + pkt.payload.size());
    blob.push_back(static_cast<std::uint8_t>(pkt.counter >> 24));
    blob.push_back(static_cast<std::uint8_t>(pkt.counter >> 16));
    blob.push_back(static_cast<std::uint8_t>(pkt.counter >> 8));
    blob.push_back(static_cast<std::uint8_t>(pkt.counter));
    blob.insert(blob.end(), pkt.nonce.begin(), pkt.nonce.end());
    blob.insert(blob.end(), pkt.payload.begin(), pkt.payload.end());
    return blob;
}

/**
 * @brief ESP-IDF entry point — simulates Board A sending and Board B
 *        receiving one authenticated datagram.
 */
extern "C" void app_main(void)
{
    // -------------------------------------------------------------------------
    //  STEP 1 — Bring up SE050 + SELECT the IoT Applet
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
    (void)chip.SelectDefaultIoTApplet(rapdu, sizeof(rapdu), &rapdu_len, 350U);

    // -------------------------------------------------------------------------
    //  STEP 2 — Ensure the shared demo identity key exists
    // -------------------------------------------------------------------------
    //  In production each board owns its *own* private key and has the
    //  peer's *public* key (learned during cloud registration). Here we
    //  share one slot so the demo is self-contained.
    // -------------------------------------------------------------------------
    const se050::cmd::ObjectId comms_key_id{0xF0U, 0x50U, 0x60U, 0x70U};

    bool exists = false;
    (void)chip.CheckObjectExists(comms_key_id, &exists, 350U);
    if (!exists) {
        ESP_LOGI(TAG, "Generating initial device ECDSA identity key...");
        (void)chip.GenerateEcKeyPair(comms_key_id, se050::cmd::EcCurve::NistP256, 500U);
    }

    // =========================================================================
    //  BOARD A — SENDER
    // =========================================================================
    ESP_LOGI(TAG, "[SENDER] Assembling secure datagram.");

    // ---- 3A) Build the packet skeleton --------------------------------------
    SecurePacket tx_packet{};
    tx_packet.counter = 401U; // In production: load "last sent + 1" from NVS.
    tx_packet.payload = {'S','E','N','S','O','R','_','A','L','I','V','E','=','1'};

    // ---- 3B) Pull a fresh 12-byte nonce from the SE050 TRNG -----------------
    //  Using on-chip entropy avoids any dependency on the MCU PRNG quality.
    std::size_t nonce_len = 0;
    const se050::Error rg = chip.GetRandom(static_cast<std::uint16_t>(tx_packet.nonce.size()),
                                           tx_packet.nonce.data(),
                                           tx_packet.nonce.size(),
                                           &nonce_len, 300U);
    if (rg != se050::Error::Ok) {
        ESP_LOGE(TAG, "TRNG failed.");
        return;
    }

    // ---- 3C) Hash the authenticated blob with SHA-256 -----------------------
    //  We feed (counter || nonce || payload) — anything outside this blob is
    //  NOT covered by the signature.
    const std::vector<std::uint8_t> tx_blob = serialize_auth_blob(tx_packet);
    std::array<std::uint8_t, 32> tx_hash{};
    (void)mbedtls_sha256(tx_blob.data(), tx_blob.size(), tx_hash.data(), /*is224=*/0);

    // ---- 3D) Ask the SE050 to sign the hash ---------------------------------
    //  The private key never leaves the chip.
    std::uint8_t sig[128]{};
    std::size_t sig_len = 0;
    const se050::Error sg = chip.EcdsaSign(comms_key_id, se050::cmd::EcdsaAlgo::Sha256,
                                           tx_hash.data(), tx_hash.size(),
                                           sig, sizeof(sig), &sig_len, 500U);
    if (sg != se050::Error::Ok) {
        ESP_LOGE(TAG, "Board A signature failed: %u", static_cast<unsigned>(sg));
        return;
    }
    tx_packet.signature_der.assign(sig, sig + sig_len);

    log_secure_packet("Over-the-wire Packet", tx_packet);

    // =========================================================================
    //  BOARD B — RECEIVER
    // =========================================================================
    //  Real receiver: deserialize the bytes into a SecurePacket first. Here
    //  we just reuse `tx_packet` to focus on the verification logic.
    // =========================================================================
    ESP_LOGI(TAG, "[RECEIVER] Received datagram via Ethernet/Port.");

    // ---- 4A) Anti-replay check ---------------------------------------------
    //  The receiver stores the highest counter it has ever accepted from
    //  Board A. Any packet whose counter is <= that value is replayed and
    //  must be dropped. Persist this across reboots in production.
    static std::uint32_t last_board_a_counter = 400U;
    if (tx_packet.counter <= last_board_a_counter) {
        ESP_LOGE(TAG, "Replay attack detected! counter=%u last=%u",
                 static_cast<unsigned>(tx_packet.counter),
                 static_cast<unsigned>(last_board_a_counter));
        return;
    }

    // ---- 4B) Re-hash the same authenticated blob locally --------------------
    const std::vector<std::uint8_t> rx_blob = serialize_auth_blob(tx_packet);
    std::array<std::uint8_t, 32> rx_hash{};
    (void)mbedtls_sha256(rx_blob.data(), rx_blob.size(), rx_hash.data(), /*is224=*/0);

    // ---- 4C) Ask the SE050 to verify the sender's signature -----------------
    bool sig_ok = false;
    const se050::Error vg = chip.EcdsaVerify(comms_key_id, se050::cmd::EcdsaAlgo::Sha256,
                                             rx_hash.data(), rx_hash.size(),
                                             tx_packet.signature_der.data(),
                                             tx_packet.signature_der.size(),
                                             &sig_ok, 500U);
    if (vg != se050::Error::Ok || !sig_ok) {
        ESP_LOGE(TAG, "Cryptographic packet authenticity FAILED — dropping.");
        return;
    }

    // ---- 4D) Accept the packet and advance the anti-replay watermark --------
    last_board_a_counter = tx_packet.counter;
    ESP_LOGI(TAG, "[RECEIVER] Success! Identity + integrity validated. "
                  "Packet accepted (counter=%u).",
             static_cast<unsigned>(tx_packet.counter));
}
