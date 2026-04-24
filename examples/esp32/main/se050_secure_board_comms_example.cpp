/**
 * @file se050_secure_board_comms_example.cpp
 * @brief Board-to-Board Secure Comms App Layer Example.
 *
 * This flow demonstrates how to build an authenticated application packet:
 * - Sender (Board A): local MCU hashes the payload, SE050 signs it (ECDSA).
 * - Receiver (Board B): verifies signature via SE050 before processing.
 *
 * @note In production, append mbedtls AES-GCM around the payload for confidentiality.
 */
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

// Simulate a wire/packet format
struct SecurePacket {
    std::uint32_t counter;
    std::array<std::uint8_t, 12> nonce;
    std::vector<std::uint8_t> payload;
    std::vector<std::uint8_t> signature_der; // Sent by Board A, verified by Board B
};

static void log_secure_packet(const char* label, const SecurePacket& pkg)
{
    ESP_LOGI(TAG, "--- %s ---", label);
    ESP_LOGI(TAG, "  Counter: %u", static_cast<unsigned>(pkg.counter));
    ESP_LOGI(TAG, "  Payload: %.*s", static_cast<int>(pkg.payload.size()), pkg.payload.data());
    ESP_LOGI(TAG, "  Signature length: %u", static_cast<unsigned>(pkg.signature_der.size()));
    ESP_LOGI(TAG, "-------------------");
}

extern "C" void app_main(void)
{
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

    const se050::cmd::ObjectId comms_key_id{0xF0U, 0x50U, 0x60U, 0x70U};

    // 0. Ensure Key exists (We use one key for demo, normally each board has own Private Key)
    bool exists = false;
    (void)chip.CheckObjectExists(comms_key_id, &exists, 350U);
    if (!exists) {
        ESP_LOGI(TAG, "Generating initial device ECDSA identity key...");
        (void)chip.GenerateEcKeyPair(comms_key_id, se050::cmd::EcCurve::NistP256, 500U);
    }

    // ==============================================================
    // BOARD A (SENDER)
    // ==============================================================
    ESP_LOGI(TAG, "[SENDER] Assembling secure datagram.");
    SecurePacket tx_packet{};
    tx_packet.counter = 401U; // Monotonic counter
    tx_packet.payload = {'S','E','N','S','O','R','_','A','L','I','V','E','=','1'};

    // 1. Ask SE050 for a strong cryptographic Nonce
    std::size_t nonce_len = 0;
    const se050::Error rg = chip.GetRandom(static_cast<std::uint16_t>(tx_packet.nonce.size()), tx_packet.nonce.data(), tx_packet.nonce.size(), &nonce_len, 300U);
    
    if (rg != se050::Error::Ok) {
        ESP_LOGE(TAG, "TRNG failed.");
        return;
    }

    // 2. Hash the data that will be sent (Counter || Nonce || Payload)
    std::vector<std::uint8_t> blob_to_sign;
    blob_to_sign.push_back(static_cast<std::uint8_t>(tx_packet.counter >> 24));
    blob_to_sign.push_back(static_cast<std::uint8_t>(tx_packet.counter >> 16));
    blob_to_sign.push_back(static_cast<std::uint8_t>(tx_packet.counter >> 8));
    blob_to_sign.push_back(static_cast<std::uint8_t>(tx_packet.counter));
    blob_to_sign.insert(blob_to_sign.end(), tx_packet.nonce.begin(), tx_packet.nonce.end());
    blob_to_sign.insert(blob_to_sign.end(), tx_packet.payload.begin(), tx_packet.payload.end());

    std::array<std::uint8_t, 32> hash{};
    mbedtls_sha256(blob_to_sign.data(), blob_to_sign.size(), hash.data(), 0);

    // 3. Ask SE050 to Sign the Hash
    std::uint8_t sig[128]{};
    std::size_t sig_len = 0;
    const se050::Error sg = chip.EcdsaSign(comms_key_id, se050::cmd::EcdsaAlgo::Sha256, hash.data(), hash.size(), sig, sizeof(sig), &sig_len, 500U);
    
    if (sg != se050::Error::Ok) {
        ESP_LOGE(TAG, "Board A Signature failed: %u", static_cast<unsigned>(sg));
        return;
    }
    tx_packet.signature_der.assign(sig, sig + sig_len);
    log_secure_packet("Over-the-wire Packet", tx_packet);


    // ==============================================================
    // BOARD B (RECEIVER)
    // ==============================================================
    ESP_LOGI(TAG, "[RECEIVER] Received datagram via Ethernet/Port.");
    
    // 1. Verify anti-replay
    static std::uint32_t last_board_a_counter = 400U;
    if (tx_packet.counter <= last_board_a_counter) {
        ESP_LOGE(TAG, "Replay attack detected!");
        return;
    }

    // 2. Re-create the hash locally
    std::vector<std::uint8_t> blob_to_verify;
    blob_to_verify.push_back(static_cast<std::uint8_t>(tx_packet.counter >> 24));
    blob_to_verify.push_back(static_cast<std::uint8_t>(tx_packet.counter >> 16));
    blob_to_verify.push_back(static_cast<std::uint8_t>(tx_packet.counter >> 8));
    blob_to_verify.push_back(static_cast<std::uint8_t>(tx_packet.counter));
    blob_to_verify.insert(blob_to_verify.end(), tx_packet.nonce.begin(), tx_packet.nonce.end());
    blob_to_verify.insert(blob_to_verify.end(), tx_packet.payload.begin(), tx_packet.payload.end());

    std::array<std::uint8_t, 32> rx_hash{};
    mbedtls_sha256(blob_to_verify.data(), blob_to_verify.size(), rx_hash.data(), 0);

    // 3. Ask SE050 to Verify the Signature
    bool sig_ok = false;
    const se050::Error vg = chip.EcdsaVerify(comms_key_id, se050::cmd::EcdsaAlgo::Sha256, rx_hash.data(), rx_hash.size(), tx_packet.signature_der.data(), tx_packet.signature_der.size(), &sig_ok, 500U);

    if (vg != se050::Error::Ok || !sig_ok) {
        ESP_LOGE(TAG, "Cryptographic Packet Authenticity FAILED. Dropping.");
        return;
    }

    ESP_LOGI(TAG, "[RECEIVER] Success! Identity and Integrity validated. Packet accepted.");
}
