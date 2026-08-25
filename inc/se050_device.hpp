/**
 * @file se050_device.hpp
 * @brief Top-level device object: transport session + **T=1** + convenience APDU helpers.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_applet.hpp"
#include "se050_commands.hpp"
#include "se050_rfc3394.hpp"
#include "se050_scp03.hpp"
#include "se050_session.hpp"
#include "se050_t1_session.hpp"
#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>

namespace se050 {

template <typename TransportT>
class Device {
public:
    explicit Device(TransportT& transport) noexcept : session_(transport), t1_(transport) {}

    [[nodiscard]] bool EnsureInitialized() noexcept { return session_.EnsureReady(); }

    /** @brief Raw I²C exchange (legacy / bring-up); prefer @ref T1 for SE050 T=1 blocks. */
    [[nodiscard]] Error TransceiveRaw(const std::uint8_t* tx, std::size_t tx_len,
                                      std::uint8_t* rx, std::size_t rx_cap,
                                      std::size_t* rx_len_out,
                                      std::uint32_t timeout_ms) noexcept {
        return session_.TransceiveRaw(tx, tx_len, rx, rx_cap, rx_len_out, timeout_ms);
    }

    [[nodiscard]] Error HardwareReset() noexcept { return session_.PulseReset(); }

    /** @brief ISO 7816-3 T=1 session bound to the same transport as @ref SessionRef. */
    [[nodiscard]] T1Session<TransportT>& T1() noexcept { return t1_; }
    [[nodiscard]] const T1Session<TransportT>& T1() const noexcept { return t1_; }

    /** @brief SCP03 session. Handshake uses T=1 directly; wrapped APDUs go through @ref TransmitApdu. */
    [[nodiscard]] scp03::Session<TransportT>& Scp03() noexcept { return scp03_; }
    [[nodiscard]] const scp03::Session<TransportT>& Scp03() const noexcept { return scp03_; }

    /**
     * @brief Bind caller-owned wrap workspace (CM4: D2 `.se_apdu_scratch`, not a task stack).
     * @details Required before @ref TransmitApdu will wrap. Handshake APDUs stay plaintext.
     */
    void BindScp03WrapScratch(std::uint8_t* buf, std::size_t cap) noexcept {
        scp03_wrap_ = buf;
        scp03_wrap_cap_ = cap;
    }

    /**
     * @brief Transmit a **C-APDU** (already serialized) and receive the **R-APDU** INF bytes.
     * @details When @ref Scp03 is open, C-MAC/C-ENC wrap and R-MAC/R-ENC unwrap using the
     *          bound scratch. Otherwise plaintext T=1 (honest posture without unique keys).
     * @param capdu Serialized command APDU.
     * @param capdu_len Length of @p capdu.
     * @param rapdu_buf Buffer for concatenated response body + `SW1SW2`.
     * @param rapdu_cap Capacity of @p rapdu_buf.
     * @param rapdu_len Written length on success.
     */
    [[nodiscard]] Error TransmitApdu(const std::uint8_t* capdu, std::size_t capdu_len, std::uint8_t* rapdu_buf,
                                     std::size_t rapdu_cap, std::size_t* rapdu_len,
                                     std::uint32_t timeout_ms) noexcept {
        if (!EnsureInitialized()) {
            return Error::NotInitialized;
        }
        if (!scp03_.IsOpen()) {
            return t1_.ExchangeInformation(capdu, capdu_len, rapdu_buf, rapdu_cap, rapdu_len, timeout_ms);
        }
        if (scp03_wrap_ == nullptr || scp03_wrap_cap_ < scp03::kWrapScratchBytes) {
            return Error::BufferTooSmall;
        }
        std::size_t wrapped_len = 0;
        Error e = scp03_.WrapCommand(capdu, capdu_len, scp03_wrap_, scp03_wrap_cap_, &wrapped_len);
        if (e != Error::Ok) {
            return e;
        }
        e = t1_.ExchangeInformation(scp03_wrap_, wrapped_len, rapdu_buf, rapdu_cap, rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        if (rapdu_len == nullptr) {
            return Error::InvalidArgument;
        }
        return scp03_.UnwrapResponse(rapdu_buf, *rapdu_len, rapdu_buf, rapdu_cap, rapdu_len);
    }

    /**
     * @brief `SELECT` the default IoT applet (`applet::kDefaultIoTAppletAid`, short `Le`).
     * @param rapdu_buf Response buffer (status at tail).
     * @param rapdu_cap Capacity of @p rapdu_buf.
     * @param rapdu_len Written length.
     */
    [[nodiscard]] Error SelectDefaultIoTApplet(std::uint8_t* rapdu_buf, std::size_t rapdu_cap, std::size_t* rapdu_len,
                                               std::uint32_t timeout_ms) noexcept {
        std::uint8_t capdu[5U + sizeof(applet::kDefaultIoTAppletAid) + 1U]{};
        std::size_t capdu_len = 0;
        const Error be = applet::BuildSelectDefaultIot(capdu, sizeof(capdu), &capdu_len);
        if (be != Error::Ok) {
            return be;
        }
        return TransmitApdu(capdu, capdu_len, rapdu_buf, rapdu_cap, rapdu_len, timeout_ms);
    }

    [[nodiscard]] Error GetVersion(cmd::VersionInfo* out, std::uint32_t timeout_ms) noexcept {
        if (out == nullptr) {
            return Error::InvalidArgument;
        }
        std::uint8_t capdu[32]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildGetVersion(capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[64]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        return cmd::ParseVersionInfo(rapdu, rapdu_len, out);
    }

    [[nodiscard]] Error GetRandom(std::uint16_t bytes_requested, std::uint8_t* out, std::size_t out_cap,
                                  std::size_t* out_len, std::uint32_t timeout_ms) noexcept {
        if (out_len == nullptr) {
            return Error::InvalidArgument;
        }
        *out_len = 0;
        std::uint8_t capdu[32]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildGetRandom(bytes_requested, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[kMaxApduResponseBytes]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        return cmd::ParseDataTag1(rapdu, rapdu_len, out, out_cap, out_len);
    }

    [[nodiscard]] Error GetFreeMemory(cmd::MemoryType memory_type, std::uint16_t* free_bytes,
                                      std::uint32_t timeout_ms) noexcept {
        if (free_bytes == nullptr) {
            return Error::InvalidArgument;
        }
        std::uint8_t capdu[32]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildGetFreeMemory(memory_type, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[64]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        return cmd::ParseFreeMemory(rapdu, rapdu_len, free_bytes);
    }

    [[nodiscard]] Error WriteBinary(const cmd::ObjectId& object_id, const std::uint8_t* data, std::size_t data_len,
                                    bool has_offset, std::uint16_t offset, bool has_file_length,
                                    std::uint16_t file_length, std::uint32_t timeout_ms) noexcept {
        std::uint8_t capdu[kMaxApduCommandBytes]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildWriteBinary(object_id, data, data_len, has_offset, offset, has_file_length, file_length,
                                        capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[64]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        const std::uint8_t* payload = nullptr;
        std::size_t payload_len = 0;
        apdu::StatusWords sw{};
        e = apdu::ParseResponse(rapdu, rapdu_len, &payload, &payload_len, &sw);
        if (e != Error::Ok) {
            return e;
        }
        return apdu::IsSuccess(sw) ? Error::Ok : Error::Protocol;
    }

    [[nodiscard]] Error ReadObject(const cmd::ObjectId& object_id, bool has_offset, std::uint16_t offset,
                                   bool has_length, std::uint16_t length, std::uint8_t* out, std::size_t out_cap,
                                   std::size_t* out_len, std::uint32_t timeout_ms) noexcept {
        if (out_len == nullptr) {
            return Error::InvalidArgument;
        }
        *out_len = 0;
        std::uint8_t capdu[64]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildReadObject(object_id, has_offset, offset, has_length, length, capdu, sizeof(capdu),
                                       &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[kMaxApduResponseBytes]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        return cmd::ParseDataTag1(rapdu, rapdu_len, out, out_cap, out_len);
    }

    [[nodiscard]] Error DeleteSecureObject(const cmd::ObjectId& object_id, std::uint32_t timeout_ms) noexcept {
        std::uint8_t capdu[32]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildDeleteSecureObject(object_id, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[64]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        const std::uint8_t* payload = nullptr;
        std::size_t payload_len = 0;
        apdu::StatusWords sw{};
        e = apdu::ParseResponse(rapdu, rapdu_len, &payload, &payload_len, &sw);
        if (e != Error::Ok) {
            return e;
        }
        return apdu::IsSuccess(sw) ? Error::Ok : Error::Protocol;
    }

    [[nodiscard]] Error CheckObjectExists(const cmd::ObjectId& object_id, bool* exists,
                                          std::uint32_t timeout_ms) noexcept {
        if (exists == nullptr) {
            return Error::InvalidArgument;
        }
        *exists = false;
        std::uint8_t capdu[32]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildCheckObjectExists(object_id, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[96]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        return cmd::ParseObjectExistsResult(rapdu, rapdu_len, exists);
    }

    [[nodiscard]] Error ReadPublicEcKey(const cmd::ObjectId& key_id, std::uint8_t* out, std::size_t out_cap,
                                        std::size_t* out_len, std::uint32_t timeout_ms) noexcept {
        return ReadObject(key_id, false, 0U, false, 0U, out, out_cap, out_len, timeout_ms);
    }

    [[nodiscard]] Error GenerateEcKeyPair(const cmd::ObjectId& object_id, cmd::EcCurve curve,
                                          std::uint32_t timeout_ms) noexcept {
        std::uint8_t capdu[64]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildGenerateEcKeyPair(object_id, curve, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[64]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        const std::uint8_t* payload = nullptr;
        std::size_t payload_len = 0;
        apdu::StatusWords sw{};
        e = apdu::ParseResponse(rapdu, rapdu_len, &payload, &payload_len, &sw);
        if (e != Error::Ok) {
            return e;
        }
        return apdu::IsSuccess(sw) ? Error::Ok : Error::Protocol;
    }

    [[nodiscard]] Error EcdsaSign(const cmd::ObjectId& key_id, cmd::EcdsaAlgo algo,
                                  const std::uint8_t* digest, std::size_t digest_len,
                                  std::uint8_t* signature_out, std::size_t signature_cap,
                                  std::size_t* signature_len, std::uint32_t timeout_ms) noexcept {
        if (signature_len == nullptr) {
            return Error::InvalidArgument;
        }
        *signature_len = 0;
        std::uint8_t capdu[256]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildEcdsaSign(key_id, algo, digest, digest_len, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[kMaxApduResponseBytes]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        return cmd::ParseDataTag1(rapdu, rapdu_len, signature_out, signature_cap, signature_len);
    }

    [[nodiscard]] Error EcdsaVerify(const cmd::ObjectId& key_id, cmd::EcdsaAlgo algo,
                                    const std::uint8_t* digest, std::size_t digest_len,
                                    const std::uint8_t* signature, std::size_t signature_len,
                                    bool* verified, std::uint32_t timeout_ms) noexcept {
        if (verified == nullptr) {
            return Error::InvalidArgument;
        }
        *verified = false;
        std::uint8_t capdu[384]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildEcdsaVerify(key_id, algo, digest, digest_len, signature, signature_len, capdu,
                                        sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[96]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        return cmd::ParseVerifyResult(rapdu, rapdu_len, verified);
    }

    /**
     * @brief Write a persistent AESKey (AN12413 WriteSymmKey, P1_AES).
     * @details Image KEK must be an AES object, not a BinaryFile, or
     *          CipherOneShot / RFC3394 unwrap returns 0x6985.
     */
    [[nodiscard]] Error WriteAesKey(const cmd::ObjectId& object_id, const std::uint8_t* key, std::size_t key_len,
                                    std::uint32_t timeout_ms) noexcept {
        std::uint8_t capdu[80]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildWriteAesKey(object_id, key, key_len, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[32]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        const std::uint8_t* payload = nullptr;
        std::size_t payload_len = 0;
        apdu::StatusWords sw{};
        e = apdu::ParseResponse(rapdu, rapdu_len, &payload, &payload_len, &sw);
        if (e != Error::Ok) {
            return e;
        }
        return apdu::IsSuccess(sw) ? Error::Ok : Error::Protocol;
    }

    /**
     * @brief One-shot AES-ECB (AN12413 CipherOneShot, AES_ECB_NOPAD).
     * @details Input must be a multiple of 16 bytes. Used as the RFC 3394
     *          block oracle so the KEK never leaves the SE.
     */
    [[nodiscard]] Error CipherAesEcb(const cmd::ObjectId& key_id, bool decrypt, const std::uint8_t* in,
                                     std::size_t in_len, std::uint8_t* out, std::size_t out_cap, std::size_t* out_len,
                                     std::uint32_t timeout_ms) noexcept {
        if (out_len == nullptr) {
            return Error::InvalidArgument;
        }
        *out_len = 0;
        if (in == nullptr || out == nullptr || in_len == 0U || (in_len % 16U) != 0U) {
            return Error::InvalidArgument;
        }
        std::uint8_t capdu[80]{};
        std::size_t capdu_len = 0;
        Error e = cmd::BuildCipherOneShot(key_id, decrypt, in, in_len, capdu, sizeof(capdu), &capdu_len);
        if (e != Error::Ok) {
            return e;
        }
        std::uint8_t rapdu[48]{};
        std::size_t rapdu_len = 0;
        e = TransmitApdu(capdu, capdu_len, rapdu, sizeof(rapdu), &rapdu_len, timeout_ms);
        if (e != Error::Ok) {
            return e;
        }
        return cmd::ParseDataTag1(rapdu, rapdu_len, out, out_cap, out_len);
    }

    /**
     * @brief RFC 3394 unwrap of an AES-256 CEK using @p kek_id as the wrapping key.
     * @details 24 AES-ECB decrypt APDUs. Caller must HoldBus for the whole call.
     */
    [[nodiscard]] Error UnwrapAes256Rfc3394(const cmd::ObjectId& kek_id, const std::uint8_t* wrapped,
                                            std::size_t wrapped_len, std::uint8_t* out, std::size_t out_cap,
                                            std::size_t* out_len, std::uint32_t timeout_ms) noexcept {
        struct Ctx {
            Device* self;
            cmd::ObjectId id;
            std::uint32_t timeout_ms;
        };
        Ctx ctx{this, kek_id, timeout_ms};
        auto decrypt = [](const std::uint8_t in[16], std::uint8_t outb[16], void* v) -> Error {
            auto* c = static_cast<Ctx*>(v);
            std::size_t n = 0;
            const Error e = c->self->CipherAesEcb(c->id, true, in, 16U, outb, 16U, &n, c->timeout_ms);
            if (e != Error::Ok) {
                return e;
            }
            return (n == 16U) ? Error::Ok : Error::Protocol;
        };
        return rfc3394::Unwrap(wrapped, wrapped_len, out, out_cap, out_len, decrypt, &ctx);
    }

    Session<TransportT>& SessionRef() noexcept { return session_; }
    const Session<TransportT>& SessionRef() const noexcept { return session_; }

private:
    Session<TransportT> session_;
    T1Session<TransportT> t1_;
    scp03::Session<TransportT> scp03_{};
    std::uint8_t* scp03_wrap_{nullptr};
    std::size_t scp03_wrap_cap_{0};
};

}  // namespace se050
