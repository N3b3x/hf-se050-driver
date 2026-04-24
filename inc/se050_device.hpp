/**
 * @file se050_device.hpp
 * @brief Top-level device object: transport session + **T=1** + convenience APDU helpers.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_applet.hpp"
#include "se050_commands.hpp"
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

    /**
     * @brief Transmit a **C-APDU** (already serialized) and receive the **R-APDU** INF bytes.
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
        return t1_.ExchangeInformation(capdu, capdu_len, rapdu_buf, rapdu_cap, rapdu_len, timeout_ms);
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

    Session<TransportT>& SessionRef() noexcept { return session_; }
    const Session<TransportT>& SessionRef() const noexcept { return session_; }

private:
    Session<TransportT> session_;
    T1Session<TransportT> t1_;
};

}  // namespace se050
