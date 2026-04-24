/**
 * @file se050_commands.hpp
 * @brief Typed SE050 command builders/parsers for a core management/object subset.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_apdu.hpp"
#include "se050_tlv.hpp"
#include "se050_types.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <cstdint>

namespace se050::cmd {

inline constexpr std::uint8_t kClaNoSm = 0x80U;

inline constexpr std::uint8_t kInsWrite = 0x01U;
inline constexpr std::uint8_t kInsRead = 0x02U;
inline constexpr std::uint8_t kInsCrypto = 0x03U;
inline constexpr std::uint8_t kInsMgmt = 0x04U;

inline constexpr std::uint8_t kP1Default = 0x00U;
inline constexpr std::uint8_t kP1Binary = 0x06U;
inline constexpr std::uint8_t kP1Signature = 0x0CU;
inline constexpr std::uint8_t kP1Ec = 0x01U;
inline constexpr std::uint8_t kP1KeyPair = 0x60U;

inline constexpr std::uint8_t kP2Default = 0x00U;
inline constexpr std::uint8_t kP2Version = 0x20U;
inline constexpr std::uint8_t kP2Memory = 0x22U;
inline constexpr std::uint8_t kP2DeleteObject = 0x28U;
inline constexpr std::uint8_t kP2Random = 0x49U;
inline constexpr std::uint8_t kP2Exist = 0x27U;
inline constexpr std::uint8_t kP2Sign = 0x09U;
inline constexpr std::uint8_t kP2Verify = 0x0AU;

inline constexpr std::uint8_t kTag1 = 0x41U;
inline constexpr std::uint8_t kTag2 = 0x42U;
inline constexpr std::uint8_t kTag3 = 0x43U;
inline constexpr std::uint8_t kTag5 = 0x45U;

inline constexpr std::uint8_t kResultSuccess = 0x01U;

using ObjectId = std::array<std::uint8_t, 4>;

enum class MemoryType : std::uint8_t {
    Persistent = 0x01,
    TransientReset = 0x02,
    TransientDeselect = 0x03,
};

enum class EcCurve : std::uint8_t {
    NistP192 = 0x01,
    NistP224 = 0x02,
    NistP256 = 0x03,
    NistP384 = 0x04,
    NistP521 = 0x05,
};

enum class EcdsaAlgo : std::uint8_t {
    Sha1 = 0x11,
    Sha224 = 0x25,
    Sha256 = 0x21,
    Sha384 = 0x22,
    Sha512 = 0x26,
};

struct VersionInfo {
    std::uint8_t applet_major{0};
    std::uint8_t applet_minor{0};
    std::uint8_t applet_patch{0};
    std::uint16_t applet_config{0};
    std::uint16_t secure_box{0};
};

[[nodiscard]] inline Error BuildGetVersion(std::uint8_t* out, std::size_t out_cap,
                                           std::size_t* out_len) noexcept {
    return apdu::BuildCase4Extended(kClaNoSm, kInsMgmt, kP1Default, kP2Version, nullptr, 0U, out, out_cap,
                                    out_len);
}

[[nodiscard]] inline Error BuildGetRandom(std::uint16_t random_len, std::uint8_t* out, std::size_t out_cap,
                                          std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[8]{};
    std::size_t payload_len = 0;
    const Error t = tlv::AppendU16Be(kTag1, random_len, payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsMgmt, kP1Default, kP2Random, payload, payload_len, out, out_cap,
                                    out_len);
}

[[nodiscard]] inline Error BuildGetFreeMemory(MemoryType memory_type, std::uint8_t* out, std::size_t out_cap,
                                              std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[8]{};
    std::size_t payload_len = 0;
    const Error t = tlv::AppendU8(kTag1, static_cast<std::uint8_t>(memory_type), payload, sizeof(payload),
                                  &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsMgmt, kP1Default, kP2Memory, payload, payload_len, out, out_cap,
                                    out_len);
}

[[nodiscard]] inline Error BuildDeleteSecureObject(const ObjectId& object_id, std::uint8_t* out,
                                                   std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[12]{};
    std::size_t payload_len = 0;
    const Error t = tlv::Append(kTag1, object_id.data(), object_id.size(), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsMgmt, kP1Default, kP2DeleteObject, payload, payload_len, out,
                                    out_cap, out_len);
}

[[nodiscard]] inline Error BuildCheckObjectExists(const ObjectId& object_id, std::uint8_t* out,
                                                  std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[12]{};
    std::size_t payload_len = 0;
    const Error t = tlv::Append(kTag1, object_id.data(), object_id.size(), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsRead, kP1Default, kP2Exist, payload, payload_len, out, out_cap,
                                    out_len);
}

[[nodiscard]] inline Error BuildGenerateEcKeyPair(const ObjectId& object_id, EcCurve curve, std::uint8_t* out,
                                                  std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[16]{};
    std::size_t payload_len = 0;
    Error t = tlv::Append(kTag1, object_id.data(), object_id.size(), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    t = tlv::AppendU8(kTag2, static_cast<std::uint8_t>(curve), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsWrite, static_cast<std::uint8_t>(kP1Ec | kP1KeyPair), kP2Default,
                                    payload, payload_len, out, out_cap, out_len);
}

[[nodiscard]] inline Error BuildWriteBinary(const ObjectId& object_id, const std::uint8_t* data,
                                            std::size_t data_len, bool has_offset, std::uint16_t offset,
                                            bool has_file_length, std::uint16_t file_length, std::uint8_t* out,
                                            std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr || (data_len > 0U && data == nullptr)) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[kMaxApduCommandBytes]{};
    std::size_t payload_len = 0;

    Error t = tlv::Append(kTag1, object_id.data(), object_id.size(), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    if (has_offset) {
        t = tlv::AppendU16Be(kTag2, offset, payload, sizeof(payload), &payload_len);
        if (t != Error::Ok) {
            return t;
        }
    }
    if (has_file_length) {
        t = tlv::AppendU16Be(kTag3, file_length, payload, sizeof(payload), &payload_len);
        if (t != Error::Ok) {
            return t;
        }
    }
    t = tlv::Append(0x44U, data, data_len, payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsWrite, kP1Binary, kP2Default, payload, payload_len, out, out_cap,
                                    out_len);
}

[[nodiscard]] inline Error BuildReadObject(const ObjectId& object_id, bool has_offset, std::uint16_t offset,
                                           bool has_length, std::uint16_t length, std::uint8_t* out,
                                           std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[32]{};
    std::size_t payload_len = 0;
    Error t = tlv::Append(kTag1, object_id.data(), object_id.size(), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    if (has_offset) {
        t = tlv::AppendU16Be(kTag2, offset, payload, sizeof(payload), &payload_len);
        if (t != Error::Ok) {
            return t;
        }
    }
    if (has_length) {
        t = tlv::AppendU16Be(kTag3, length, payload, sizeof(payload), &payload_len);
        if (t != Error::Ok) {
            return t;
        }
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsRead, kP1Default, kP2Default, payload, payload_len, out, out_cap,
                                    out_len);
}

[[nodiscard]] inline Error BuildEcdsaSign(const ObjectId& key_id, EcdsaAlgo algo, const std::uint8_t* digest,
                                          std::size_t digest_len, std::uint8_t* out, std::size_t out_cap,
                                          std::size_t* out_len) noexcept {
    if (out_len == nullptr || (digest_len > 0U && digest == nullptr)) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[128]{};
    std::size_t payload_len = 0;
    Error t = tlv::Append(kTag1, key_id.data(), key_id.size(), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    t = tlv::AppendU8(kTag2, static_cast<std::uint8_t>(algo), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    t = tlv::Append(kTag3, digest, digest_len, payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsCrypto, kP1Signature, kP2Sign, payload, payload_len, out, out_cap,
                                    out_len);
}

[[nodiscard]] inline Error BuildEcdsaVerify(const ObjectId& key_id, EcdsaAlgo algo, const std::uint8_t* digest,
                                            std::size_t digest_len, const std::uint8_t* signature,
                                            std::size_t signature_len, std::uint8_t* out, std::size_t out_cap,
                                            std::size_t* out_len) noexcept {
    if (out_len == nullptr || (digest_len > 0U && digest == nullptr) ||
        (signature_len > 0U && signature == nullptr)) {
        return Error::InvalidArgument;
    }
    std::uint8_t payload[256]{};
    std::size_t payload_len = 0;
    Error t = tlv::Append(kTag1, key_id.data(), key_id.size(), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    t = tlv::AppendU8(kTag2, static_cast<std::uint8_t>(algo), payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    t = tlv::Append(kTag3, digest, digest_len, payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    t = tlv::Append(kTag5, signature, signature_len, payload, sizeof(payload), &payload_len);
    if (t != Error::Ok) {
        return t;
    }
    return apdu::BuildCase4Extended(kClaNoSm, kInsCrypto, kP1Signature, kP2Verify, payload, payload_len, out,
                                    out_cap, out_len);
}

[[nodiscard]] inline Error ParseResponseTag1(const std::uint8_t* rapdu, std::size_t rapdu_len,
                                             const std::uint8_t** value_out, std::size_t* value_len_out,
                                             apdu::StatusWords* sw_out) noexcept {
    if (value_out == nullptr || value_len_out == nullptr || sw_out == nullptr) {
        return Error::InvalidArgument;
    }
    const std::uint8_t* payload = nullptr;
    std::size_t payload_len = 0;
    const Error pe = apdu::ParseResponse(rapdu, rapdu_len, &payload, &payload_len, sw_out);
    if (pe != Error::Ok) {
        return pe;
    }
    if (!apdu::IsSuccess(*sw_out)) {
        return Error::Protocol;
    }
    if (!tlv::FindFirst(kTag1, payload, payload_len, value_out, value_len_out)) {
        return Error::Protocol;
    }
    return Error::Ok;
}

[[nodiscard]] inline Error ParseVersionInfo(const std::uint8_t* rapdu, std::size_t rapdu_len,
                                            VersionInfo* out) noexcept {
    if (out == nullptr) {
        return Error::InvalidArgument;
    }
    const std::uint8_t* v = nullptr;
    std::size_t v_len = 0;
    apdu::StatusWords sw{};
    const Error e = ParseResponseTag1(rapdu, rapdu_len, &v, &v_len, &sw);
    if (e != Error::Ok) {
        return e;
    }
    if (v_len < 7U) {
        return Error::Protocol;
    }
    out->applet_major = v[0];
    out->applet_minor = v[1];
    out->applet_patch = v[2];
    out->applet_config = static_cast<std::uint16_t>((static_cast<std::uint16_t>(v[3]) << 8U) | v[4]);
    out->secure_box = static_cast<std::uint16_t>((static_cast<std::uint16_t>(v[5]) << 8U) | v[6]);
    return Error::Ok;
}

[[nodiscard]] inline Error ParseFreeMemory(const std::uint8_t* rapdu, std::size_t rapdu_len,
                                           std::uint16_t* free_bytes) noexcept {
    if (free_bytes == nullptr) {
        return Error::InvalidArgument;
    }
    const std::uint8_t* v = nullptr;
    std::size_t v_len = 0;
    apdu::StatusWords sw{};
    const Error e = ParseResponseTag1(rapdu, rapdu_len, &v, &v_len, &sw);
    if (e != Error::Ok) {
        return e;
    }
    if (v_len != 2U) {
        return Error::Protocol;
    }
    *free_bytes = static_cast<std::uint16_t>((static_cast<std::uint16_t>(v[0]) << 8U) | v[1]);
    return Error::Ok;
}

[[nodiscard]] inline Error ParseDataTag1(const std::uint8_t* rapdu, std::size_t rapdu_len, std::uint8_t* out,
                                         std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    *out_len = 0;
    const std::uint8_t* v = nullptr;
    std::size_t v_len = 0;
    apdu::StatusWords sw{};
    const Error e = ParseResponseTag1(rapdu, rapdu_len, &v, &v_len, &sw);
    if (e != Error::Ok) {
        return e;
    }
    if (v_len > out_cap) {
        return Error::BufferTooSmall;
    }
    if (v_len > 0U && out != nullptr) {
        std::memcpy(out, v, v_len);
    }
    *out_len = v_len;
    return Error::Ok;
}

[[nodiscard]] inline Error ParseVerifyResult(const std::uint8_t* rapdu, std::size_t rapdu_len,
                                             bool* verified) noexcept {
    if (verified == nullptr) {
        return Error::InvalidArgument;
    }
    *verified = false;
    const std::uint8_t* v = nullptr;
    std::size_t v_len = 0;
    apdu::StatusWords sw{};
    const Error e = ParseResponseTag1(rapdu, rapdu_len, &v, &v_len, &sw);
    if (e != Error::Ok) {
        return e;
    }
    if (v_len != 1U) {
        return Error::Protocol;
    }
    *verified = (v[0] == kResultSuccess);
    return Error::Ok;
}

[[nodiscard]] inline Error ParseObjectExistsResult(const std::uint8_t* rapdu, std::size_t rapdu_len,
                                                   bool* exists) noexcept {
    if (exists == nullptr) {
        return Error::InvalidArgument;
    }
    *exists = false;
    const std::uint8_t* v = nullptr;
    std::size_t v_len = 0;
    apdu::StatusWords sw{};
    const Error e = ParseResponseTag1(rapdu, rapdu_len, &v, &v_len, &sw);
    if (e != Error::Ok) {
        return e;
    }
    if (v_len != 1U) {
        return Error::Protocol;
    }
    *exists = (v[0] == kResultSuccess);
    return Error::Ok;
}

}  // namespace se050::cmd
