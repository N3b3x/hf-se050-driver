/**
 * @file se050_tlv.hpp
 * @brief Minimal BER-TLV helpers used by SE050 command payloads and responses.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace se050::tlv {

[[nodiscard]] inline Error AppendTagAndLength(std::uint8_t tag, std::size_t value_len, std::uint8_t* out,
                                              std::size_t out_cap, std::size_t* off) noexcept {
    if (out == nullptr || off == nullptr) {
        return Error::InvalidArgument;
    }
    if (*off >= out_cap) {
        return Error::BufferTooSmall;
    }
    out[(*off)++] = tag;
    if (value_len <= 0x7FU) {
        if (*off >= out_cap) {
            return Error::BufferTooSmall;
        }
        out[(*off)++] = static_cast<std::uint8_t>(value_len);
        return Error::Ok;
    }
    if (value_len <= 0xFFU) {
        if (*off + 1U >= out_cap) {
            return Error::BufferTooSmall;
        }
        out[(*off)++] = 0x81U;
        out[(*off)++] = static_cast<std::uint8_t>(value_len);
        return Error::Ok;
    }
    if (value_len <= 0xFFFFU) {
        if (*off + 2U >= out_cap) {
            return Error::BufferTooSmall;
        }
        out[(*off)++] = 0x82U;
        out[(*off)++] = static_cast<std::uint8_t>((value_len >> 8U) & 0xFFU);
        out[(*off)++] = static_cast<std::uint8_t>(value_len & 0xFFU);
        return Error::Ok;
    }
    return Error::InvalidArgument;
}

[[nodiscard]] inline Error Append(std::uint8_t tag, const std::uint8_t* value, std::size_t value_len,
                                  std::uint8_t* out, std::size_t out_cap, std::size_t* off) noexcept {
    const Error h = AppendTagAndLength(tag, value_len, out, out_cap, off);
    if (h != Error::Ok) {
        return h;
    }
    if (*off + value_len > out_cap) {
        return Error::BufferTooSmall;
    }
    if (value_len > 0U && value != nullptr) {
        std::memcpy(out + *off, value, value_len);
    }
    *off += value_len;
    return Error::Ok;
}

[[nodiscard]] inline Error AppendU8(std::uint8_t tag, std::uint8_t value, std::uint8_t* out, std::size_t out_cap,
                                    std::size_t* off) noexcept {
    return Append(tag, &value, 1U, out, out_cap, off);
}

[[nodiscard]] inline Error AppendU16Be(std::uint8_t tag, std::uint16_t value, std::uint8_t* out,
                                       std::size_t out_cap, std::size_t* off) noexcept {
    const std::uint8_t bytes[2] = {static_cast<std::uint8_t>((value >> 8U) & 0xFFU),
                                   static_cast<std::uint8_t>(value & 0xFFU)};
    return Append(tag, bytes, sizeof(bytes), out, out_cap, off);
}

[[nodiscard]] inline bool DecodeLength(const std::uint8_t* data, std::size_t data_len, std::size_t* off,
                                       std::size_t* value_len) noexcept {
    if (data == nullptr || off == nullptr || value_len == nullptr || *off >= data_len) {
        return false;
    }
    const std::uint8_t l0 = data[(*off)++];
    if ((l0 & 0x80U) == 0U) {
        *value_len = l0;
        return true;
    }
    const std::size_t num_bytes = static_cast<std::size_t>(l0 & 0x7FU);
    if (num_bytes == 0U || num_bytes > 2U || *off + num_bytes > data_len) {
        return false;
    }
    std::size_t len = 0;
    for (std::size_t i = 0; i < num_bytes; ++i) {
        len = (len << 8U) | data[(*off)++];
    }
    *value_len = len;
    return true;
}

[[nodiscard]] inline bool FindFirst(std::uint8_t wanted_tag, const std::uint8_t* tlv_data, std::size_t tlv_len,
                                    const std::uint8_t** value_out, std::size_t* value_len_out) noexcept {
    if (tlv_data == nullptr || value_out == nullptr || value_len_out == nullptr) {
        return false;
    }
    std::size_t off = 0;
    while (off < tlv_len) {
        const std::uint8_t tag = tlv_data[off++];
        std::size_t value_len = 0;
        if (!DecodeLength(tlv_data, tlv_len, &off, &value_len)) {
            return false;
        }
        if (off + value_len > tlv_len) {
            return false;
        }
        if (tag == wanted_tag) {
            *value_out = tlv_data + off;
            *value_len_out = value_len;
            return true;
        }
        off += value_len;
    }
    return false;
}

}  // namespace se050::tlv
