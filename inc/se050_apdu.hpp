/**
 * @file se050_apdu.hpp
 * @brief ISO 7816-4 **C-APDU** packing and **R-APDU** parsing helpers (short + extended length).
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace se050::apdu {

/** @brief Parsed status words from a response APDU. */
struct StatusWords {
    std::uint8_t sw1{0};
    std::uint8_t sw2{0};
};

/**
 * @brief Build a **CASE 4** command APDU with **extended** length encoding.
 *
 * Layout: `CLA INS P1 P2 00 Lc_hi Lc_lo [data...] Le_hi Le_lo` (Bertin-style extended `Lc`/`Le`).
 *
 * @param cla INS class byte.
 * @param ins Instruction byte.
 * @param p1 First parameter.
 * @param p2 Second parameter.
 * @param data Command data field (may be @c nullptr if @p data_len == 0).
 * @param data_len Length of @p data (0 … @ref kMaxApduCommandBytes - 9).
 * @param out Serialized APDU.
 * @param out_cap Capacity of @p out.
 * @param out_len Written length on success.
 */
[[nodiscard]] inline Error BuildCase4Extended(std::uint8_t cla, std::uint8_t ins, std::uint8_t p1,
                                              std::uint8_t p2, const std::uint8_t* data,
                                              std::size_t data_len, std::uint8_t* out,
                                              std::size_t out_cap, std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    *out_len = 0;
    constexpr std::size_t kHeader = 7U; /* CLA.. + 00 LcHi LcLo */
    constexpr std::size_t kLeExt = 3U;    /* 00 LeHi LeLo */
    if (data_len > (kMaxApduCommandBytes - kHeader - kLeExt)) {
        return Error::InvalidArgument;
    }
    const std::size_t need = kHeader + data_len + kLeExt;
    if (need > out_cap) {
        return Error::BufferTooSmall;
    }
    std::size_t i = 0;
    out[i++] = cla;
    out[i++] = ins;
    out[i++] = p1;
    out[i++] = p2;
    out[i++] = 0x00;
    out[i++] = static_cast<std::uint8_t>((data_len >> 8) & 0xFFU);
    out[i++] = static_cast<std::uint8_t>(data_len & 0xFFU);
    if (data_len > 0U && data != nullptr) {
        std::memcpy(out + i, data, data_len);
        i += data_len;
    }
    out[i++] = 0x00;
    out[i++] = 0x00;
    out[i++] = 0x00; /* Request up to 65536 bytes Ne (00 00 00) */
    *out_len = i;
    return Error::Ok;
}

/**
 * @brief Build a **CASE 3/4 short** command when `data_len ≤ 255` and a 1-byte `Le` is enough.
 *
 * Layout: `CLA INS P1 P2 Lc [data...] [Le]`. If @p le_present is @c false, the `Le` byte is omitted
 * (CASE 3). If @p le_present is @c true, @p le is appended (CASE 4 short).
 */
[[nodiscard]] inline Error BuildCaseShort(std::uint8_t cla, std::uint8_t ins, std::uint8_t p1,
                                          std::uint8_t p2, const std::uint8_t* data,
                                          std::uint8_t data_len, bool le_present, std::uint8_t le,
                                          std::uint8_t* out, std::size_t out_cap,
                                          std::size_t* out_len) noexcept {
    if (out_len == nullptr) {
        return Error::InvalidArgument;
    }
    *out_len = 0;
    const std::size_t need = 5U + data_len + (le_present ? 1U : 0U);
    if (need > out_cap) {
        return Error::BufferTooSmall;
    }
    std::size_t i = 0;
    out[i++] = cla;
    out[i++] = ins;
    out[i++] = p1;
    out[i++] = p2;
    out[i++] = data_len;
    if (data_len > 0U && data != nullptr) {
        std::memcpy(out + i, data, data_len);
        i += data_len;
    }
    if (le_present) {
        out[i++] = le;
    }
    *out_len = i;
    return Error::Ok;
}

/**
 * @brief Parse a simple R-APDU: optional response data followed by `SW1 SW2`.
 * @param rsp Full response INF from the T=1 layer (typically `T1Session::ExchangeInformation`).
 * @param rsp_len Length of @p rsp (must be ≥ 2).
 * @param data_out Optional pointer into @p rsp where payload starts (may equal @p rsp).
 * @param data_len_out Length of payload excluding status bytes.
 * @param sw_out Status words.
 */
[[nodiscard]] inline Error ParseResponse(const std::uint8_t* rsp, std::size_t rsp_len,
                                         const std::uint8_t** data_out, std::size_t* data_len_out,
                                         StatusWords* sw_out) noexcept {
    if (data_out == nullptr || data_len_out == nullptr || sw_out == nullptr) {
        return Error::InvalidArgument;
    }
    if (rsp_len < 2U) {
        return Error::Protocol;
    }
    *data_out = rsp;
    *data_len_out = rsp_len - 2U;
    sw_out->sw1 = rsp[rsp_len - 2U];
    sw_out->sw2 = rsp[rsp_len - 1U];
    return Error::Ok;
}

/** @brief Return @c true when `SW1 == 0x90` and `SW2 == 0x00`. */
[[nodiscard]] inline bool IsSuccess(const StatusWords& sw) noexcept {
    return sw.sw1 == 0x90U && sw.sw2 == 0x00U;
}

/** @brief `SW1 == 0x61` — more data available via GET RESPONSE (common GlobalPlatform pattern). */
[[nodiscard]] inline bool IsMoreData(const StatusWords& sw) noexcept { return sw.sw1 == 0x61U; }

}  // namespace se050::apdu
