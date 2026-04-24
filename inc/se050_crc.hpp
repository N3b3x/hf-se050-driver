/**
 * @file se050_crc.hpp
 * @brief ISO/IEC 7816-3 T=1 **EDC** (16-bit CRC) for NXP SE050 T1oI2C blocks.
 *
 * @details The polynomial and bit ordering match the reference implementation used
 *          with NXP EdgeLock ESE stacks (CRC-16 “ANSI” / IBM-SDLC style, reflected
 *          input, reflected output with final XOR 0xFFFF). On the wire the EDC is
 *          **big-endian**: `frame[len-2] = (crc >> 8)`, `frame[len-1] = (crc & 0xFF)`.
 *
 * @note This is a clean-room implementation intended for interoperability with SE050
 *       framing; verify against a logic analyser or golden captures on first silicon.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace se050::crc {

/**
 * @brief Compute T=1 EDC over bytes `[offset, offset+length)` of @p buffer.
 * @param buffer   Full frame buffer (NAD..INF).
 * @param offset   First byte included in CRC (normally 0 for whole frame sans EDC).
 * @param length   Number of bytes to feed into CRC **excluding** the 2-byte EDC field.
 * @return 16-bit CRC value; @ref AppendEdc maps it to the wire as MSB then LSB.
 */
[[nodiscard]] inline std::uint16_t Crc16Edc7816(const std::uint8_t* buffer, std::size_t offset,
                                                std::size_t length) noexcept {
    std::uint16_t crc = 0xFFFFU;
    for (std::size_t i = offset; i < offset + length; ++i) {
        crc ^= static_cast<std::uint16_t>(buffer[i]);
        for (int bit = 8; bit > 0; --bit) {
            if ((crc & 0x0001U) != 0U) {
                crc = static_cast<std::uint16_t>((crc >> 1) ^ 0x8408U);
            } else {
                crc = static_cast<std::uint16_t>(crc >> 1);
            }
        }
    }
    crc = static_cast<std::uint16_t>(crc ^ 0xFFFFU);
    return crc;
}

/** @brief Append EDC immediately after `frame[0 .. len_without_edc-1]`. */
inline void AppendEdc(std::uint8_t* frame, std::size_t len_without_edc) noexcept {
    const std::uint16_t c = Crc16Edc7816(frame, 0, len_without_edc);
    frame[len_without_edc] = static_cast<std::uint8_t>((c >> 8) & 0xFFU);
    frame[len_without_edc + 1U] = static_cast<std::uint8_t>(c & 0xFFU);
}

/** @brief Verify EDC on a full received frame (includes trailing 2-byte CRC). */
[[nodiscard]] inline bool VerifyFrameCrc(const std::uint8_t* frame, std::size_t total_len) noexcept {
    if (total_len < 5U) {
        return false;
    }
    const std::uint16_t recv =
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(frame[total_len - 2U]) << 8 |
                                    frame[total_len - 1U]);
    const std::uint16_t calc = Crc16Edc7816(frame, 0, total_len - 2U);
    return recv == calc;
}

}  // namespace se050::crc
