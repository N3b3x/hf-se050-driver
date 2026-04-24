/**
 * @file se050_applet.hpp
 * @brief SE050 **applet selection** helpers (ISO 7816-4 `SELECT` by DF name / AID).
 *
 * @details The default AID bytes mirror the **NXP Plug & Trust / mbed** SE05x IoT applet
 *          convention. Always confirm the correct AID for your **OEM OS build** using
 *          NXP tooling (`se05x_GetInfo`) or your secure manufacturing database.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_apdu.hpp"
#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>

namespace se050::applet {

/**
 * @brief Default SE05x IoT / EdgeLock AID used by many NXP reference projects (13 bytes).
 *
 * Replace at integration time if your part uses a different RID/PIX layout.
 */
inline constexpr std::uint8_t kDefaultIoTAppletAid[] = {0xA0U, 0x00U, 0x00U, 0x03U, 0x96U, 0x04U, 0x03U,
                                                        0x03U, 0x03U, 0x00U, 0x00U, 0x00U, 0x00U};

/** @brief `sizeof(kDefaultIoTAppletAid)` as a `std::uint8_t` (fits short `Lc`). */
inline constexpr std::uint8_t kDefaultIoTAppletAidLen =
    static_cast<std::uint8_t>(sizeof(kDefaultIoTAppletAid) / sizeof(kDefaultIoTAppletAid[0]));

/**
 * @brief Build `SELECT` (CLA=`0x00`, INS=`0xA4`, P1=`0x04`, P2=`0x00`) for @ref kDefaultIoTAppletAid.
 * @param out Serialized C-APDU.
 * @param cap Capacity of @p out (≥ 5 + @ref kDefaultIoTAppletAidLen + 1 when `Le` present).
 * @param out_len Written length.
 */
[[nodiscard]] inline Error BuildSelectDefaultIot(std::uint8_t* out, std::size_t cap,
                                                 std::size_t* out_len) noexcept {
    return apdu::BuildCaseShort(0x00U, 0xA4U, 0x04U, 0x00U, kDefaultIoTAppletAid, kDefaultIoTAppletAidLen, true, 0x00U,
                                out, cap, out_len);
}

/**
 * @brief Build `SELECT` for an arbitrary AID / DF name.
 * @param aid Application identifier bytes.
 * @param aid_len Length of @p aid (must fit in short `Lc`, ≤ 255).
 */
[[nodiscard]] inline Error BuildSelectApplication(const std::uint8_t* aid, std::uint8_t aid_len,
                                                  std::uint8_t* out, std::size_t cap,
                                                  std::size_t* out_len) noexcept {
    return apdu::BuildCaseShort(0x00U, 0xA4U, 0x04U, 0x00U, aid, aid_len, true, 0x00U, out, cap, out_len);
}

}  // namespace se050::applet
