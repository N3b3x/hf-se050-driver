/**
 * @file se050_atr.hpp
 * @brief Parser for SE050 T=1oI2C ATR/profile INF payload.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>

namespace se050::atr {

struct Profile {
    std::uint8_t protocol_version{0};
    std::uint8_t vendor_id[5]{};
    std::uint16_t bwt{0};
    std::uint16_t ifsc{0};
    std::uint8_t plid{0};
    std::uint16_t max_i2c_khz{0};
    std::uint8_t config{0};
    std::uint8_t min_poll_ms{0};
    std::uint16_t segt_us{0};
    std::uint16_t wakeup_us{0};
    const std::uint8_t* historical{nullptr};
    std::size_t historical_len{0};
};

[[nodiscard]] inline Error Parse(const std::uint8_t* inf, std::size_t inf_len, Profile* out) noexcept {
    if (inf == nullptr || out == nullptr) {
        return Error::InvalidArgument;
    }
    if (inf_len < 7U) {
        return Error::Protocol;
    }
    out->protocol_version = inf[0];
    for (std::size_t i = 0; i < 5U; ++i) {
        out->vendor_id[i] = inf[1U + i];
    }
    const std::size_t dllp_len = inf[6];
    if (7U + dllp_len > inf_len || dllp_len < 4U) {
        return Error::Protocol;
    }
    const std::uint8_t* dllp = inf + 7U;
    out->bwt = static_cast<std::uint16_t>((static_cast<std::uint16_t>(dllp[0]) << 8U) | dllp[1]);
    out->ifsc = static_cast<std::uint16_t>((static_cast<std::uint16_t>(dllp[2]) << 8U) | dllp[3]);

    std::size_t off = 7U + dllp_len;
    if (off + 2U > inf_len) {
        return Error::Protocol;
    }
    out->plid = inf[off++];
    const std::size_t plp_len = inf[off++];
    if (off + plp_len > inf_len || plp_len < 11U) {
        return Error::Protocol;
    }
    const std::uint8_t* plp = inf + off;
    out->max_i2c_khz = static_cast<std::uint16_t>((static_cast<std::uint16_t>(plp[0]) << 8U) | plp[1]);
    out->config = plp[2];
    out->min_poll_ms = plp[3];
    out->segt_us = static_cast<std::uint16_t>((static_cast<std::uint16_t>(plp[7]) << 8U) | plp[8]);
    out->wakeup_us = static_cast<std::uint16_t>((static_cast<std::uint16_t>(plp[9]) << 8U) | plp[10]);

    off += plp_len;
    if (off >= inf_len) {
        return Error::Protocol;
    }
    const std::size_t hb_len = inf[off++];
    if (off + hb_len > inf_len) {
        return Error::Protocol;
    }
    out->historical = inf + off;
    out->historical_len = hb_len;
    return Error::Ok;
}

}  // namespace se050::atr
