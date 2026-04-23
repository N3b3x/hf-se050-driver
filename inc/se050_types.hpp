/**
 * @file se050_types.hpp
 * @brief Shared types, limits, and error codes for the HF-SE050 driver.
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace se050 {

/** Driver / transport operation result (no exceptions on embedded paths). */
enum class Error : std::uint8_t {
    Ok = 0,
    NotInitialized,
    Transport,
    Timeout,
    InvalidArgument,
    BufferTooSmall,
    /** Reserved for T=1 / APDU layers (future). */
    Protocol,
};

/** Default 7-bit I2C address for SE050 class parts (see NXP / board docs). */
inline constexpr std::uint8_t kDefaultI2cAddress7 = 0x48;

/** Host command buffer high bound (SE050 extended APDU payload; see NXP SE05x docs). */
inline constexpr std::size_t kMaxApduCommandBytes = 892;
/** Host response buffer high bound. */
inline constexpr std::size_t kMaxApduResponseBytes = 892;

}  // namespace se050
