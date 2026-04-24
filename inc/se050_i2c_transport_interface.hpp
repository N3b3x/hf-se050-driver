/**
 * @file se050_i2c_transport_interface.hpp
 * @brief CRTP base for an I²C-backed SE050 link (split @p Write / @p Read + optional raw transceive).
 *
 * @details T=1 over I²C (UM11225 / UM1225 family) requires the host to **write** a full outbound
 *          block, wait an inter-frame guard time, then **read** the answer in one or more chunks.
 *          A single `transmit_receive` covering the whole card response is often **not** portable
 *          because the target may NACK until the block is complete. Implementations therefore
 *          expose explicit @ref Write and @ref Read entry points; @ref Transceive remains for
 *          bring-up and legacy callers.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>

namespace se050 {

/**
 * @brief Curiously recurring transport interface for SE050 I²C masters.
 * @tparam Derived Concrete transport (`class D : public I2cTransceiveInterface<D>`).
 *
 * @par Derived requirements
 * The derived type must implement (all `noexcept`):
 * - `bool EnsureInitialized() noexcept`
 * - `Error I2cWrite(const std::uint8_t* tx, std::size_t tx_len, std::uint32_t timeout_ms) noexcept`
 * - `Error I2cRead(std::uint8_t* rx, std::size_t rx_len, std::uint32_t timeout_ms) noexcept`
 * - `Error Transceive(const std::uint8_t* tx, std::size_t tx_len, std::uint8_t* rx, std::size_t rx_cap,
 *                     std::size_t* rx_len_out, std::uint32_t timeout_ms) noexcept`
 * - `Error HardwareReset() noexcept`
 * - `void delay_ms_impl(std::uint32_t ms) noexcept`
 */
template <typename Derived>
class I2cTransceiveInterface {
public:
    I2cTransceiveInterface() noexcept = default;
    I2cTransceiveInterface(const I2cTransceiveInterface&) = delete;
    I2cTransceiveInterface& operator=(const I2cTransceiveInterface&) = delete;

    /** @brief One-shot write of @p tx_len bytes to the SE050 I²C target address. */
    [[nodiscard]] Error Write(const std::uint8_t* tx, std::size_t tx_len,
                              std::uint32_t timeout_ms) noexcept {
        return static_cast<Derived*>(this)->I2cWrite(tx, tx_len, timeout_ms);
    }

    /** @brief Read exactly @p rx_len bytes from the SE050 (blocking until complete or error). */
    [[nodiscard]] Error Read(std::uint8_t* rx, std::size_t rx_len, std::uint32_t timeout_ms) noexcept {
        return static_cast<Derived*>(this)->I2cRead(rx, rx_len, timeout_ms);
    }

    [[nodiscard]] bool EnsureInitialized() noexcept {
        return static_cast<Derived*>(this)->EnsureInitialized();
    }

    [[nodiscard]] Error Transceive(const std::uint8_t* tx, std::size_t tx_len, std::uint8_t* rx,
                                   std::size_t rx_cap, std::size_t* rx_len_out,
                                   std::uint32_t timeout_ms) noexcept {
        return static_cast<Derived*>(this)->Transceive(tx, tx_len, rx, rx_cap, rx_len_out, timeout_ms);
    }

    [[nodiscard]] Error HardwareReset() noexcept { return static_cast<Derived*>(this)->HardwareReset(); }

    void delay_ms(std::uint32_t ms) noexcept { static_cast<Derived*>(this)->delay_ms_impl(ms); }

protected:
    ~I2cTransceiveInterface() noexcept = default;
    I2cTransceiveInterface(I2cTransceiveInterface&&) noexcept = default;
    I2cTransceiveInterface& operator=(I2cTransceiveInterface&&) noexcept = default;
};

}  // namespace se050
