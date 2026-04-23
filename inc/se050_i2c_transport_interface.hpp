/**
 * @file se050_i2c_transport_interface.hpp
 * @brief CRTP transport for SE050 on I2C (T=1 / APDU bytes move as opaque blocks).
 *
 * Unlike register-oriented I2C drivers, the secure element expects framed
 * command/response exchanges at a fixed slave address. Platform code implements
 * this interface (e.g. ESP-IDF `i2c_master_transmit_receive`).
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace se050 {

/**
 * @brief CRTP base for low-level SE050 I2C exchange.
 * @tparam Derived Concrete type (e.g. `HfSe050EspIdfI2c`).
 */
template <typename Derived>
class I2cTransceiveInterface {
public:
    [[nodiscard]] bool EnsureInitialized() noexcept {
        return static_cast<Derived*>(this)->EnsureInitialized();
    }

    /**
     * @brief Atomic write-then-read at the SE050 I2C address (typical for T=1).
     * @param tx          Bytes to transmit (may be nullptr if @p tx_len == 0).
     * @param tx_len      Number of bytes to transmit.
     * @param rx          Receive buffer.
     * @param rx_cap      Capacity of @p rx in bytes.
     * @param rx_len_out  Filled with bytes actually read on success.
     * @param timeout_ms  Bus transaction deadline.
     */
    [[nodiscard]] Error Transceive(const std::uint8_t* tx, std::size_t tx_len, std::uint8_t* rx,
                                   std::size_t rx_cap, std::size_t* rx_len_out,
                                   std::uint32_t timeout_ms) noexcept {
        return static_cast<Derived*>(this)->Transceive(tx, tx_len, rx, rx_cap, rx_len_out,
                                                      timeout_ms);
    }

    /** Optional inter-frame delay (implemented via `delay_ms_impl` on Derived). */
    void delay_ms(std::uint32_t ms) noexcept {
        if constexpr (HasDelayMs<Derived>::value) {
            static_cast<Derived*>(this)->delay_ms_impl(ms);
        } else {
            (void)ms;
        }
    }

    /**
     * @brief Hardware reset of SE050 (SE_RESET pin) when wired; otherwise no-op `Ok`.
     */
    [[nodiscard]] Error HardwareReset() noexcept {
        return static_cast<Derived*>(this)->HardwareReset();
    }

private:
    template <typename, typename = void>
    struct HasDelayMs : std::false_type {};
    template <typename T>
    struct HasDelayMs<T, std::void_t<decltype(std::declval<T>().delay_ms_impl(0U))>>
        : std::true_type {};
};

}  // namespace se050
