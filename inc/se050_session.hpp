/**
 * @file se050_session.hpp
 * @brief Low-level session: owns no buffers; forwards transceive to transport.
 *
 * `TransceiveRaw` is a thin wrapper over the CRTP transport. **Do not** use zero-length
 * I²C writes on SE050 (NXP errata: acknowledged address-only frames can lock the bus).
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_i2c_transport_interface.hpp"
#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>

namespace se050 {

/**
 * @brief Transport-facing session (no owned buffers).
 * @tparam TransportT Concrete type implementing @ref I2cTransceiveInterface.
 */
template <typename TransportT>
class Session {
public:
    explicit Session(TransportT& transport) noexcept : transport_(transport) {}

    /** @brief Propagates to the transport’s `EnsureInitialized()`. */
    [[nodiscard]] bool EnsureReady() noexcept { return transport_.EnsureInitialized(); }

    /**
     * @brief Raw transceive used for early bring-up (not a substitute for `se050::T1Session`).
     * @param tx_len Must be **non-zero** (SE050 I²C errata).
     */
    [[nodiscard]] Error TransceiveRaw(const std::uint8_t* tx, std::size_t tx_len,
                                      std::uint8_t* rx, std::size_t rx_cap,
                                      std::size_t* rx_len_out,
                                      std::uint32_t timeout_ms) noexcept {
        if (rx_len_out == nullptr) {
            return Error::InvalidArgument;
        }
        if (tx_len == 0U) {
            return Error::InvalidArgument;
        }
        if (!transport_.EnsureInitialized()) {
            return Error::NotInitialized;
        }
        return transport_.Transceive(tx, tx_len, rx, rx_cap, rx_len_out, timeout_ms);
    }

    /** @brief Optional GPIO / power-style reset routed through the transport. */
    [[nodiscard]] Error PulseReset() noexcept { return transport_.HardwareReset(); }

    TransportT& Transport() noexcept { return transport_; }
    const TransportT& Transport() const noexcept { return transport_; }

private:
    TransportT& transport_;
};

}  // namespace se050
