/**
 * @file se050_session.hpp
 * @brief Low-level session: owns no buffers; forwards transceive to transport.
 *
 * T=1 state machine and APDU assembly will live alongside this type in later
 * phases; for now `TransceiveRaw` is a thin, testable wrapper.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_i2c_transport_interface.hpp"
#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>

namespace se050 {

template <typename TransportT>
class Session {
public:
    explicit Session(TransportT& transport) noexcept : transport_(transport) {}

    [[nodiscard]] bool EnsureReady() noexcept { return transport_.EnsureInitialized(); }

    [[nodiscard]] Error TransceiveRaw(const std::uint8_t* tx, std::size_t tx_len,
                                      std::uint8_t* rx, std::size_t rx_cap,
                                      std::size_t* rx_len_out,
                                      std::uint32_t timeout_ms) noexcept {
        if (rx_len_out == nullptr) {
            return Error::InvalidArgument;
        }
        if (!transport_.EnsureInitialized()) {
            return Error::NotInitialized;
        }
        return transport_.Transceive(tx, tx_len, rx, rx_cap, rx_len_out, timeout_ms);
    }

    [[nodiscard]] Error PulseReset() noexcept { return transport_.HardwareReset(); }

    TransportT& Transport() noexcept { return transport_; }
    const TransportT& Transport() const noexcept { return transport_; }

private:
    TransportT& transport_;
};

}  // namespace se050
