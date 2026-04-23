/**
 * @file se050_device.hpp
 * @brief Top-level device object templated on CRTP transport (Phase 1–2 boundary).
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_session.hpp"
#include "se050_types.hpp"

namespace se050 {

template <typename TransportT>
class Device {
public:
    explicit Device(TransportT& transport) noexcept : session_(transport) {}

    [[nodiscard]] bool EnsureInitialized() noexcept { return session_.EnsureReady(); }

    /** Raw I2C exchange (T=1 / APDU bytes). */
    [[nodiscard]] Error TransceiveRaw(const std::uint8_t* tx, std::size_t tx_len,
                                      std::uint8_t* rx, std::size_t rx_cap,
                                      std::size_t* rx_len_out,
                                      std::uint32_t timeout_ms) noexcept {
        return session_.TransceiveRaw(tx, tx_len, rx, rx_cap, rx_len_out, timeout_ms);
    }

    [[nodiscard]] Error HardwareReset() noexcept { return session_.PulseReset(); }

    Session<TransportT>& SessionRef() noexcept { return session_; }
    const Session<TransportT>& SessionRef() const noexcept { return session_; }

private:
    Session<TransportT> session_;
};

}  // namespace se050
