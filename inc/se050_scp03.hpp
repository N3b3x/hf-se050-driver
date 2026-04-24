/**
 * @file se050_scp03.hpp
 * @brief **SCP03** secure channel scaffolding (crypto hooks not included in this repository).
 *
 * @details GlobalPlatform SCP03 (`ENC` / `MAC` / `DEK` session keys, `C-MAC` / `R-MAC`,
 *          counter-based AES) is intentionally **not** implemented here: it requires a vetted
 *          AES-CMAC / AES-CTR implementation, secure key provisioning, and platform RNG access.
 *
 *          Integrators should implement `Scp03HostCrypto` against their PSA / mbedTLS /
 *          wolfSSL stack and then drive the handshake APDUs through @ref T1Session::ExchangeInformation.
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_t1_session.hpp"
#include "se050_types.hpp"

#include <cstddef>
#include <cstdint>

namespace se050::scp03 {

/** @brief Placeholder for static keys / key diversification inputs (integration-specific). */
struct StaticKeys {
    const std::uint8_t* host_static_key_enc{nullptr};
    std::size_t host_static_key_enc_len{0};
    const std::uint8_t* host_static_key_cmac{nullptr};
    std::size_t host_static_key_cmac_len{0};
};

/**
 * @brief SCP03 session object bound to an existing T=1 session.
 * @tparam TransportT CRTP I²C transport type used by @ref T1Session.
 *
 * @par Current behaviour
 * All entry points return @ref Error::NotSupported until a crypto backend is wired in.
 */
template <typename TransportT>
class Session {
public:
    Session() noexcept = default;

    /**
     * @brief Perform SCP03 `INITIALIZE UPDATE` / `EXTERNAL AUTHENTICATE` (not implemented).
     * @param t1 T=1 session used for future APDU exchange once crypto is integrated.
     */
    [[nodiscard]] Error OpenSecureChannel(T1Session<TransportT>& /*t1*/, const StaticKeys& /*keys*/,
                                          std::uint32_t /*timeout_ms*/) noexcept {
        return Error::NotSupported;
    }

    /** @brief Close logical SCP03 state (not implemented). */
    [[nodiscard]] Error Close() noexcept { return Error::NotSupported; }

    [[nodiscard]] bool IsOpen() const noexcept { return false; }
};

}  // namespace se050::scp03
