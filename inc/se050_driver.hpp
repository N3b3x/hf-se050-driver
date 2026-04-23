/**
 * @file se050_driver.hpp
 * @brief Umbrella include for the HF-SE050 driver (transport + device).
 *
 * @copyright Copyright (c) 2026 HardFOC. All rights reserved.
 */
#pragma once

#include "se050_device.hpp"
#include "se050_i2c_transport_interface.hpp"
#include "se050_session.hpp"
#include "se050_types.hpp"

namespace se050 {

/** @deprecated Use `Device<TransportT>` — kept for a short transition. */
template <typename TransportT>
using Driver = Device<TransportT>;

}  // namespace se050
