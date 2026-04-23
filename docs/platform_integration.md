---
layout: default
title: "Platform integration"
description: "CRTP I2C transport for SE050"
nav_order: 4
parent: "📚 Documentation"
permalink: /docs/platform_integration/
---

# Platform integration (CRTP transport)

The driver is built around **`se050::I2cTransceiveInterface<Derived>`** — compile-time polymorphism with zero virtual calls, matching other `hf-*-driver` repos.

## Required methods (`Derived`)

| Method | Purpose |
|--------|---------|
| `bool EnsureInitialized() noexcept` | One-time bus + device setup. |
| `Error Transceive(const uint8_t* tx, size_t tx_len, uint8_t* rx, size_t rx_cap, size_t* rx_len_out, uint32_t timeout_ms) noexcept` | Atomic write/read at the SE050 7-bit address. |
| `Error HardwareReset() noexcept` | Pulse SE_RESET when wired; return `Ok` if not used. |

## Optional

| Method | Purpose |
|--------|---------|
| `void delay_ms_impl(uint32_t ms) noexcept` | Inter-frame delay; omit if not needed. |

## Reference implementation

See **`examples/esp32/main/include/hf_se050_esp_i2c.hpp`** — ESP-IDF `i2c_master_*` bridge for `se050::Device<HfSe050EspIdfI2c>`.

## Handler layer (`hf-core`)

A future **`Se050Handler`** will mirror **`Fdo2Handler`**: wrap **`BaseI2c`** (and optional **`BaseGpio`**) in a small adapter class that inherits **`se050::I2cTransceiveInterface<>`**, add **`RtosMutex`**, and own **`se050::Device<Adapter>`**.
