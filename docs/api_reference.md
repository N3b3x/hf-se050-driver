---
layout: default
title: "📖 API reference"
description: "SE050 driver API (Phase 1)"
nav_order: 9
parent: "📚 Documentation"
permalink: /docs/api_reference/
---

# API reference (Phase 1)

| Header | Types |
|--------|--------|
| [`se050_types.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_types.hpp) | `se050::Error`, buffer limits, default I2C address |
| [`se050_i2c_transport_interface.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_i2c_transport_interface.hpp) | `se050::I2cTransceiveInterface<Derived>` CRTP base |
| [`se050_session.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_session.hpp) | `se050::Session<TransportT>` — forwards `TransceiveRaw` |
| [`se050_t1_session.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_t1_session.hpp) | `se050::T1Session<TransportT>` — T=1 block exchange (CRC/chaining/WTX/resync) |
| [`se050_apdu.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_apdu.hpp) | C-APDU builders and R-APDU status parsing |
| [`se050_tlv.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_tlv.hpp) | BER-TLV encode/decode helpers |
| [`se050_commands.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_commands.hpp) | Typed command builders/parsers (core mgmt + object lifecycle subset) |
| [`se050_atr.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_atr.hpp) | ATR/profile INF parser |
| [`se050_device.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_device.hpp) | `se050::Device<TransportT>` — application entry |
| [`se050_driver.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/inc/se050_driver.hpp) | Umbrella include; `Driver` alias → `Device` |

ESP32 transport: [`examples/esp32/main/include/hf_se050_esp_i2c.hpp`](https://github.com/N3b3x/hf-se050-driver/blob/main/examples/esp32/main/include/hf_se050_esp_i2c.hpp).
