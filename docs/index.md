---
layout: default
title: "📚 Documentation"
description: "Documentation for the HF-SE050 driver"
nav_order: 2
parent: "HardFOC SE050 Driver"
permalink: /docs/
has_children: true
---

# HF-SE050 documentation

This site tracks the [`docs/`](https://github.com/N3b3x/hf-se050-driver/tree/main/docs) folder for the **NXP SE050 / SE050A** secure element driver. It focuses on practical bring-up, object management, onboarding flows, and production security patterns.

## Structure

1. **[Installation](installation.md)** — Toolchain and repo layout  
2. **[Quick start](quickstart.md)** — Planned bring-up flow  
3. **[Hardware setup](hardware_setup.md)** — I²C and board notes  
4. **[CMake integration](cmake_integration.md)** — `hf::se050` and ESP-IDF component  
4b. **[Platform integration](platform_integration.md)** — CRTP I2C transport  
5. **[API reference](api_reference.md)** — Transport, session, device templates  
6. **[Examples](examples.md)** — All ESP32 example flows + internal diagrams  
7. **[Troubleshooting](troubleshooting.md)** — Common issues while developing  
8. **[Security flows (IoT / OTA / Comms)](security_iot_ota_comms.md)** — End-to-end trust and channel models with SE050  
9. **[Datasheet & links](datasheet/README.md)** — Official NXP pointers; local PDFs stay out of git  
