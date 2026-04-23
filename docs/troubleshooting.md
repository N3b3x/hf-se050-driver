---
layout: default
title: "Troubleshooting"
nav_order: 8
parent: "📚 Documentation"
permalink: /docs/troubleshooting/
---

# Troubleshooting

- **`APP_TYPE not defined`** — always configure through `examples/esp32/scripts/build_app.sh` (or pass `-DAPP_TYPE=...` to CMake as in CI).  
- **Missing `scripts/`** — run `git submodule update --init --recursive` at repo root.  
- **Version header not found** — generated under the build tree; the minimal example does not include it yet; full integration will document include paths.  
