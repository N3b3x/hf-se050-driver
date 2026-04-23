---
layout: default
title: "Quick start"
nav_order: 4
parent: "📚 Documentation"
permalink: /docs/quickstart/
---

# Quick start

1. Initialize `examples/esp32/scripts` (`git submodule update --init --recursive`).  
2. From `examples/esp32/`, run `./scripts/build_app.sh se050_minimal_example Debug release/v5.5`.  
3. Flash with `./scripts/flash_app.sh flash se050_minimal_example Debug` (set `ESPPORT` as needed).  

The minimal example only logs a scaffold message until the SE050 stack is implemented.
