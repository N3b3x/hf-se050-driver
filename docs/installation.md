---
layout: default
title: "Installation"
nav_order: 3
parent: "📚 Documentation"
permalink: /docs/installation/
---

# Installation

- **C++17** or newer for consumers.  
- **CMake ≥ 3.16** for the interface library target `hf::se050`.  
- **ESP-IDF ≥ 5.0** for `examples/esp32` (see example `README.md`).  

Clone with submodules:

```bash
git clone --recursive https://github.com/N3b3x/hf-se050-driver.git
```

Non-redistributable reference files belong in `_local_reference/` (gitignored); see that directory’s `README.md`.

## Doxygen (API HTML, local)

CI builds the same tree via **`_config/Doxyfile`** with working directory **`.`** (repository root).

```bash
./scripts/build_doxygen.sh
```

Requires **`doxygen`** on your `PATH` (optional: **`graphviz`** for nicer call graphs). With the stock `_config/Doxyfile`, HTML is emitted to **`docs/html/`**. The **`Se050Handler`** HAL façade lives in **`hf-core`** (`handlers/se050/`, Jekyll **`docs/handlers/se050_handler.md`**); this Doxygen build covers **`inc/*.hpp`** and the ESP32 example sources listed in the Doxyfile **`INPUT`** tag. Use both: Doxygen for `se050::Device` API, hf-core docs for CMake flags (`HF_CORE_ENABLE_SE050`) and ESP32 handler tests.
