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
