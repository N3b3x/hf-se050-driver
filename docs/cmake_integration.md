---
layout: default
title: "CMake integration"
nav_order: 6
parent: "📚 Documentation"
permalink: /docs/cmake_integration/
---

# CMake integration

Host / generic CMake:

```cmake
add_subdirectory(hf-se050-driver)  # or find_package after install
target_link_libraries(my_app PRIVATE hf::se050)
```

`cmake/hf_se050_build_settings.cmake` defines include dirs and generates `se050_version.h`.

ESP-IDF uses the `examples/esp32/components/hf_se050` wrapper component (same settings file).
