# ESP32 examples — HF-SE050

## Prerequisites

- ESP-IDF **v5.5** (or as listed in `app_config.yml`)
- Submodule **`examples/esp32/scripts`** initialized:

```bash
git submodule update --init --recursive
```

## Build / flash

From **`examples/esp32/`**:

```bash
./scripts/build_app.sh se050_minimal_example Debug release/v5.5
./scripts/flash_app.sh flash se050_minimal_example Debug
```

Set `ESPPORT` if needed (for example `export ESPPORT=/dev/ttyACM0`).

## Status

**Scaffold only** — the example prints a log line and exits `app_main`. SE050 I²C and APDU integration will be added after reference material is merged into tracked sources.
