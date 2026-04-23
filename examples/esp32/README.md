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

## Default wiring (`HfSe050EspIdfI2c`)

| Signal | GPIO (ESP32-S3 default) |
|--------|-------------------------|
| SDA    | 47                      |
| SCL    | 48                      |
| SE050 7-bit addr | `0x48` (override in `Se050EspI2cConfig`) |
| SE_RESET | not used (`GPIO_NUM_NC`) |

Override by constructing `hf_se050_examples::Se050EspI2cConfig` before `HfSe050EspIdfI2c`.

## Status

**Phase 1** — CRTP transport, `se050::Device`, and a trivial `TransceiveRaw` probe. **T=1 / APDU** come next; see repo `README.md` and `docs/platform_integration.md`.
