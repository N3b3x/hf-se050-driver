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

## Available apps

- `se050_minimal_example` — reset + T=1 warm reset + GET ATR + SELECT applet
- `se050_smoke_example` — adds GetVersion/GetRandom/GetFreeMemory typed APDU checks
- `se050_object_lifecycle_example` — write/read/delete binary object lifecycle round-trip
- `se050_cloud_onboarding_example` — generate P-256 key, sign onboarding challenge digest, verify signature on-chip
- `se050_cloud_registration_packet_example` — idempotent key provisioning + public key read + challenge signature payload

## Security learning docs

- `docs/examples.md` — internals for each app + SVG flow diagrams
- `docs/security_iot_ota_comms.md` — IoT onboarding, OTA trust chain, Ethernet/TLS and app-layer comms security patterns
