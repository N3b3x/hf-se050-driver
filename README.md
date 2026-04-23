# hf-se050-driver

Scaffold for an **NXP SE050 / SE050A EdgeLock™ secure element** driver (I²C), aligned with other `hf-*-driver` repos under `hf-core-drivers/external`.

## Status

- **Phase 1 (done):** `se050::I2cTransceiveInterface` (CRTP), `Session`, `Device`, ESP-IDF example transport (`HfSe050EspIdfI2c`), minimal `se050_minimal_example` build.
- **Next:** T=1 over I2C, APDU, SCP03, applet APIs — see `docs/platform_integration.md`.
- **Local reference material:** put datasheets, old code, and NDA-restricted exports under `_local_reference/` (see that folder’s README). That tree is **gitignored** and will not sync to GitHub.

## Layout

| Path | Purpose |
|------|---------|
| `inc/` | Public headers (stubs until implementation). |
| `cmake/` | CMake package + `hf_se050_build_settings.cmake`. |
| `docs/` | Documentation stubs (Jekyll/Doxygen wired via `_config/`). |
| `examples/esp32/` | ESP-IDF example(s); `scripts/` is a submodule to `hf-espidf-project-tools`. |
| `_config/` | Doxygen, Jekyll, clang-format/tidy, lychee, etc. |
| `.github/workflows/` | CI (YAML, markdown, docs, ESP32 matrix build). |
| `_local_reference/` | **Ignored** except `README.md` — your private inputs. |

## ESP32 example (minimal)

From `examples/esp32/` (after `git submodule update --init --recursive`):

```bash
./scripts/build_app.sh se050_minimal_example Debug release/v5.5
./scripts/flash_app.sh flash se050_minimal_example Debug
```

Default target in `app_config.yml` is **esp32s3**.

## CMake (host / generic)

```cmake
find_package(hf_se050 CONFIG)  # when installed / in CMAKE_PREFIX_PATH
target_link_libraries(my_target PRIVATE hf::se050)
```

## Related repos

- Consumed as a submodule from [`hardfoc/hf-core-drivers`](https://github.com/hardfoc/hf-core-drivers) at `external/hf-se050-driver`.
