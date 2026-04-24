# SE050 → AWS IoT — Full Device Lifecycle Example

This is the **headline end-to-end example** for the HF-SE050 driver.
It walks a single ESP32-S3 + NXP SE050 board through every phase of a
production medical / industrial IoT device's life:

1. **Factory provisioning** — on-chip key-pair, CSR, cert install
2. **First-field-boot** — WiFi associate, IP, ready for TLS
3. **TLS identity** — mbedTLS delegates ECDSA sign to the SE050
4. **Steady-state telemetry** — ADC oversample → JSON → SE050 sign → MQTT
5. **OTA verify** — ECDSA-verify firmware manifest against on-chip trust anchor
6. **Cloud control channel** — signed commands for ping / re-provision / OTA / config

> **Security posture, threat model, factory procedure, secure-boot
> chain (ESP32 + STM32H7 + nRF + i.MX), pen-test plan, and
> FDA-submission checklist live in [SECURITY.md](./SECURITY.md).
> Read that first if you're building a medical-grade product.**

Everything lives inside this directory and compiles as a single ESP-IDF
application so you can flash → monitor → understand in one pass.

---

## 1. File layout

```
se050_aws_iot_lifecycle/
├── se050_aws_iot_lifecycle.cpp   ← main entry (the file in app_config.yml)
├── lifecycle_config.hpp          ← slot IDs, AWS endpoint, WiFi, feature flags
├── stage_provisioning.hpp        ← STAGE 1 + re-provisioning (signed token)
├── stage_bootstrap.hpp           ← STAGE 2
├── stage_tls_identity.hpp        ← STAGE 3
├── stage_telemetry.hpp           ← STAGE 4
├── stage_ota_verify.hpp          ← STAGE 5
├── stage_control.hpp             ← STAGE 6 (signed cloud commands)
├── README.md                     ← this file
├── SECURITY.md                   ← FDA-grade security architecture doc
└── tools/                        ← host-side companion scripts
    ├── README.md                 ←   map of the toolkit
    ├── sign_reprovision_token.py ←   offline HSM signer for reprov tokens
    ├── factory_provision.py      ←   end-of-line test-station driver
    ├── verify_telemetry.py       ←   CLI signature verifier
    ├── lambda_verify_telemetry.py ←  AWS Lambda cloud verifier
    ├── generate_sbom.py          ←   CycloneDX SBOM generator
    └── tests/                    ←   host unit tests (pytest)
```

The *entry* `.cpp` simply calls `RunStage()` on each stage in order. All
substance lives in the headers so you can read one stage at a time.

---

## 2. Architectural decision — how provisioning is actually done

Before you can flash your first production board you must decide **where
the device identity is created**. The industry offers three archetypes:

| Option | Who owns the ID? | Hardware needed | Field re-provision? | Recommended when |
|---|---|---|---|---|
| **A. MCU-as-middleman** (this example) | You | Just the MCU + SE050 on the board | Yes | Most teams, most products |
| **B. Bed-of-nails direct on SE050** | You | Dedicated I2C test fixture | No | CM pre-provisions bare SE050 chips before assembly |
| **C. NXP pre-provisioned profile** (`IoT-A`) | NXP / cloud | None | N/A | Consumer devices with AWS / Azure out-of-box |

We recommend **Option A** and implement it here because:

- It **reuses the same I2C / T=1 code path** the field firmware uses —
  the factory tests what ships.
- It supports SCP03 secure-channel (session keys live in the MCU where
  they belong).
- **Field re-provisioning** (service depots, hospital biomed replacement
  cycles) is possible without the original bed-of-nails fixture.
- It requires no extra tester hardware beyond your end-of-line PCBA
  programmer.

See the comment block at the top of `stage_provisioning.hpp` for the
ASCII-art flow of how the factory PC drives the MCU over USB to command
the SE050.

---

## 3. AWS IoT Core setup (once per account)

You only need to do this **once for your whole fleet**; every device then
onboards automatically.

### 3.1 Find your endpoint

```bash
aws iot describe-endpoint --endpoint-type iot:Data-ATS
```

Copy the returned hostname into `lifecycle_config.hpp → aws::kEndpointHost`.

### 3.2 Upload your CA (or use Fleet Provisioning by Claim)

- **Option 1 — Just-in-Time Registration (JITR):**
  Upload your internal CA certificate (`aws iot register-ca-certificate`)
  so AWS auto-registers each device cert on first connect.

- **Option 2 — Fleet Provisioning by Claim (recommended for >1k units):**
  Create a template with `aws iot create-provisioning-template` whose
  name matches `lifecycle_config.hpp → aws::kProvisioningTemplateName`
  (default: `HfSE050MedicalFleet`). Embed a *claim* certificate in the
  factory firmware and let AWS mint each device's final cert on first
  boot.

### 3.3 Topic policy

Attach an IoT policy that allows publish on
`hf/medical/telemetry/${iot:Connection.Thing.ThingName}/#` and subscribe
on `hf/medical/control/${iot:Connection.Thing.ThingName}/#`.

---

## 4. Building & flashing

From the `examples/esp32/` directory:

```bash
./scripts/build_app.sh se050_aws_iot_lifecycle Debug release/v5.5
./scripts/flash_app.sh se050_aws_iot_lifecycle Debug release/v5.5 /dev/ttyUSB0
idf.py -B build-app-se050_aws_iot_lifecycle-type-Debug-target-esp32s3-idf-release_v5.5 monitor
```

The target is **ESP32-S3** (configurable via `app_config.yml → metadata.target`).

### 4.1 Compile-time feature gates

Both defined in `lifecycle_config.hpp`:

| Macro | Default | Effect |
|---|---|---|
| `HF_SE050_LIFECYCLE_ENABLE_NETWORK` | `1` | Bring up WiFi (stage 2) + ADC. Set to `0` for bench SE050-only runs. |
| `HF_SE050_LIFECYCLE_SIGN_EVERY_MESSAGE` | `1` | Sign each telemetry payload with SE050 in addition to TLS. |

---

## 5. Replacing stubs for production

Search the tree for `TODO(factory)` — these are the **only** places that
hold placeholder bytes:

1. `stage_provisioning.hpp — SignCsrDigest()`
   Replace the synthetic digest with `sha256(DER(CertificationRequestInfo))`.

2. `stage_provisioning.hpp — RunStage()` (three places)
   - Real X.509 device cert (DER) from your CA.
   - Amazon Root CA 1 (PEM → DER), download: https://www.amazontrust.com/repository/AmazonRootCA1.pem
   - Vendor OTA ECDSA P-256 public key (65-byte uncompressed point).

3. `stage_telemetry.hpp — PublishStub()`
   Replace with `esp_mqtt_client_publish()` once you add the `mqtt`
   component to `MAIN_REQUIRES`.

4. `stage_tls_identity.hpp`
   Implement the `mbedtls_pk_info_t` vtable so mbedTLS transparently
   uses the SE050 for ECDSA signing during the TLS handshake (recipe
   logged at boot).

---

## 6. HIPAA / medical-grade posture

This example is written to meet the **crypto portion** of the following
standards when properly configured:

| Standard | Relevant control | How the example addresses it |
|---|---|---|
| HIPAA Security Rule §164.312(a)(2)(iv) | Encryption of ePHI at rest & in transit | TLS 1.2 + SE050 per-message sign |
| IEC 81001-5-1 | Secure software lifecycle | Signed OTA manifests, versioned slot map |
| ISO 13485 §4.1.6 | Software validation | Deterministic stage outputs, idempotent provisioning |
| ISO/IEC 27001 A.10 | Cryptographic controls | Non-exportable keys, vendor-signed firmware |
| UL 2900-1 | Product security testing | No secrets in flash; on-chip root-of-trust |

The *non-exportable private key* is the cornerstone — ensure your
security program documents that the SE050's `Policy::Forbid_Export` is
set on `slot::kDeviceIdentityKey` (the driver's `GenerateEcKeyPair`
default).

---

## 7. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Stage 0 bring-up fails | I2C wiring / pull-ups / reset pin — run `se050_minimal_example` first |
| Stage 1 keygen times out | SCP03 session key mismatch if secure-channel is active |
| Stage 2 never gets IP | SSID/PSK typo in `lifecycle_config.hpp → wifi::` |
| Stage 3 sign works but TLS fails | `mbedtls_pk_info_t` not wired; see recipe in stage header |
| Stage 4 publishes locally but nothing reaches AWS | IoT policy missing publish permission on topic |
| Stage 5 always says REJECTED | Expected for the demo — real manifests require real signatures |

Enable per-stage log filtering:

```bash
idf.py monitor --print_filter="se050_lc*:I"
```

---

## 8. Further reading

- [SE050 datasheet (NXP AN12413)](https://www.nxp.com/products/SE050)
- [AWS IoT Fleet Provisioning developer guide](https://docs.aws.amazon.com/iot/latest/developerguide/provision-wo-cert.html)
- [mbedTLS PK layer (opaque keys)](https://mbed-tls.readthedocs.io/)
- Sibling examples in this directory tree for lower-level drills:
  - `se050_minimal_example.cpp` — transport / ATR only
  - `se050_cloud_onboarding_example.cpp` — keygen + sign + verify in isolation
  - `se050_cloud_registration_packet_example.cpp` — idempotent enrollment payload
