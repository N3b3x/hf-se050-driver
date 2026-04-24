# Medical-Device Cybersecurity — Full Chain, Explained

> **Scope.** This document covers the *entire* security architecture of
> the HF-SE050 AWS-IoT lifecycle example, mapped onto the deliverables an
> FDA cybersecurity submission expects. It does **not** cover PHI / HIPAA
> because this example ships only telemetry, OTA logs, and operational
> diagnostics — no patient-identifiable data. If your product handles
> PHI you must layer HIPAA §164.312 controls on top of what's below.
>
> **Target standards:**
> - FDA *"Cybersecurity in Medical Devices: Quality System Considerations
>   and Content of Premarket Submissions"* (Sep 2023)
> - IEC 81001-5-1:2021 (Secure software lifecycle for health software)
> - IEC 62304:2015+A1:2016 (Software lifecycle — safety classification)
> - ISO 14971:2019 (Risk management)
> - NIST SP 800-193 (Platform Firmware Resiliency)
> - UL 2900-2-1 (Network-connectable healthcare products)
> - IEC/TR 60601-4-5 (IT network risk management for medical devices)

---

## 1. Threat model (short)

Using STRIDE, the relevant threats for a cloud-connected medical logger
are:

| Threat              | Example attack                                     | Where we defend                        |
|---------------------|----------------------------------------------------|----------------------------------------|
| **S**poofing        | Attacker pretends to be your device to AWS         | SE050 identity key + client cert TLS   |
| **T**ampering       | Altered firmware extracts logs / redirects data    | Signed OTA + secure boot (§5)          |
| **R**epudiation     | Device claims "not me" about a bad log             | Per-message SE050 signature            |
| **I**nfo disclosure | Bus sniff, flash dump, rogue TLS MITM              | Non-exportable key, flash encrypt, TLS |
| **D**oS             | Flood broker, brick device via bad config          | Device Defender, signed control cmds   |
| **E**OP             | Escalate via bootloader / USB / JTAG               | RoT chain + JTAG fuse disable          |

The table maps 1-to-1 to FDA's expected "Security Risk Assessment"
artifact — keep a copy under ISO 14971 §7.1.

---

## 2. The five trust anchors on the SE050

The entire architecture hinges on five keys / objects living inside the
secure element. None leaves silicon after provisioning.

| Anchor                          | Slot                      | Rotated how?                         | Offline HSM needed? |
|---------------------------------|---------------------------|--------------------------------------|---------------------|
| Device identity (ECC-P256)      | `kDeviceIdentityKey`      | Re-provisioning flow (§4)            | For cert signing    |
| Device certificate (X.509)      | `kDeviceCertificate`      | Same identity key, new CA signature  | Yes (your CA)       |
| Server root CA                  | `kServerRootCa`           | Annual rollover via control command  | Yes                 |
| OTA vendor public key           | `kOtaVendorPublicKey`     | Dual-key rotation (§7)               | Yes (firmware HSM)  |
| Re-provision authority pubkey   | `kReprovisionAuthorityKey`| Never (keep offline, pre-gen 2nd)    | **Yes, air-gapped** |

Keeping the re-provisioning authority **on an air-gapped HSM** is the
single most important operational control — it's the "master key" that
can factory-reset any deployed device, so treat it like a HSM root.

---

## 3. End-of-line factory provisioning — full procedure

The example codebase is the *device half* of the factory workflow. The
*station half* lives in your production test software. This is the
complete procedure:

### 3.1 Station hardware

```
   ┌──────────────────────┐        ┌───────────────────────────────────┐
   │  Factory PC          │        │  End-of-line test fixture         │
   │  (hardened Linux)    │        │                                   │
   │                      │        │   ┌──────────┐     ┌──────────┐   │
   │  ┌───────────────┐   │  USB   │   │  MCU     │ I²C │  SE050   │   │
   │  │ Production    │───┼────────┼──▶│ (factory │────▶│          │   │
   │  │ Test Runner   │   │        │   │  f/w)    │     │          │   │
   │  └───────┬───────┘   │        │   └──────────┘     └──────────┘   │
   │          │           │        │                                   │
   │  ┌───────▼───────┐   │ TLS    │                                   │
   │  │ Internal CA   │───┼────────┼──▶ (HSM-backed signing service)   │
   │  │ / PKI client  │   │        │                                   │
   │  └───────────────┘   │        │                                   │
   └──────────────────────┘        └───────────────────────────────────┘
```

**Factory PC requirements** (ISO 27001 A.11.1 for the room):
- Air-gapped from corporate network; exits only via a unidirectional
  diode to the CA signing service.
- BIOS/UEFI secure-boot enabled, full-disk encryption on.
- Certificate signing happens through an **HSM** (YubiHSM, SafeNet, or
  AWS CloudHSM — never a bare software key).
- Every station logs an **audit record** (see §9) that is signed by the
  factory's internal CA.

### 3.2 Per-unit sequence (what the operator sees)

```
 1. Op scans serial number barcode.                           (1 sec)
 2. Station powers up fixture, boots factory firmware.        (2 sec)
 3. Factory firmware reports SE050 Unique ID over USB.        (100 ms)
 4. Station sends "GENKEY" — device runs Stage 1 keygen.      (300 ms)
 5. Device returns the public key over USB.                   (100 ms)
 6. Station builds CSR, asks HSM-CA to sign it.               (500 ms)
 7. Station sends back signed device cert + Amazon root CA
    + OTA vendor pubkey + reprov-authority pubkey.            (200 ms)
 8. Device installs all four and writes provisioned sentinel. (300 ms)
 9. Station runs boundary-scan self-test (signs a challenge,
    verifies the signature against the exported pubkey).      (200 ms)
10. Station uploads signed audit record to factory vault.     (500 ms)
11. Op scans "PASS" barcode, device moves to packaging.       (1 sec)
```

Total: ~4-5 s per unit. Mirrors the workflow documented in
NXP AN12413 §7 "Secure Provisioning" and Microchip TrustFLEX
provisioning service reference workflow.

### 3.3 What the factory firmware MUST do that field firmware MUST NOT

| Behaviour                                     | Factory f/w | Field f/w |
|-----------------------------------------------|:-----------:|:---------:|
| Expose raw USB/UART command interface         |    YES      |    NO     |
| Accept keygen requests                        |    YES      |  only via reprov token |
| Print debug secrets to serial                 |    YES      |    NO     |
| JTAG enabled                                  |  YES (read) |    NO (blown eFuse) |
| Accept unsigned firmware                      |    NO       |    NO     |

The two builds ship from the **same source tree** differentiated by a
`HF_FACTORY_MODE=1` define. After end-of-line test the station flashes
the *field* firmware and blows the JTAG-disable eFuse before packaging.

### 3.4 Factory data retention

Per 21 CFR 820.180 records retention rule, keep for the **longer of**:
- Product service lifetime + 2 years, or
- 5 years from date of distribution.

Items to retain per unit:
- SE050 Unique ID
- Device public key (SHA-256 fingerprint)
- Device certificate (full DER)
- Factory station ID + operator badge ID
- Audit record signature (signed by the CA)

Store in a **tamper-evident** log (WORM storage or signed Merkle tree).

---

## 4. Re-provisioning (field-return / service depot)

This is the only field-active path that can reset a device back to "not
provisioned" state. It's implemented in
[stage_provisioning.hpp — RequestReprovisioning()](./stage_provisioning.hpp).

### 4.1 Token format (120 B)

```
  offset  size  field
    0      4    magic       "HFRV" (0x48 0x46 0x52 0x56)
    4      4    counter     LE uint32, strictly > on-chip counter
    8     18    device UID  (SE050 unique ID; bind to one chip only)
   26     22    reserved    zeros (future: expiry timestamp, reason code)
   48     72    signature   ECDSA-P256 DER over bytes [0..47]
                            signed by kReprovisionAuthorityKey private half
```

### 4.2 Why each field matters

- **Magic.** Cheapest possible malformation check; frees the parser
  from having to invoke the SE050 on obvious garbage.
- **Counter.** Defeats replay of a captured token — once burned, burned
  forever on that device.
- **Device UID.** Defeats "take a token meant for device A, apply to
  device B" — the verification compares the embedded UID against the
  SE050's own Unique ID. If they don't match, reject.
- **Signature.** Only the air-gapped HSM can produce this.

### 4.3 Cryptographic invariants to preserve

1. **Identity key is NOT regenerated.** The same ECC-P256 key-pair stays
   in `kDeviceIdentityKey` across the reset. Rationale: the pubkey
   fingerprint is the device's "DNA" across the factory / CA / cloud
   databases. Rotating it breaks every historical audit trail.
2. **Only the sentinel is cleared.** The new Stage 1 run will overwrite
   the certificate, root CA, and OTA key with whatever the (now-trusted)
   factory station sends. This is *how* the service depot swaps an
   expired cert without regen-ing the key.
3. **Counter moves up-only.** Never let the reprov counter decrement.

### 4.4 Operational flow

```
  Hospital biomed → RMA → Service depot
                                │
                                ▼
                      ┌──────────────────┐
                      │ Depot tester     │
                      │ reads device UID │
                      └────────┬─────────┘
                               │
                               ▼
                      ┌──────────────────┐
                      │ Air-gapped HSM   │
                      │ signs reprov     │
                      │ token (UID+ctr)  │
                      └────────┬─────────┘
                               │ via USB stick OR diode
                               ▼
                      ┌──────────────────┐
                      │ Depot tester     │
                      │ sends MQTT cmd   │
                      │ OR direct USB    │
                      └────────┬─────────┘
                               │
                               ▼
                        Device accepts,
                        reboots, runs Stage 1,
                        gets new cert, ships.
```

---

## 5. Secure-boot chain on the MCU (vendor-neutral)

The SE050 holds the *device* root of trust. The **bootloader** holds the
*firmware* root of trust — these are two different trust anchors and both
are required.

### 5.1 Chain overview

```
  ┌──────────────────┐   verifies   ┌──────────────────┐   verifies   ┌──────────────────┐
  │ MCU ROM boot     │ ───────────▶ │ 1st-stage boot-  │ ───────────▶ │ Application      │
  │ (immutable fuse  │              │ loader (BL1)     │              │ firmware         │
  │  digest / key)   │              │ signed by vendor │              │ signed by vendor │
  └──────────────────┘              └──────────────────┘              └──────────────────┘
                                                                               │
                                                                               ▼
                                                                     Re-verified against
                                                                     SE050 OTA key too
                                                                     (belt & suspenders)
```

### 5.2 Platform-specific implementation pointers

#### ESP32 / ESP32-S3 (what this example targets)

- **Secure Boot v2** — uses RSA-3072 or ECDSA-P256 signatures; root
  digest burned into eFuses by ESP-IDF's `idf.py secure-boot-generate-key`
  then `idf.py secure-boot-burn-key`.
- **Flash Encryption** — AES-256-XTS with a per-chip key stored in eFuse;
  all partitions except `nvs_keys` become unreadable via JTAG/UART.
- Gate enablement via `CONFIG_SECURE_BOOT=y` and
  `CONFIG_SECURE_FLASH_ENC_ENABLED=y` in `sdkconfig.defaults`.
- **Enable at the factory, not in dev.** Once burned, the chip can't go
  back.

Reference: ESP-IDF `docs/en/security/secure-boot-v2.rst`.

#### STM32H7 (and other Cortex-M7 / M33 targets)

- **STM32Cube Secure Bootloader (X-CUBE-SBSFU)** — open-source dual-bank
  bootloader with image authentication using ECDSA-P256 or RSA-2048.
- **SFI (Secure Firmware Install)** ships encrypted firmware to the CM.
- Secure Boot root of trust lives in OTP **user option bytes**; lock via
  `RDP Level 2` (irreversible).
- For Cortex-M33 H5 family: use **TrustZone** to split bootloader (secure
  world) from app (non-secure world). Signature verification runs in
  secure world.

Reference: AN5156 "Secure Boot and Secure Firmware Update".

#### Nordic nRF52/nRF53

- **MCUboot** (TF-M backed on nRF53). ECDSA-P256 signatures by default.
- Root public-key slot in `bootloader_storage`.

#### NXP i.MX RT / Kinetis

- **HAB (High-Assurance Boot)** with vendor-signed CSF.
- Combined with SNVS + OTP key storage for a full RoT.

### 5.3 What every vendor's implementation needs

Regardless of chip family, a compliant secure-boot solution provides:

1. **Immutable first stage** — ROM or write-once fuse block.
2. **Asymmetric signature verify** on every subsequent stage (no shared
   symmetric keys in boot path).
3. **Anti-rollback counter** — prevents downgrading to a firmware with
   known CVEs (NIST SP 800-193 §4.3).
4. **Flash-encryption bind to chip** — pulled cold-storage flash stays
   unreadable off-board.
5. **Debug disable in production** — JTAG / SWD locked via eFuse; RDP2
   on STM32, `CONFIG_SECURE_DISABLE_JTAG` on ESP32, DAP lock on nRF.

### 5.4 Integration point with the SE050

After the bootloader's *own* signature check passes on an incoming OTA,
the image is additionally verified by
[stage_ota_verify.hpp](./stage_ota_verify.hpp) against
`kOtaVendorPublicKey` on the SE050. This dual-check gives you
**key-compromise resilience**: if the bootloader key leaks, the SE050
still refuses the image; if the SE050 key leaks, the bootloader still
refuses it.

---

## 6. TLS / cloud authentication

### 6.1 What mbedTLS does (transport)

- TLS 1.2 minimum, TLS 1.3 preferred.
- Cipher suite: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (AWS IoT default).
- Server cert verification against `kServerRootCa` loaded from SE050.
- Client-auth cert sent from `kDeviceCertificate` loaded from SE050.
- `CertificateVerify` signature computed *on the SE050* via the
  `mbedtls_pk_info_t` opaque-key vtable (recipe in
  [stage_tls_identity.hpp](./stage_tls_identity.hpp)).

### 6.2 What the SE050 does (identity)

- Holds the private key non-exportably.
- Signs one SHA-256 digest per handshake (TLS 1.2 CertificateVerify).
- ~5 ms per ECDSA-P256 sign at typical I²C speeds (well under the
  MQTT keep-alive budget).

### 6.3 AWS IoT policy hardening (least privilege)

Attach **per-device** policies, not a fleet-wide wildcard. Minimum
policy for this example (adjust thing-name pattern):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iot:Connect",
      "Resource": "arn:aws:iot:us-east-1:<acct>:client/${iot:Connection.Thing.ThingName}"
    },
    {
      "Effect": "Allow",
      "Action": "iot:Publish",
      "Resource": "arn:aws:iot:us-east-1:<acct>:topic/hf/medical/telemetry/${iot:Connection.Thing.ThingName}/*"
    },
    {
      "Effect": "Allow",
      "Action": "iot:Subscribe",
      "Resource": "arn:aws:iot:us-east-1:<acct>:topicfilter/hf/medical/control/${iot:Connection.Thing.ThingName}/*"
    },
    {
      "Effect": "Allow",
      "Action": "iot:Receive",
      "Resource": "arn:aws:iot:us-east-1:<acct>:topic/hf/medical/control/${iot:Connection.Thing.ThingName}/*"
    }
  ]
}
```

### 6.4 Device Defender

Enable AWS IoT Device Defender rules for:
- Connection attempts from unexpected regions (geofence)
- Message size / rate anomalies (indicative of compromise)
- Authentication failures (brute-force indicator)

Quarantine action: revoke the device certificate via AWS IoT's
`UpdateCertificate` API. The next TLS handshake will fail; the depot
flow (§4) is needed to return the device to service.

---

## 7. OTA — the complete update story

### 7.1 Dual-signature requirement

Every firmware image is signed **twice** with two different keys:

1. Bootloader signing key (ESP32 Secure Boot v2 / MCUboot / HAB / etc.)
2. SE050 OTA vendor key (`kOtaVendorPublicKey`)

Both must verify for the image to boot. Key ceremony is performed in
the build farm's HSM; neither key ever touches a developer laptop.

### 7.2 A/B partitions + anti-rollback

Every target MCU in this reference uses A/B partitioning:

- `ota_0`, `ota_1`, `data` (persistent), `factory` (golden image).
- Anti-rollback counter in `nvs_keys` (ESP32) or user-option-byte
  (STM32). Image header carries a monotonic version; boot refuses
  anything `< nvm_counter`.
- On successful boot + N self-tests, counter bumps.

### 7.3 Recovery posture

If a bad image crashes during boot:
1. Bootloader retries up to 3 times (watchdog-reset counted).
2. On 4th failure, bootloader falls back to `factory` partition.
3. Factory partition re-requests an OTA from the cloud on connect.

This matches NIST SP 800-193 "Recovery" tier.

### 7.4 Key rotation

Dual-key scheme: the image header carries **two** signature slots. Key
rollover procedure:

| Step | Action                                                         |
|------|----------------------------------------------------------------|
| 1    | Build new image signed by **both** old and new keys            |
| 2    | Deploy to fleet — boot path still trusts old key                |
| 3    | Control command rotates `kOtaVendorPublicKey` to new key       |
| 4    | Future builds signed only by new key                           |

This lets you retire a compromised key without bricking the fleet.

---

## 8. Logging and audit trail (non-PHI)

This example transmits **only operational data** — sensor readings,
firmware version, uptime, error codes. The per-message ECDSA signature
produced by [stage_telemetry.hpp](./stage_telemetry.hpp) provides:

- **Authenticity** — only this specific device's SE050 could have
  produced the signature.
- **Integrity** — any byte flipped in transit or storage invalidates
  the signature.
- **Non-repudiation** — downstream consumers can prove, even to a third
  party, that the data originated from this device.

Recommended cloud-side pipeline (sketch):

```
   MQTT broker → Kinesis Firehose → S3 (object-lock WORM) + Timestream
                       │
                       └────────────▶ Lambda "signature-verify"
                                      on new-object trigger; logs to
                                      CloudWatch + SNS alert on fail.
```

Object-lock retention: **10 years** matches the longest applicable US
medical-device record requirement (21 CFR 820).

---

## 9. Testing that satisfies pre-market cybersecurity review

FDA's 2023 guidance §V.C.1.b requires three classes of testing. Map
your test suite to these headings exactly so the reviewer can find
them.

### 9.1 Security requirement unit tests

Run in CI on every PR. Minimum suite:

| Test                                          | Pass criterion                   |
|-----------------------------------------------|----------------------------------|
| SE050 private key is not exportable           | `ReadPublicEcKey` returns pub only; no private-half API exists |
| Provisioned sentinel survives reboot          | Boot twice; Stage 1 skipped 2nd  |
| Unsigned OTA manifest is rejected             | Bit-flipped signature → `EcdsaVerify` returns `sig_ok=false` |
| Stale reprov token is rejected                | Submit token with counter ≤ NVM  |
| Mismatched UID token is rejected              | Submit token targeting other UID |
| TLS uses client-cert auth                     | Wireshark capture shows `CertificateVerify` present |
| Telemetry signature verifies offline          | Capture → re-hash → verify w/ exported pubkey → OK |

### 9.2 Fuzz testing

Targets (any one of AFL++, libFuzzer, Honggfuzz):
- APDU response parser (driver-side, on host build)
- OTA manifest parser
- Control-command dispatcher (`HandleCommand`)
- MQTT topic string builder

Minimum coverage: **24 hours of fuzzing, zero crashes** per component,
reported per IEC 81001-5-1 §8.1.3.

### 9.3 Penetration testing

Contract an external firm accredited under **ISO 17025** with medical
scope (examples: MedCrypt, MedSec, NCC Group Medical). Scope items:

- **Hardware-level** — power analysis + EM side-channel on SE050 I²C
  bus; glitching at the MCU reset line; JTAG probe after fuse burn.
- **Firmware-level** — extract flash, look for secrets; replay captured
  MQTT messages; attempt downgrade.
- **Cloud-level** — policy scanner (iamlive), IAM-role escalation,
  cross-tenant data leak tests.
- **Supply-chain** — SBOM review per NTIA minimum elements.

Deliverable: a signed pen-test report, CVE-style findings table, and
remediation evidence. This goes into the **submission package**.

### 9.4 Mandatory documents (FDA checklist)

- **Security Risk Assessment** (STRIDE + ISO 14971 hazard analysis)
- **Architecture View** — this diagram + narrative
- **Cybersecurity SBOM** — CycloneDX or SPDX format, per NTIA minimum
- **Threat Modelling Report** — detailed for top-5 threats
- **Security Testing Report** — §9.1 + §9.2 + §9.3 outputs
- **Vulnerability Management Plan** — CVE monitoring cadence, patch SLA
- **Post-Market Monitoring Plan** — Device Defender triggers, incident
  response runbook, CISA/FDA MITRE disclosure path

All of these are **required** in a 510(k) or PMA cybersecurity section
under the 2023 guidance.

---

## 10. Known limitations of *this example* (what ships today)

Be honest in your submission — the reviewer will find these anyway.

| Area                               | Status in example            | Needed for production           |
|------------------------------------|------------------------------|---------------------------------|
| SE050 per-object policy flags      | Not exposed by driver yet    | Driver API bump + factory flow  |
| Re-provisioning token UID binding  | Placeholder (no SE050 UID API yet) | Wire to `GetUniqueId` when landed |
| MQTT client                        | Stubbed (`PublishStub`)      | Link `esp_mqtt_client`          |
| mbedTLS `pk_info` vtable           | Recipe-only; not compiled    | Wire per §6.1                   |
| Secure Boot v2 / Flash Encryption  | Not enabled                  | Burn at factory per §5.2        |
| AWS IoT policy                     | Document-only                | Attach per device at onboarding |
| SBOM                               | Manual                       | Auto-gen CycloneDX in CI        |

None of these block the **architecture review** — they're scheduled for
the driver v0.4.0 release.

---

## 11. Incident response — the day something breaks

Written into the post-market monitoring plan (§9.4):

1. **Detect** — Device Defender alarm, field report, or CVE feed hit.
2. **Contain** — revoke affected device certs via
   `aws iot update-certificate --new-status REVOKED`.
3. **Eradicate** — roll out dual-signed replacement firmware via §7.4.
4. **Recover** — service depot flow (§4) brings quarantined units back
   online with new cert.
5. **Post-mortem** — file with CISA + FDA within **60 days** if
   exploited, **90 days** regardless (CIRCIA + FDA 2023 guidance).

---

## 12. What you still need to build (your side)

This example is the device-firmware reference. The rest of your
medical-grade security program needs you to stand up:

- A **CA + HSM** for device-cert issuance (YubiHSM2, SafeNet Luna, or
  AWS CloudHSM).
- A **factory provisioning tool** (Python works; mirrors §3.2 steps).
- An **air-gapped HSM** for the re-provisioning authority key.
- A **build HSM** for OTA signing (separate from device CA).
- **CI/CD security gates** (SAST, fuzz, SBOM diff, dep-vuln scan).
- **Cloud-side signature verifier** Lambda (§8).
- **Device Defender rules** and **quarantine runbook** (§6.4).
- **Pen-test contract** (§9.3).
- **Post-market monitoring plan** (§11).

---

## Appendix A — Quick reference to example files

- [lifecycle_config.hpp](./lifecycle_config.hpp) — slot map, AWS config
- [stage_provisioning.hpp](./stage_provisioning.hpp) — Stage 1 + reprov
- [stage_bootstrap.hpp](./stage_bootstrap.hpp) — Stage 2 WiFi
- [stage_tls_identity.hpp](./stage_tls_identity.hpp) — Stage 3 TLS hook
- [stage_telemetry.hpp](./stage_telemetry.hpp) — Stage 4 signed telemetry
- [stage_ota_verify.hpp](./stage_ota_verify.hpp) — Stage 5 OTA verify
- [stage_control.hpp](./stage_control.hpp) — Stage 6 signed commands
- [se050_aws_iot_lifecycle.cpp](./se050_aws_iot_lifecycle.cpp) — entry

## Appendix B — Standards cross-reference

| Section | Standard clause mapped                                   |
|---------|----------------------------------------------------------|
| §1      | ISO 14971 §5.3 / FDA 2023 §IV.A                          |
| §2      | ISO 27001 A.10, NIST SP 800-57                            |
| §3      | 21 CFR 820.180, ISO 13485 §7.5.8, NXP AN12413            |
| §4      | IEC 81001-5-1 §7.2.3                                      |
| §5      | NIST SP 800-193 §4, IEC 62304 §5.4                        |
| §6      | RFC 8446, AWS IoT Core security best practices            |
| §7      | NIST SP 800-193 §4.3 "Recovery"                           |
| §8      | 21 CFR 820 (record retention), HIPAA §164.312(b) (N/A here) |
| §9      | FDA 2023 guidance §V.C.1, IEC 81001-5-1 §8                |
| §10     | Transparency clause, FDA 2023 §V.B.1                      |
| §11     | CIRCIA, FDA 2023 §V.E                                     |
