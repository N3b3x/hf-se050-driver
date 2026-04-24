# Companion tooling for the SE050 AWS-IoT lifecycle example

These scripts are the **host-side half** of the workflows that the
device firmware implements. They are intentionally small, readable,
and dependency-light so you can drop them into your factory / cloud
pipeline without a framework commitment.

| Script                         | Pairs with                              | Purpose                                                |
|--------------------------------|-----------------------------------------|--------------------------------------------------------|
| `sign_reprovision_token.py`    | `stage_provisioning.hpp::RequestReprovisioning` | Produce a 120 B signed token from an offline HSM key   |
| `factory_provision.py`         | `stage_provisioning.hpp::RunStage` (factory build) | End-of-line test station driver (§3 in SECURITY.md)    |
| `verify_telemetry.py`          | `stage_telemetry.hpp::SignPayload`      | Offline / CI signature verifier for captured messages  |
| `lambda_verify_telemetry.py`   | same                                    | AWS Lambda version of the verifier (S3 trigger)        |
| `generate_sbom.py`             | SECURITY.md §9.4                        | CycloneDX SBOM generator (scans ESP-IDF + driver tree) |
| `tests/test_reprov_token.py`   | SECURITY.md §9.1                        | Host unit tests for the token format + invariants      |

## Dependencies

Everything uses the Python standard library plus **`cryptography`**
(pyca/cryptography). Install once:

```bash
python3 -m pip install --user cryptography
```

For the SBOM generator add:

```bash
python3 -m pip install --user cyclonedx-python-lib
```

## Security posture

- No script writes secrets to disk. Keys are either loaded from a PEM
  handed in on the command line **or** fetched via a PKCS#11 / HSM URI.
- The `sign_reprovision_token.py` script refuses to run if the private
  key file mode is broader than `0600`.
- `factory_provision.py` never logs private-half material; it only
  records fingerprints.
- All scripts exit with **non-zero** on any cryptographic failure —
  fail closed.
