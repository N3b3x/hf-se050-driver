#!/usr/bin/env python3
"""Offline verifier for SE050-signed telemetry messages.

Pairs with ``stage_telemetry.hpp::SignPayload``. The device publishes a
JSON envelope of the shape::

    {
      "thing": "hf-medical-0001",
      "ts":    1713550000,
      "fw":    "1.2.3",
      "ch":    0,
      "mv":    1234,
      "sig":   "<base64 ECDSA-P256 DER over the canonical payload>"
    }

The canonical payload bytes that the device signs are the JSON object
with the ``sig`` field *removed*, serialised with sorted keys and no
whitespace (``json.dumps(payload, sort_keys=True, separators=(',',':'))``).
Any cloud-side consumer that wants to verify end-to-end authenticity
re-serialises the same way and verifies against the device's public key.

Usage::

    python3 verify_telemetry.py \\
        --pubkey device_0001.pub.pem \\
        --message captured.json
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write(
        "error: pip install --user cryptography\n"
    )
    sys.exit(2)


def canonical_bytes(payload: dict) -> bytes:
    clone = {k: v for k, v in payload.items() if k != "sig"}
    return json.dumps(clone, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_message(pub: ec.EllipticCurvePublicKey, payload: dict) -> None:
    sig_b64 = payload.get("sig")
    if not sig_b64:
        raise ValueError("message missing 'sig' field")
    sig = base64.b64decode(sig_b64)
    pub.verify(sig, canonical_bytes(payload), ec.ECDSA(hashes.SHA256()))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--pubkey", required=True, help="device public key PEM")
    p.add_argument("--message", required=True,
                   help="JSON file containing the captured telemetry message")
    args = p.parse_args(argv)

    pub = serialization.load_pem_public_key(Path(args.pubkey).read_bytes())
    if not isinstance(pub, ec.EllipticCurvePublicKey) or \
       not isinstance(pub.curve, ec.SECP256R1):
        sys.stderr.write("error: expected a P-256 ECDSA public key\n")
        return 1

    payload = json.loads(Path(args.message).read_text())
    try:
        verify_message(pub, payload)
    except InvalidSignature:
        sys.stderr.write("FAIL — signature does not verify\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"FAIL — {e}\n")
        return 1
    print(f"OK — thing={payload.get('thing')!r}, ts={payload.get('ts')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
