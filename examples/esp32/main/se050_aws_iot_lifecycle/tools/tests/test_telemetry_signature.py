#!/usr/bin/env python3
"""Round-trip test for the telemetry signature canonical form.

SECURITY.md §9.1 row: "Telemetry signature verifies offline".
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import verify_telemetry  # noqa: E402

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


@pytest.fixture
def device_key():
    return ec.generate_private_key(ec.SECP256R1())


def _sign_payload(device_key, payload: dict) -> dict:
    canonical = verify_telemetry.canonical_bytes(payload)
    sig = device_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    out = dict(payload)
    out["sig"] = base64.b64encode(sig).decode()
    return out


def test_happy_path(device_key):
    payload = {"thing": "dev-1", "ts": 123, "fw": "1.0.0", "ch": 0, "mv": 1000}
    signed = _sign_payload(device_key, payload)
    verify_telemetry.verify_message(device_key.public_key(), signed)


def test_tampered_field_rejected(device_key):
    payload = {"thing": "dev-1", "ts": 123, "fw": "1.0.0", "ch": 0, "mv": 1000}
    signed = _sign_payload(device_key, payload)
    signed["mv"] = 2000   # tamper after signing
    with pytest.raises(Exception):
        verify_telemetry.verify_message(device_key.public_key(), signed)


def test_missing_sig_rejected(device_key):
    payload = {"thing": "dev-1", "ts": 123, "mv": 1000}
    with pytest.raises(ValueError):
        verify_telemetry.verify_message(device_key.public_key(), payload)


def test_wrong_key_rejected():
    k1 = ec.generate_private_key(ec.SECP256R1())
    k2 = ec.generate_private_key(ec.SECP256R1())
    payload = {"thing": "dev-1", "ts": 123, "mv": 1000}
    signed = _sign_payload(k1, payload)
    with pytest.raises(Exception):
        verify_telemetry.verify_message(k2.public_key(), signed)


def test_canonical_form_key_order_independent(device_key):
    # Two payloads with same content but different construction order
    # must produce identical canonical bytes.
    p1 = {"thing": "x", "ts": 1, "mv": 2}
    p2 = {"mv": 2, "ts": 1, "thing": "x"}
    assert verify_telemetry.canonical_bytes(p1) == verify_telemetry.canonical_bytes(p2)
