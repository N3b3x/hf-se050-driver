#!/usr/bin/env python3
"""Host-side unit tests for the re-provisioning token format.

These mirror the security unit-test table in SECURITY.md §9.1. Run::

    python3 -m pytest tools/tests -q

The tests do not need a real SE050. They exercise the pure-Python
signer plus an in-memory re-implementation of the device-side parser
invariants; keeping those two in lock-step is what catches protocol
drift between factory tool and firmware.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import sign_reprovision_token as signer  # noqa: E402

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


# -- device-side parser reimplementation (tracks stage_provisioning.hpp) ---
MAGIC = b"HFRV"
HEADER_LEN = 48
UID_LEN = 18


class DeviceVerifier:
    """In-memory mirror of RequestReprovisioning().

    Stores the NVM counter and the authority public key. Exposes a single
    ``accept(token, chip_uid)`` entry point that returns True on success
    and updates the counter, or False on any protocol failure.
    """

    def __init__(self, authority_pub: ec.EllipticCurvePublicKey,
                 chip_uid: bytes, initial_counter: int = 0):
        self.pub = authority_pub
        self.chip_uid = chip_uid.ljust(UID_LEN, b"\x00")
        self.counter = initial_counter

    def accept(self, token: bytes) -> bool:
        if len(token) < HEADER_LEN + 64:
            return False
        if token[:4] != MAGIC:
            return False
        ctr = struct.unpack("<I", token[4:8])[0]
        if ctr <= self.counter:
            return False
        token_uid = token[8:26]
        if token_uid != self.chip_uid:
            return False
        header, sig = token[:HEADER_LEN], token[HEADER_LEN:]
        try:
            self.pub.verify(sig, header, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        self.counter = ctr
        return True


# -- fixtures --------------------------------------------------------------
@pytest.fixture
def authority():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def uid():
    return bytes(range(UID_LEN))


def _token(auth_priv, counter: int, uid: bytes) -> bytes:
    header = signer._build_header(counter, uid.ljust(UID_LEN, b"\x00"))
    sig = auth_priv.sign(header, ec.ECDSA(hashes.SHA256()))
    return header + sig


# -- tests -----------------------------------------------------------------
def test_happy_path_accepts(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=0)
    tok = _token(authority, counter=1, uid=uid)
    assert dev.accept(tok) is True
    assert dev.counter == 1


def test_replay_rejected(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=0)
    tok = _token(authority, counter=5, uid=uid)
    assert dev.accept(tok) is True
    # Replaying the same token must fail (counter no longer strictly greater).
    assert dev.accept(tok) is False


def test_counter_rollback_rejected(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=10)
    assert dev.accept(_token(authority, counter=9, uid=uid)) is False
    assert dev.accept(_token(authority, counter=10, uid=uid)) is False  # equal also rejected


def test_wrong_uid_rejected(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=0)
    other = bytes(UID_LEN)
    assert dev.accept(_token(authority, counter=1, uid=other)) is False


def test_wrong_signer_rejected(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=0)
    attacker = ec.generate_private_key(ec.SECP256R1())
    assert dev.accept(_token(attacker, counter=1, uid=uid)) is False


def test_bad_magic_rejected(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=0)
    tok = bytearray(_token(authority, counter=1, uid=uid))
    tok[0] ^= 0xFF
    assert dev.accept(bytes(tok)) is False


def test_bit_flip_in_body_rejected(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=0)
    tok = bytearray(_token(authority, counter=1, uid=uid))
    tok[25] ^= 0x01   # flip a reserved byte — part of signed region
    assert dev.accept(bytes(tok)) is False


def test_truncated_token_rejected(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=0)
    tok = _token(authority, counter=1, uid=uid)
    assert dev.accept(tok[:-10]) is False


def test_counter_equal_rejected(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=7)
    # "strictly greater" invariant: ctr == nvm_ctr must be rejected.
    assert dev.accept(_token(authority, counter=7, uid=uid)) is False


def test_sequential_bumps_accepted(authority, uid):
    dev = DeviceVerifier(authority.public_key(), uid, initial_counter=0)
    for n in [1, 2, 5, 100, 101]:
        assert dev.accept(_token(authority, counter=n, uid=uid)) is True
    assert dev.counter == 101
