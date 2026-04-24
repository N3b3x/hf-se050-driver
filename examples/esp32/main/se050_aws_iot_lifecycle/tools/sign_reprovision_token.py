#!/usr/bin/env python3
"""Sign a 120-byte re-provisioning token for the SE050 lifecycle example.

Token layout (matches ``stage_provisioning.hpp``)::

    offset  size  field
      0      4    magic      "HFRV"  (little-endian 0x56524648)
      4      4    counter    uint32 LE, strictly greater than the on-chip counter
      8     18    device_uid 18-byte SE050 unique ID (zero-padded if shorter)
     26     22    reserved   zero bytes (future: expiry + reason code)
     48     72    signature  ECDSA-P256 DER over bytes [0..47]

Usage
-----

Generate a signer key once on your air-gapped HSM host::

    python3 sign_reprovision_token.py genkey --out reprov_authority.pem

Install the corresponding **public** key on the device (factory flow):

    openssl ec -in reprov_authority.pem -pubout -out reprov_authority.pub.pem

Sign a token for a specific device::

    python3 sign_reprovision_token.py sign \\
        --key reprov_authority.pem \\
        --uid  00112233445566778899AABBCCDDEEFF0011 \\
        --counter 7 \\
        --out device_0001.reprov.bin

The resulting 120 B blob is what the field device's
``RequestReprovisioning()`` accepts.

This script intentionally has no network / cloud dependency. Run it on
a fully air-gapped host; move the output file via write-once media.
"""
from __future__ import annotations

import argparse
import os
import stat
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    sys.stderr.write(
        "error: this tool requires the 'cryptography' package.\n"
        "       python3 -m pip install --user cryptography\n"
    )
    sys.exit(2)

# -- constants -------------------------------------------------------------
MAGIC = b"HFRV"          # bytes 0..3, matches kReprovisionMagic
HEADER_LEN = 48          # bytes covered by the signature
TOKEN_LEN_MIN = HEADER_LEN + 64   # smallest legal DER P-256 signature
TOKEN_LEN_MAX = HEADER_LEN + 72   # largest typical DER P-256 signature
UID_LEN = 18

# -- helpers ---------------------------------------------------------------
def _enforce_0600(path: Path) -> None:
    """Refuse to read a private key that is group/world-readable."""
    if os.name != "posix":
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        sys.stderr.write(
            f"error: {path} has mode 0o{mode:03o}; expected 0o600. "
            "A reprov-authority key must not be group/world-readable.\n"
        )
        sys.exit(3)


def _parse_uid(hex_str: str) -> bytes:
    """Parse a hex device UID, zero-pad or truncate to UID_LEN."""
    raw = bytes.fromhex(hex_str.strip().replace(" ", ""))
    if len(raw) > UID_LEN:
        sys.stderr.write(f"error: UID longer than {UID_LEN} bytes\n")
        sys.exit(4)
    return raw.ljust(UID_LEN, b"\x00")


def _build_header(counter: int, uid: bytes) -> bytes:
    if counter < 1 or counter > 0xFFFFFFFF:
        sys.stderr.write("error: counter must be in [1, 2^32-1]\n")
        sys.exit(4)
    reserved = b"\x00" * 22
    return MAGIC + struct.pack("<I", counter) + uid + reserved


# -- commands --------------------------------------------------------------
def cmd_genkey(args: argparse.Namespace) -> int:
    """Generate a new P-256 signer key and write it with 0600 perms."""
    out = Path(args.out)
    if out.exists() and not args.force:
        sys.stderr.write(f"error: {out} exists; pass --force to overwrite\n")
        return 1
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Create with tight perms, then write.
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    print(f"wrote {out} (mode 0600)")
    print(f"public key (uncompressed, 65 B, install to kReprovisionAuthorityKey):")
    print("  " + pub.hex())
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a reprov token for a specific device."""
    key_path = Path(args.key)
    if not key_path.is_file():
        sys.stderr.write(f"error: key file not found: {key_path}\n")
        return 1
    _enforce_0600(key_path)

    with key_path.open("rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or \
       not isinstance(key.curve, ec.SECP256R1):
        sys.stderr.write("error: key is not P-256 ECDSA\n")
        return 1

    uid = _parse_uid(args.uid)
    header = _build_header(args.counter, uid)
    sig = key.sign(header, ec.ECDSA(hashes.SHA256()))
    token = header + sig

    if not (TOKEN_LEN_MIN <= len(token) <= TOKEN_LEN_MAX):
        # DER sigs can be 70..72 B depending on r,s high bits.
        # The device parser handles variable-length DER; warn only.
        sys.stderr.write(
            f"warning: token length {len(token)} outside typical "
            f"[{TOKEN_LEN_MIN},{TOKEN_LEN_MAX}]\n"
        )

    out = Path(args.out)
    out.write_bytes(token)
    print(f"wrote {out} ({len(token)} bytes)")
    print(f"  magic    : {MAGIC.hex()}")
    print(f"  counter  : {args.counter}")
    print(f"  uid      : {uid.hex()}")
    print(f"  sig_len  : {len(sig)}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Local sanity-check: verify a token against the authority public key.

    Useful for CI to prove the signer + token file + pubkey agree *before*
    you ship them to a device.
    """
    pub_pem = Path(args.pubkey).read_bytes()
    pub = serialization.load_pem_public_key(pub_pem)
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        sys.stderr.write("error: public key is not ECDSA\n")
        return 1

    token = Path(args.token).read_bytes()
    if len(token) < TOKEN_LEN_MIN:
        sys.stderr.write(f"error: token too short: {len(token)}\n")
        return 1
    if token[:4] != MAGIC:
        sys.stderr.write("error: bad magic\n")
        return 1

    header, sig = token[:HEADER_LEN], token[HEADER_LEN:]
    try:
        pub.verify(sig, header, ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        sys.stderr.write(f"error: signature failed: {e}\n")
        return 1
    counter = struct.unpack("<I", token[4:8])[0]
    uid = token[8:26]
    print(f"OK — counter={counter}, uid={uid.hex()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    pg = sub.add_parser("genkey", help="generate a new authority signing key")
    pg.add_argument("--out", required=True, help="PEM output path (chmod 0600)")
    pg.add_argument("--force", action="store_true", help="overwrite existing")
    pg.set_defaults(func=cmd_genkey)

    ps = sub.add_parser("sign", help="sign a reprov token for a device")
    ps.add_argument("--key", required=True, help="authority private PEM (0600)")
    ps.add_argument("--uid", required=True, help="device UID as hex (<=18 B)")
    ps.add_argument("--counter", type=int, required=True,
                    help="counter, strictly > on-device kReprovisionCounter")
    ps.add_argument("--out", required=True, help="output binary token path")
    ps.set_defaults(func=cmd_sign)

    pv = sub.add_parser("verify", help="verify a token against a public PEM")
    pv.add_argument("--pubkey", required=True, help="authority public PEM")
    pv.add_argument("--token", required=True, help="token binary to verify")
    pv.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
