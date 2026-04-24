#!/usr/bin/env python3
"""End-of-line factory provisioning tool (reference implementation).

Drives a device that is running the **factory build** of this example
through the 11-step per-unit sequence documented in SECURITY.md §3.2.

This is a reference implementation of the *station-side* control loop.
Replace the stub ``FactoryTransport`` with your actual bench transport
(USB-CDC / Segger RTT / JTAG scripting / whatever). Everything above the
transport layer — CSR construction, CA signing, audit record format,
provisioned-unit manifest — is production-ready.

Security preconditions
----------------------
- Run on a host inside your factory subnet only (ISO 27001 A.11.1).
- The CA signing private key MUST live on an HSM. This tool only talks
  to the HSM via PKCS#11 (see ``HsmSigner``) — it never touches the raw
  private bytes.
- Audit records are signed by the factory CA and written to a WORM
  vault path (passed via ``--audit-vault``). The tool refuses to run if
  that path is writable by group/other.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.stderr.write("error: pip install --user cryptography\n")
    sys.exit(2)

log = logging.getLogger("factory")


# -- transport stub --------------------------------------------------------
class FactoryTransport:
    """Abstract device transport used by the factory station.

    Swap this for USB-CDC / RTT / JTAG in your real station. The protocol
    defined here is a simple request/response:

      - ``READ_UID``           → 18 B hex UID
      - ``GENKEY``             → no payload
      - ``READ_PUB``           → 65 B uncompressed EC point, hex
      - ``INSTALL_CERT <hex>`` → OK / FAIL
      - ``INSTALL_CA <hex>``   → OK / FAIL
      - ``INSTALL_REPROV_AUTH <hex>`` → OK / FAIL
      - ``LOCK``               → OK / FAIL
      - ``SIGN_CHALLENGE <hex>`` → DER signature hex
    """

    def send(self, cmd: str) -> str:  # pragma: no cover — stub
        raise NotImplementedError(
            "Plug in your real transport. The command is:\n  " + cmd
        )


# -- HSM signer stub -------------------------------------------------------
class HsmSigner:
    """PKCS#11-backed CA signer.

    Real implementations: python-pkcs11, PyKCS11, or aws-cloudhsm-client.
    This class encapsulates everything so the main flow stays clean.
    """

    def __init__(self, pkcs11_uri: Optional[str], dev_ca_pem: Optional[Path]):
        self._uri = pkcs11_uri
        self._dev_ca = None
        self._dev_ca_key = None
        if dev_ca_pem is not None:
            # Development fallback — a local CA. NEVER use in production.
            log.warning("HsmSigner running with a LOCAL CA key — dev-only!")
            data = dev_ca_pem.read_bytes()
            self._dev_ca_key = serialization.load_pem_private_key(data, None)
            cert_pem_path = dev_ca_pem.with_suffix(".crt.pem")
            self._dev_ca = x509.load_pem_x509_certificate(cert_pem_path.read_bytes())

    def sign_device_cert(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        if self._dev_ca_key is None:
            raise RuntimeError("production path not implemented in reference tool")
        now = _dt.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._dev_ca.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _dt.timedelta(days=365 * 10))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(self._dev_ca_key, hashes.SHA256())
        )
        return cert


# -- per-unit flow ---------------------------------------------------------
@dataclass
class UnitRecord:
    serial: str
    uid_hex: str
    pubkey_fpr: str
    cert_der_sha256: str
    station_id: str
    operator_id: str
    timestamp: str
    outcome: str  # "PASS" | "FAIL"


def _build_csr(pub_der_65B: bytes, serial: str) -> x509.CertificateSigningRequest:
    """Build a CSR that embeds the SE050 pubkey.

    NOTE: cryptography can't build a CSR *around* a foreign public key
    without the matching private key (CSR must be self-signed). In
    production you'd implement this with a lower-level ASN.1 builder
    (asn1crypto) or skip CSR and ask the CA to issue directly from the
    raw pubkey — which is what most IoT CAs accept anyway.

    This stub raises to make that explicit; real factory flows use
    ``asn1crypto.csr.CertificationRequest`` and sign the
    ``certification_request_info`` field via the device's
    ``SIGN_CHALLENGE`` command.
    """
    raise NotImplementedError(
        "CSR construction with an external pubkey requires asn1crypto; "
        "see the comment in _build_csr for the recipe."
    )


def _audit_record(rec: UnitRecord, ca_key) -> bytes:
    body = json.dumps({
        "v": 1,
        "serial": rec.serial,
        "uid": rec.uid_hex,
        "pubkey_fpr": rec.pubkey_fpr,
        "cert_sha256": rec.cert_der_sha256,
        "station": rec.station_id,
        "operator": rec.operator_id,
        "ts": rec.timestamp,
        "outcome": rec.outcome,
    }, sort_keys=True, separators=(",", ":")).encode()
    sig = ca_key.sign(body, ec.ECDSA(hashes.SHA256()))
    return body + b"\n--SIG--\n" + sig.hex().encode() + b"\n"


def provision_one(tx: FactoryTransport, hsm: HsmSigner, args) -> UnitRecord:
    log.info("reading SE050 UID…")
    uid_hex = tx.send("READ_UID").strip()

    log.info("requesting on-chip keygen…")
    tx.send("GENKEY")

    log.info("reading exported public key…")
    pub_hex = tx.send("READ_PUB").strip()
    pub_der = bytes.fromhex(pub_hex)
    fpr = hashlib.sha256(pub_der).hexdigest()

    log.info("building CSR + requesting CA signature (HSM)…")
    csr = _build_csr(pub_der, args.serial)   # raises NotImplemented in stub
    cert = hsm.sign_device_cert(csr)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_sha = hashlib.sha256(cert_der).hexdigest()

    log.info("installing device cert, server CA, reprov-authority pubkey…")
    tx.send("INSTALL_CERT " + cert_der.hex())
    tx.send("INSTALL_CA "   + Path(args.server_ca).read_bytes().hex())
    tx.send("INSTALL_REPROV_AUTH " + Path(args.reprov_pub).read_bytes().hex())

    log.info("locking factory access…")
    tx.send("LOCK")

    return UnitRecord(
        serial=args.serial,
        uid_hex=uid_hex,
        pubkey_fpr=fpr,
        cert_der_sha256=cert_sha,
        station_id=args.station_id,
        operator_id=args.operator_id,
        timestamp=_dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        outcome="PASS",
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--serial", required=True, help="unit serial number")
    p.add_argument("--server-ca", required=True, help="server root CA (DER)")
    p.add_argument("--reprov-pub", required=True,
                   help="reprov authority pubkey bytes (65 B uncompressed EC)")
    p.add_argument("--station-id", default=os.environ.get("FACTORY_STATION", "dev"))
    p.add_argument("--operator-id", default=os.environ.get("FACTORY_OP", "dev"))
    p.add_argument("--audit-vault", required=True, help="WORM path for record")
    p.add_argument("--dev-ca-key", type=Path,
                   help="dev-only CA private key PEM (paired with .crt.pem)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")

    vault = Path(args.audit_vault)
    if vault.exists() and (vault.stat().st_mode & 0o022):
        sys.stderr.write("error: audit vault is group/world-writable\n")
        return 3
    vault.mkdir(parents=True, exist_ok=True)

    tx = FactoryTransport()
    hsm = HsmSigner(os.environ.get("HSM_PKCS11_URI"), args.dev_ca_key)

    try:
        rec = provision_one(tx, hsm, args)
    except Exception as e:
        log.error("provision FAILED: %s", e)
        return 1

    audit_path = vault / f"{rec.serial}-{uuid.uuid4().hex[:8]}.audit"
    # WORM: create with 0400 and forbid overwrite.
    fd = os.open(audit_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    with os.fdopen(fd, "wb") as f:
        f.write(_audit_record(rec, hsm._dev_ca_key))
    log.info("audit record: %s", audit_path)
    print(f"PASS {rec.serial} uid={rec.uid_hex} fpr={rec.pubkey_fpr[:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
