"""AWS Lambda handler — cloud-side signature verifier for SE050 telemetry.

Wiring (S3 object-created trigger, one object = one MQTT payload)::

    MQTT → IoT Rule → Kinesis Firehose → S3 (object-lock)
                                          │
                                          └─→ Lambda (this file)
                                              ├─ OK   → Timestream write
                                              └─ FAIL → SNS alert + quarantine

The device public key is looked up in **AWS IoT Core's registry** — the
``thing`` field of the payload identifies which device, and the
registry holds the certificate that was issued at factory time
(§3 in SECURITY.md). This means key rotation requires no Lambda
redeploy.

Environment variables
---------------------
``ALERT_SNS_TOPIC_ARN`` (optional) — notified on verification failure.
``AWS_REGION``                   — set by Lambda runtime automatically.

IAM permissions required
------------------------
``s3:GetObject`` on the bucket,
``iot:DescribeThing``, ``iot:ListThingPrincipals``, ``iot:DescribeCertificate``,
``sns:Publish`` on the alert topic.

This file is deliberately self-contained so it can be deployed as a
single-file Lambda. For larger codebases migrate to a layer.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any

import boto3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate

log = logging.getLogger()
log.setLevel(logging.INFO)

_s3 = boto3.client("s3")
_iot = boto3.client("iot")
_sns = boto3.client("sns")

_ALERT_TOPIC = os.environ.get("ALERT_SNS_TOPIC_ARN")


def _canonical(payload: dict) -> bytes:
    clone = {k: v for k, v in payload.items() if k != "sig"}
    return json.dumps(clone, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _lookup_device_pubkey(thing_name: str) -> ec.EllipticCurvePublicKey:
    """Resolve a thing name → device cert → P-256 public key."""
    principals = _iot.list_thing_principals(thingName=thing_name)["principals"]
    for arn in principals:
        # Principals for cert-auth look like: arn:aws:iot:...:cert/<certId>
        if ":cert/" not in arn:
            continue
        cert_id = arn.rsplit("/", 1)[-1]
        desc = _iot.describe_certificate(certificateId=cert_id)
        pem = desc["certificateDescription"]["certificatePem"].encode()
        cert = load_pem_x509_certificate(pem)
        pub = cert.public_key()
        if isinstance(pub, ec.EllipticCurvePublicKey) and \
           isinstance(pub.curve, ec.SECP256R1):
            return pub
    raise LookupError(f"no P-256 cert found for thing {thing_name!r}")


def _alert(thing: str, reason: str) -> None:
    if not _ALERT_TOPIC:
        return
    _sns.publish(
        TopicArn=_ALERT_TOPIC,
        Subject=f"SE050 telemetry signature FAIL for {thing}",
        Message=f"thing={thing}\nreason={reason}\n",
    )


def _verify_object(bucket: str, key: str) -> dict[str, Any]:
    body = _s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    payload = json.loads(body)
    thing = payload.get("thing", "<unknown>")
    sig_b64 = payload.get("sig")
    if not sig_b64:
        _alert(thing, "missing sig")
        raise ValueError("missing sig")
    sig = base64.b64decode(sig_b64)

    pub = _lookup_device_pubkey(thing)
    try:
        pub.verify(sig, _canonical(payload), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        _alert(thing, "bad signature")
        raise
    log.info("verified thing=%s ts=%s key=%s", thing, payload.get("ts"), key)
    return payload


def lambda_handler(event: dict, context: Any) -> dict:  # pragma: no cover
    results: list[dict] = []
    failures = 0
    for rec in event.get("Records", []):
        bucket = rec["s3"]["bucket"]["name"]
        key = rec["s3"]["object"]["key"]
        try:
            payload = _verify_object(bucket, key)
            results.append({"key": key, "ok": True, "thing": payload.get("thing")})
        except Exception as e:
            failures += 1
            log.error("verify failed for s3://%s/%s : %s", bucket, key, e)
            results.append({"key": key, "ok": False, "err": str(e)})
    return {"verified": len(results) - failures, "failed": failures,
            "results": results}
