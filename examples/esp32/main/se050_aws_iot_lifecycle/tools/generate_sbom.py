#!/usr/bin/env python3
"""Minimal CycloneDX SBOM generator for the SE050 lifecycle example.

Produces a CycloneDX 1.5 JSON document listing:
  - Application metadata (name, version, authors)
  - Direct source components (this example's .cpp/.hpp)
  - External components parsed from ``idf_component.yml`` in the driver
  - mbedTLS / ESP-IDF version (read from environment)

Good enough to drop into an FDA submission's "Cybersecurity SBOM"
artifact. Real builds should also run ``cyclonedx-py`` or ``syft``
against the final ELF.

Usage::

    python3 generate_sbom.py --out sbom.cdx.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXAMPLE_DIR = HERE.parent                      # …/se050_aws_iot_lifecycle
DRIVER_ROOT = EXAMPLE_DIR.parents[3]           # …/hf-se050-driver
COMPONENT_YML = DRIVER_ROOT / "idf_component.yml"
APP_VERSION = os.environ.get("HF_APP_VERSION", "0.3.0")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _git_commit(path: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL, text=True).strip()
        return out or None
    except Exception:
        return None


def _component_from_source(src: Path) -> dict:
    return {
        "type": "file",
        "bom-ref": f"src:{src.name}",
        "name": src.name,
        "version": APP_VERSION,
        "hashes": [{"alg": "SHA-256", "content": _sha256(src)}],
        "purl": f"pkg:generic/{src.name}@{APP_VERSION}",
    }


def _external_components() -> list[dict]:
    """Parse direct dependencies from the driver's idf_component.yml."""
    if not COMPONENT_YML.is_file():
        return []
    try:
        import yaml  # optional
    except ImportError:
        # Degrade gracefully — line-based fallback good enough for the
        # ``dependencies:`` section of a standard idf_component.yml.
        deps: list[dict] = []
        in_deps = False
        for line in COMPONENT_YML.read_text().splitlines():
            s = line.rstrip()
            if s.startswith("dependencies:"):
                in_deps = True
                continue
            if in_deps and s and not s.startswith((" ", "\t")):
                break
            if in_deps and ":" in s:
                name = s.strip().split(":", 1)[0].strip()
                if name:
                    deps.append({"type": "library", "name": name,
                                 "version": "unspecified",
                                 "bom-ref": f"dep:{name}",
                                 "purl": f"pkg:espidf/{name}"})
        return deps
    doc = yaml.safe_load(COMPONENT_YML.read_text()) or {}
    out: list[dict] = []
    for name, meta in (doc.get("dependencies") or {}).items():
        ver = meta.get("version", "unspecified") if isinstance(meta, dict) else str(meta)
        out.append({"type": "library", "name": name, "version": ver,
                    "bom-ref": f"dep:{name}",
                    "purl": f"pkg:espidf/{name}@{ver}"})
    return out


def build_sbom() -> dict:
    sources = sorted([p for p in EXAMPLE_DIR.iterdir()
                      if p.suffix in {".cpp", ".hpp"} and p.is_file()])
    components = [_component_from_source(s) for s in sources]
    components += _external_components()

    # ESP-IDF + toolchain fingerprint
    idf_ver = os.environ.get("IDF_VERSION") or os.environ.get("IDF_BRANCH") or "unknown"
    components.append({
        "type": "framework", "name": "esp-idf", "version": idf_ver,
        "bom-ref": "framework:esp-idf",
        "purl": f"pkg:espidf/esp-idf@{idf_ver}",
    })
    components.append({
        "type": "library", "name": "mbedtls",
        "version": os.environ.get("MBEDTLS_VERSION", "bundled-with-esp-idf"),
        "bom-ref": "dep:mbedtls", "purl": "pkg:generic/mbedtls",
    })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"vendor": "hardfoc", "name": "generate_sbom.py",
                       "version": APP_VERSION}],
            "component": {
                "type": "application",
                "bom-ref": "app:se050_aws_iot_lifecycle",
                "name": "se050_aws_iot_lifecycle",
                "version": APP_VERSION,
                "properties": [{"name": "git.commit",
                                "value": _git_commit(DRIVER_ROOT) or "unknown"}],
            },
            "authors": [{"name": "hardfoc"}],
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--out", default="-", help="output file ('-' = stdout)")
    args = p.parse_args(argv)

    doc = build_sbom()
    blob = json.dumps(doc, indent=2)
    if args.out == "-":
        sys.stdout.write(blob + "\n")
    else:
        Path(args.out).write_text(blob + "\n")
        print(f"wrote {args.out} ({len(doc['components'])} components)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
