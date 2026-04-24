#!/usr/bin/env bash
# Generate API HTML from _config/Doxyfile (same entry point as CI: ci-docs-publish.yml).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if ! command -v doxygen >/dev/null 2>&1; then
  echo "ERROR: doxygen is not installed or not on PATH." >&2
  echo "  Debian/Ubuntu: sudo apt install doxygen graphviz" >&2
  echo "  Then re-run: $0" >&2
  exit 1
fi
echo "Running doxygen from: $ROOT"
doxygen _config/Doxyfile
echo "Done. Default HTML output: docs/html/ (OUTPUT_DIRECTORY=docs, HTML_OUTPUT=html in _config/Doxyfile)."
