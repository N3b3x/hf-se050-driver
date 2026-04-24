"""Pytest config so the tools/ modules are importable without install."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
