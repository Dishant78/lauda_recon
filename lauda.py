"""Convenience launcher for a source checkout.

For an installed project use ``lauda-recon``. This launcher lets contributors
run ``python lauda.py`` without first installing the package in editable mode.
"""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from lauda_recon.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
