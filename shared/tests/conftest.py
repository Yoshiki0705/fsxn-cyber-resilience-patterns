"""Pytest configuration for shared library tests."""
from __future__ import annotations

import sys
from pathlib import Path

# Add shared solutions directory to path
PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "shared"))
