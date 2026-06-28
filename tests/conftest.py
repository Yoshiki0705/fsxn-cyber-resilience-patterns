"""Pytest configuration — add solution directories to sys.path for imports."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root and solution directories to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "shared"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "event-driven-response" / "lambda"))
sys.path.insert(0, str(PROJECT_ROOT / "solutions" / "ontap-native" / "lambda"))
