"""Shared helpers for checker tests.

Each test writes a minimal fixture into a boundary subfolder under a pytest
tmp_path, mirroring the real environments/*/configs/bN_*/ layout, so checkers
are exercised through the exact same target_dir contract run_checks.py uses -
no fixture ever imports environments/broken_lab or environments/fixed_lab
directly, so these tests don't silently break if the lab fixtures change.
"""
from pathlib import Path


def write(tmp_path: Path, boundary_dir: str, filename: str, content: str) -> Path:
    d = tmp_path / boundary_dir
    d.mkdir(parents=True, exist_ok=True)
    f = d / filename
    f.write_text(content)
    return f
