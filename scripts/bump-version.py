#!/usr/bin/env python3
"""Bump the project version in pyproject.toml + dns_healthcheck/__init__.py.

Usage:
    python scripts/bump-version.py 0.5.0
    python scripts/bump-version.py patch     # 0.4.0 -> 0.4.1
    python scripts/bump-version.py minor     # 0.4.0 -> 0.5.0
    python scripts/bump-version.py major     # 0.4.0 -> 1.0.0

The script keeps both files in sync and refuses to bump downwards.
Run before tagging a release: `git tag v$(python scripts/bump-version.py --print)`.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "dns_healthcheck" / "__init__.py"

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def read_current() -> tuple[int, int, int]:
    text = PYPROJECT.read_text()
    m = re.search(r'^version = "([^"]+)"', text, flags=re.MULTILINE)
    if not m:
        raise SystemExit('could not locate `version = "..."` in pyproject.toml')
    pieces = VERSION_RE.match(m.group(1))
    if not pieces:
        raise SystemExit(f"version {m.group(1)!r} is not semver MAJOR.MINOR.PATCH")
    return int(pieces[1]), int(pieces[2]), int(pieces[3])


def compute_new(current: tuple[int, int, int], bump: str) -> tuple[int, int, int]:
    maj, mn, pa = current
    if bump == "patch":
        return maj, mn, pa + 1
    if bump == "minor":
        return maj, mn + 1, 0
    if bump == "major":
        return maj + 1, 0, 0
    m = VERSION_RE.match(bump)
    if not m:
        raise SystemExit(f"argument {bump!r} must be patch/minor/major or X.Y.Z")
    new = int(m[1]), int(m[2]), int(m[3])
    if new <= current:
        raise SystemExit(f"refusing to bump downwards: {bump} <= {'.'.join(map(str, current))}")
    return new


def write(new_version: str) -> None:
    py = PYPROJECT.read_text()
    py = re.sub(r'^version = "[^"]+"', f'version = "{new_version}"', py, count=1, flags=re.MULTILINE)
    PYPROJECT.write_text(py)
    init = INIT.read_text()
    init = re.sub(r'^__version__ = "[^"]+"', f'__version__ = "{new_version}"', init, count=1, flags=re.MULTILINE)
    INIT.write_text(init)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bump", nargs="?", help="patch|minor|major|X.Y.Z")
    parser.add_argument("--print", action="store_true", help="print the current version and exit")
    args = parser.parse_args()

    current = read_current()
    cur_str = ".".join(map(str, current))
    if args.print:
        print(cur_str)
        return 0
    if not args.bump:
        parser.print_help()
        return 2
    new = compute_new(current, args.bump)
    new_str = ".".join(map(str, new))
    write(new_str)
    print(f"bumped {cur_str} -> {new_str}")
    print("next: git add pyproject.toml dns_healthcheck/__init__.py && git commit && git tag v" + new_str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
