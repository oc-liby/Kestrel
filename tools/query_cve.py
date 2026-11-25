#!/usr/bin/env python3
"""薄封装：调用技能内的 query_cve.py（开发/CI 用；随技能安装的是 script 本体）。"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills/cve-triage/scripts"))

from query_cve import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
