#!/usr/bin/env python3
"""生成 CVE 查询索引与组件别名表。

用法：
  python tools/build_index.py          # 写 cve-index.json（aliases.json 不存在时创建初始表）
  python tools/build_index.py --check  # 只校验索引是否最新

需要 PyYAML（仅开发/CI 依赖）。
"""
import argparse
import json
import sys
import pathlib

try:
    import yaml
except ImportError:
    sys.exit("需要 PyYAML：pip install pyyaml（仅开发/CI 依赖）")

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "skills/cve-triage/data/aig-vuln"
INDEX = DATA / "cve-index.json"
ALIASES = DATA / "aliases.json"

INITIAL_ALIASES = {
    "schema_version": 1,
    "aliases": {
        "openwebui": "open-webui",
        "lobehub": "lobechat",
        "litellm": "LiteLLM",
    },
}


def build():
    entries = []
    advisories = []
    total = 0
    for f in sorted(DATA.rglob("*.yaml")):
        total += 1
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            continue
        info = d.get("info") or {}
        cve = str(info.get("cve", "")).strip()
        name = str(info.get("name", "") or f.parent.name)
        severity = str(info.get("severity", "")).upper()
        rule = str(d.get("rule", "") or "")
        rel = f.relative_to(DATA).as_posix()
        item = {
            "cve": cve,
            "component": name,
            "component_dir": f.parent.name,
            "severity": severity,
            "rule": rule,
            "path": rel,
        }
        if cve.upper().startswith("CVE-"):
            entries.append(item)
        else:
            item["kind"] = "advisory"
            advisories.append(item)
    return {
        "schema_version": 1,
        "generated_from": "data/aig-vuln/**/*.yaml",
        "total": total,
        "entries": entries,
        "advisories": advisories,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    idx = build()
    text = json.dumps(idx, ensure_ascii=False, indent=1, sort_keys=False) + "\n"

    if args.check:
        current = INDEX.read_text(encoding="utf-8") if INDEX.exists() else ""
        if current != text:
            print("FAIL: cve-index.json 不是最新，运行 python tools/build_index.py")
            return 1
        print("PASS: cve-index.json 最新（%d CVE + %d advisory）"
              % (len(idx["entries"]), len(idx["advisories"])))
        return 0

    INDEX.write_text(text, encoding="utf-8", newline="\n")
    if not ALIASES.exists():
        ALIASES.write_text(json.dumps(INITIAL_ALIASES, ensure_ascii=False, indent=1) + "\n",
                           encoding="utf-8", newline="\n")
        print("已创建 aliases.json")
    print("已生成 cve-index.json：%d CVE + %d advisory（共 %d）"
          % (len(idx["entries"]), len(idx["advisories"]), idx["total"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
