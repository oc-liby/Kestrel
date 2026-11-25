#!/usr/bin/env python3
"""数据校验：CVE YAML 可解析、组件内 CVE 唯一、index.json 一致、数据集许可声明覆盖。

用法：
  python tools/check_data.py --check   # 只校验（默认行为）
  python tools/check_data.py           # 同上

需要 PyYAML（仅开发/CI 依赖；运行时脚本仍零依赖）。
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
DATASETS = ROOT / "skills/ai-mcp-security/data/eval-datasets"
NOTICE = ROOT / "THIRD_PARTY_NOTICES.md"


def check_yaml(issues):
    by_comp = {}
    total = 0
    for f in sorted(DATA.rglob("*.yaml")):
        total += 1
        try:
            d = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            issues.append("%s: 解析失败 %s" % (f.relative_to(ROOT), str(e)[:100]))
            continue
        if not isinstance(d, dict):
            issues.append("%s: 顶层不是映射" % f.relative_to(ROOT))
            continue
        info = d.get("info") or {}
        cve = str(info.get("cve", "")).strip()
        comp = f.parent.name
        if cve:
            key = (comp, cve)
            if key in by_comp:
                issues.append("%s: 组件内 CVE 重复 %s" % (comp, cve))
            by_comp[key] = f
        rule = str(d.get("rule", "") or "")
        if rule and rule.count('"') % 2:
            issues.append("%s: rule 引号不配平" % f.relative_to(ROOT))
    return total


def check_index(issues):
    index_path = DATA / "index.json"
    if not index_path.exists():
        issues.append("缺 index.json")
        return
    idx = json.loads(index_path.read_text(encoding="utf-8"))
    dirs = {p.name for p in DATA.iterdir() if p.is_dir()}
    for c in idx.get("components", []):
        d = c.get("dir")
        if d not in dirs:
            issues.append("index.json 组件目录不存在: %s" % d)
            continue
        actual = sum(1 for _ in (DATA / d).glob("*.yaml"))
        if actual != c.get("cves"):
            issues.append("index.json 计数不一致: %s %s != %s"
                          % (d, c.get("cves"), actual))
    if idx.get("total_components") != len(dirs):
        issues.append("index.json total_components=%s，实际目录 %s"
                      % (idx.get("total_components"), len(dirs)))


def check_datasets(issues):
    if not NOTICE.exists():
        issues.append("缺 THIRD_PARTY_NOTICES.md")
        return
    notice = NOTICE.read_text(encoding="utf-8")
    for f in sorted(DATASETS.glob("*.json")):
        if f.name not in notice:
            issues.append("NOTICE 未覆盖数据集: %s" % f.name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只校验（默认行为）")
    ap.parse_args()
    issues = []
    total = check_yaml(issues)
    check_index(issues)
    check_datasets(issues)

    if issues:
        print("FAIL: %d issue(s)" % len(issues))
        for i in issues[:50]:
            print("-", i)
        return 1
    print("PASS: %d YAML, index 一致, 数据集许可已声明" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
