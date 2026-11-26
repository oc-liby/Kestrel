#!/usr/bin/env python3
"""契约校验：frontmatter 必填字段、依赖图、跨技能引用方向。

用法：
  python tools/check_contracts.py            # 默认：frontmatter + 依赖图 FAIL，跨技能引用 WARN
  python tools/check_contracts.py --strict-refs  # 全下沉后 CI 使用：跨技能引用也 FAIL
"""
import argparse
import re
import sys
import pathlib

try:
    import yaml
except ImportError:
    sys.exit("需要 PyYAML：pip install pyyaml（仅开发/CI 依赖）")

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
PHASE_ENUM = {"flow", "recon", "vuln-discovery", "exploitation",
              "post-exploitation", "reporting", "cross-cutting"}
LAYER_ENUM = {"constitution", "flow", "skill", "knowledge"}
RISK_ENUM = {"none", "low", "medium", "high"}


def parse_frontmatter(path):
    """返回 (frontmatter dict | None, 错误信息 | None)。"""
    text = path.read_text(encoding="utf-8")
    m = re.match(r"(?s)^---\n(.*?)\n---\n", text)
    if not m:
        return None, "无 frontmatter"
    try:
        return yaml.safe_load(m.group(1)) or {}, None
    except yaml.YAMLError as e:
        return None, "frontmatter 解析失败: %s" % str(e)[:120]


def collect():
    metas = {}
    issues = []
    for d in sorted(p for p in SKILLS.iterdir() if p.is_dir()):
        md = d / "SKILL.md"
        if not md.exists():
            issues.append("%s: 缺 SKILL.md" % d.name)
            continue
        fm, err = parse_frontmatter(md)
        if err:
            issues.append("%s: %s" % (d.name, err))
            continue
        name = fm.get("name")
        meta = fm.get("metadata") or {}
        if name != d.name:
            issues.append("%s: name=%r 与目录名不一致" % (d.name, name))
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(meta.get("version", ""))):
            issues.append("%s: version 非法（应为 X.Y.Z）" % d.name)
        if not isinstance(meta.get("entry"), bool):
            issues.append("%s: entry 必须是布尔" % d.name)
        requires = meta.get("requires")
        if not isinstance(requires, list):
            issues.append("%s: requires 必须是列表" % d.name)
            requires = []
        triggers = meta.get("triggers")
        if not isinstance(triggers, list):
            issues.append("%s: triggers 必须是列表" % d.name)
            triggers = []
        # 可选枚举校验
        phase = str(meta.get("phase", ""))
        for p in [x.strip() for x in phase.split(",") if x.strip()]:
            if p not in PHASE_ENUM:
                issues.append("%s: phase 非法值 %s" % (d.name, p))
        if "layer" in meta and meta["layer"] not in LAYER_ENUM:
            issues.append("%s: layer 非法值 %s" % (d.name, meta["layer"]))
        if "risk" in meta and meta["risk"] not in RISK_ENUM:
            issues.append("%s: risk 非法值 %s" % (d.name, meta["risk"]))
        metas[d.name] = {
            "meta": meta,
            "requires": requires,
            "triggers": triggers,
            "text": md.read_text(encoding="utf-8"),
        }
    return metas, issues


def check_graph(metas, issues):
    entries = [n for n, v in metas.items() if v["meta"].get("entry") is True]
    if len(entries) != 1:
        issues.append("entry 必须唯一，当前: %s" % entries)
    entry = entries[0] if len(entries) == 1 else None

    for n, v in metas.items():
        if n == entry:
            continue
        if "pentest-flow" not in v["requires"]:
            issues.append("%s: requires 未包含 pentest-flow" % n)
        if not v["triggers"]:
            issues.append("%s: triggers 不能为空（非 entry）" % n)

    for n, v in metas.items():
        for r in v["requires"]:
            if r not in metas:
                issues.append("%s: requires 指向不存在的技能 %s" % (n, r))

    # 环检测（DFS 三色）
    color = {}

    def dfs(u):
        color[u] = 1
        for w in metas[u]["requires"]:
            if w not in metas:
                continue
            if color.get(w) == 1:
                return True
            if color.get(w) is None and dfs(w):
                return True
        color[u] = 2
        return False

    if any(color.get(u) is None and dfs(u) for u in metas):
        issues.append("requires 存在环")
    return entry


def scan_cross_refs(metas, entry):
    """非 entry 技能直接引用其他能力包 references/ 的数量与样例。

    白名单：_shared、本技能目录、entry（pentest-flow）。
    扫描范围：SKILL.md + 本技能 references/*.md（references 内的跨技能引用同样检查）。
    """
    hits = []
    for n, v in metas.items():
        if n == entry:
            continue
        texts = [v["text"]]
        refs_dir = SKILLS / n / "references"
        if refs_dir.is_dir():
            for f in refs_dir.rglob("*.md"):
                texts.append(f.read_text(encoding="utf-8"))
        for text in texts:
            for m in re.finditer(r"`([^`\n]+?\.md)`|\]\(([^)]+?\.md)\)", text):
                rel = m.group(1) or m.group(2)
                if not rel or rel.startswith(("http", "/", "~")):
                    continue
                if " " in rel or "*" in rel or "<" in rel:
                    continue
                if "_shared" in rel:
                    continue
                m2 = re.search(r"(?:\.\./)+(pentest-flow|[a-z0-9][a-z0-9-]*)/", rel)
                if not m2:
                    continue
                target = m2.group(1)
                if target in metas and target not in (n, entry) and target not in v["requires"]:
                    hits.append((n, rel))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict-refs", action="store_true",
                    help="跨技能引用也计入 FAIL（全下沉后 CI 已启用）")
    args = ap.parse_args()

    metas, issues = collect()
    entry = check_graph(metas, issues)
    refs = scan_cross_refs(metas, entry)

    if refs:
        if args.strict_refs:
            for n, rel in refs:
                issues.append("%s: 跨技能引用 %s" % (n, rel))
        else:
            print("WARN: %d 处跨技能直接引用（全下沉后应为 0；CI 使用 --strict-refs）" % len(refs))
            for n, rel in refs[:8]:
                print("  - %s -> %s" % (n, rel))

    if issues:
        print("FAIL: %d issue(s)" % len(issues))
        for i in issues:
            print("-", i)
        return 1
    print("PASS: %d skills, entry=%s, requires 无环" % (len(metas), entry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
