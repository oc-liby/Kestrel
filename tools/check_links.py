#!/usr/bin/env python3
"""链接检查：扫描技能与文档中的相对 .md 引用，输出断链。

只检查相对路径（../、./、技能名/、references/ 开头）；
跳过 URL、绝对路径、通配符、占位符、产物名与外部项目示例。
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"
SKILL_NAMES = {p.name for p in SKILLS.iterdir() if p.is_dir()}

# 产物名 / 外部示例：不作为路径解析
PRODUCT_NAMES = {"plan.md", "findings.md", "notes.md", "approvals.md",
                 "cleanup.md", "challenges.md", "report.md", "env-map.md"}
EXTERNAL = {"CLAUDE.md", "AGENTS.md", ".github/copilot-instructions.md",
            "docs/README.md", "README.md", "SKILL.md"}


def iter_markdown():
    # 只检查安装单元（skills/）；docs/ 是设计文档，示例路径不代表现状
    yield from sorted(SKILLS.rglob("*.md"))


def extract_refs(text):
    """返回 (路径, 类型) 迭代：反引号路径与 markdown 链接。"""
    for m in re.finditer(r"`([^`\n]+?\.md)`", text):
        yield m.group(1).strip(), "code"
    for m in re.finditer(r"\]\(([^)\s]+?\.md)(?:#[^)]*)?\)", text):
        yield m.group(1).strip(), "link"


def is_checkable(rel, md):
    if not rel or rel.startswith(("http", "/", "~")):
        return False
    if " " in rel or "*" in rel or "<" in rel or ">" in rel:
        return False
    if rel in EXTERNAL or rel.split("/")[-1] in PRODUCT_NAMES:
        return False
    # 只检查相对路径或引用目录
    parts = rel.split("/")
    if rel.startswith(("../", "./")):
        return True
    if parts[0] in SKILL_NAMES:
        return True
    if parts[0] == "references" and md.parent.name == "references":
        return True
    return False


def main():
    bad = []
    for md in iter_markdown():
        try:
            text = md.read_text(encoding="utf-8")
        except OSError:
            continue
        for rel, kind in extract_refs(text):
            if not is_checkable(rel, md):
                continue
            target = (md.parent / rel).resolve()
            if not target.exists():
                bad.append((str(md.relative_to(ROOT)), rel))

    if bad:
        print("FAIL: %d broken link(s)" % len(bad))
        for f, r in bad[:50]:
            print("- %s -> %s" % (f, r))
        return 1
    print("PASS: 0 broken link")
    return 0


if __name__ == "__main__":
    sys.exit(main())
