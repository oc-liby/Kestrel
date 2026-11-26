#!/usr/bin/env python3
"""check_contracts 的回归测试：frontmatter、跨技能引用、_shared 放行。"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_contracts as cc  # noqa: E402


def make_skill(root: Path, name: str, entry=False, requires="[pentest-flow]", triggers=True):
    d = root / "skills" / name
    d.mkdir(parents=True)
    trig = '  triggers:\n    - "test signal"\n' if triggers else "  triggers: []\n"
    fm = (
        "---\n"
        f"name: {name}\n"
        "description: test skill for contracts\n"
        "metadata:\n"
        '  version: "0.1.0"\n'
        f"  entry: {'true' if entry else 'false'}\n"
        f"  requires: {requires}\n"
        f"{trig}"
        '  layer: "skill"\n'
        '  risk: "low"\n'
        '  phase: "recon"\n'
        '  task_types: "pentest"\n'
        "---\n"
        f"# {name}\n"
    )
    (d / "SKILL.md").write_text(fm, encoding="utf-8")
    return d


class ContractsTest(unittest.TestCase):
    def run_check(self, build, strict=True):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build(root)
            skills = root / "skills"
            with mock.patch.object(cc, "SKILLS", skills):
                metas, issues = cc.collect()
                entry = cc.check_graph(metas, issues)
                refs = cc.scan_cross_refs(metas, entry)
                if strict and refs:
                    issues.extend("%s: 跨技能引用 %s" % (n, rel) for n, rel in refs)
                return issues, refs

    def test_missing_triggers_fails(self):
        def build(root):
            make_skill(root, "pentest-flow", entry=True, requires="[]")
            make_skill(root, "web", triggers=False)
        issues, _ = self.run_check(build)
        self.assertTrue([i for i in issues if "triggers" in i], issues)

    def test_cross_skill_reference_fails(self):
        def build(root):
            make_skill(root, "pentest-flow", entry=True, requires="[]")
            a = make_skill(root, "web")
            make_skill(root, "other")
            refs = a / "references"
            refs.mkdir()
            (refs / "note.md").write_text(
                "see `../../other/references/x.md`\n", encoding="utf-8"
            )
        issues, refs = self.run_check(build)
        self.assertTrue(refs, "应检出跨技能引用")
        self.assertTrue([i for i in issues if "跨技能引用" in i], issues)

    def test_shared_reference_passes(self):
        def build(root):
            make_skill(root, "pentest-flow", entry=True, requires="[]")
            a = make_skill(root, "web")
            refs = a / "references"
            refs.mkdir()
            (refs / "note.md").write_text(
                "see `../../pentest-flow/references/_shared/web/x.md`\n", encoding="utf-8"
            )
        issues, refs = self.run_check(build)
        self.assertFalse(refs, refs)
        self.assertFalse([i for i in issues if "跨技能引用" in i], issues)


if __name__ == "__main__":
    unittest.main(verbosity=2)
