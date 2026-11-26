#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""链接提取与可检查性判定的回归测试。"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_links as cl  # noqa: E402


class LinkTest(unittest.TestCase):
    def test_extract_code_and_link(self):
        refs = [r for r, _ in cl.extract_refs("`a/b.md` [x](c/d.md#s)")]
        self.assertEqual(refs, ["a/b.md", "c/d.md"])

    def test_product_and_relative(self):
        md = pathlib.Path("skills/x/SKILL.md")
        self.assertFalse(cl.is_checkable("plan.md", md))
        self.assertTrue(cl.is_checkable("../y/references/z.md", md))

    def _run(self, body_skill: str, body_ref: str):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            skills = root / "skills"
            (skills / "a" / "references").mkdir(parents=True)
            (skills / "a" / "SKILL.md").write_text(body_skill, encoding="utf-8")
            (skills / "a" / "references" / "n.md").write_text(body_ref, encoding="utf-8")
            shared = skills / "pentest-flow" / "references" / "_shared"
            shared.mkdir(parents=True)
            (shared / "x.md").write_text("x\n", encoding="utf-8")
            with mock.patch.object(cl, "SKILLS", skills), \
                 mock.patch.object(cl, "ROOT", root), \
                 mock.patch.object(cl, "SKILL_NAMES", {"a", "pentest-flow"}):
                import contextlib
                import io
                with contextlib.redirect_stdout(io.StringIO()):
                    return cl.main()

    def test_shared_prefix_levels_pass(self):
        rc = self._run(
            "see `../pentest-flow/references/_shared/x.md`\n",
            "see `../../pentest-flow/references/_shared/x.md`\n",
        )
        self.assertEqual(rc, 0)

    def test_wrong_shared_prefix_fails(self):
        rc = self._run("# ok\n", "see `references/_shared/x.md`\n")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
