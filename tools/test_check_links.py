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


if __name__ == "__main__":
    unittest.main(verbosity=2)
