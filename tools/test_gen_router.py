#!/usr/bin/env python3
"""gen_router 的回归测试：生成幂等、preamble 幂等。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_router  # noqa: E402
import yaml  # noqa: E402


class GenRouterTest(unittest.TestCase):
    def test_routing_md_idempotent(self):
        routing = yaml.safe_load(gen_router.ROUTING_YAML.read_text(encoding="utf-8"))
        skills = gen_router.load_skills()
        a = gen_router.gen_routing_md(skills, routing)
        b = gen_router.gen_routing_md(skills, routing)
        self.assertEqual(a, b)

    def test_preamble_idempotent(self):
        text = "# Title\n\nbody\n"
        block = gen_router.gen_preamble("web-pentest")
        once = gen_router.apply_preamble(text, block)
        twice = gen_router.apply_preamble(once, block)
        self.assertEqual(once, twice)
        self.assertIn("BEGIN GENERATED PREAMBLE", once)

    def test_entry_has_no_preamble(self):
        self.assertIsNone(gen_router.gen_preamble("pentest-flow"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
