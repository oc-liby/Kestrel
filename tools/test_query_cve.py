#!/usr/bin/env python3
"""query_cve 与索引的回归测试（10 个样例）。"""
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "skills/cve-triage/scripts"))
import query_cve as q  # noqa: E402

IDX, ALIASES = q.load()


class TestVersion(unittest.TestCase):
    def test_basic_compare(self):
        self.assertLess(q.vcmp("1.2.3", "1.2.4"), 0)
        self.assertEqual(q.vcmp("1.2.3", "1.2.3"), 0)
        self.assertGreater(q.vcmp("1.10.0", "1.9.9"), 0)

    def test_prerelease_lower(self):
        self.assertLess(q.vcmp("1.0.0-rc1", "1.0.0"), 0)
        self.assertLess(q.vcmp("1.0.0-alpha", "1.0.0-beta"), 0)

    def test_leading_v(self):
        self.assertEqual(q.vcmp("v1.2.3", "1.2.3"), 0)

    def test_partial_segments(self):
        self.assertEqual(q.vcmp("1.2", "1.2.0"), 0)


class TestRule(unittest.TestCase):
    def test_single_ops(self):
        self.assertTrue(q.eval_rule('version < "0.5.2"', "0.5.0"))
        self.assertFalse(q.eval_rule('version < "0.5.2"', "0.5.2"))
        self.assertTrue(q.eval_rule('version <= "1.0.0"', "1.0.0"))
        self.assertTrue(q.eval_rule('version >= "1.0.0"', "1.0.0"))
        self.assertTrue(q.eval_rule('version == "1.0.0"', "1.0.0"))

    def test_empty_rule_unverified(self):
        self.assertIsNone(q.eval_rule("", "1.0"))

    def test_complex_rule_unverified(self):
        self.assertIsNone(q.eval_rule('version >= "0.9" && version < "1.10.1"', "1.0"))

    def test_unknown_syntax_unverified(self):
        self.assertIsNone(q.eval_rule('version in ["1.0"]', "1.0"))

    def test_commit_hash_rule_unverified(self):
        self.assertIsNone(q.eval_rule('version < "79778fa"', "0.5.0"))

    def test_branch_rule_unverified(self):
        self.assertIsNone(q.eval_rule('version < "0.x.y-security-1"', "0.5.0"))
        self.assertIsNone(q.eval_rule('version < "git c91dbfc"', "0.5.0"))
        self.assertIsNone(q.eval_rule('version < "20250606v2pro"', "0.5.0"))

    def test_empty_target_unverified(self):
        self.assertIsNone(q.eval_rule('version < ""', "1.0"))

    def test_semver_suffix(self):
        self.assertTrue(q.eval_rule('version < "1.2.3-rc1"', "1.2.2"))
        self.assertFalse(q.eval_rule('version < "1.2.3-rc1"', "1.2.3"))


class TestLookup(unittest.TestCase):
    def test_component_match(self):
        canonical = q.resolve_component("9router", IDX, ALIASES)
        self.assertEqual(canonical, "9router")
        entries = [e for e in IDX["entries"] if e["component_dir"] == canonical]
        hit = [e for e in entries if q.eval_rule(e["rule"], "0.5.0") is True]
        self.assertTrue(any(e["cve"] == "CVE-2026-55638" for e in hit))

    def test_version_boundary(self):
        entries = [e for e in IDX["entries"] if e["component_dir"] == "9router"]
        hit = [e for e in entries if q.eval_rule(e["rule"], "0.5.2") is True]
        self.assertFalse(any(e["cve"] == "CVE-2026-55638" for e in hit))

    def test_alias(self):
        self.assertEqual(q.resolve_component("openwebui", IDX, ALIASES), "open-webui")

    def test_cve_reverse(self):
        hits = [e for e in IDX["entries"] if e["cve"].upper() == "CVE-2025-55182"]
        self.assertGreaterEqual(len(hits), 1)
        self.assertTrue(all(e["component_dir"] for e in hits))

    def test_not_found(self):
        self.assertIsNone(q.resolve_component("no-such-component-xyz", IDX, ALIASES))

    def test_list_components(self):
        comps = {e["component_dir"] for e in IDX["entries"]}
        self.assertGreaterEqual(len(comps), 100)

    def test_component_query_ignores_commit_rule(self):
        entries = [e for e in IDX["entries"] if e["component_dir"] == "open-webui"]
        hit = [e for e in entries if q.eval_rule(e["rule"], "0.5.0") is True]
        self.assertFalse(any(e["cve"] == "CVE-2024-7999" for e in hit))
        unv = [e for e in entries if q.eval_rule(e["rule"], "0.5.0") is None]
        self.assertTrue(any(e["cve"] == "CVE-2024-7999" for e in unv))


if __name__ == "__main__":
    unittest.main(verbosity=2)
