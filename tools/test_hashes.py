#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证据哈希与 approvals 链的回归测试。"""
import hashlib
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_artifacts as ca  # noqa: E402


class HashTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = pathlib.Path(self.tmp.name)
        (self.work / "evidence").mkdir()
        (self.work / "evidence" / "x.txt").write_text("proof\n", encoding="utf-8")
        (self.work / "findings.md").write_text(
            "# findings\n\n## F-001 test — confirmed\n\n"
            "- 证据：evidence/x.txt\n- 状态：confirmed\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_stamp_writes_hash(self):
        self.assertEqual(ca.stamp_hashes(str(self.work)), [])
        text = (self.work / "findings.md").read_text(encoding="utf-8")
        self.assertIn("- 证据哈希：sha256:", text)

    def test_verify_pass(self):
        ca.stamp_hashes(str(self.work))
        self.assertEqual(ca.verify_hashes(str(self.work)), [])

    def test_verify_detects_tamper(self):
        ca.stamp_hashes(str(self.work))
        (self.work / "evidence" / "x.txt").write_text("tampered\n", encoding="utf-8")
        issues = ca.verify_hashes(str(self.work))
        self.assertTrue(any("不一致" in i for i in issues))

    def test_no_hash_is_ok(self):
        self.assertEqual(ca.verify_hashes(str(self.work)), [])

    def test_approvals_chain(self):
        body = "### A-001 2026-11-26T10:00:00Z\n\n- 操作：test\n- prev: genesis\n"
        digest = "sha256:" + hashlib.sha256(("genesis" + body).encode("utf-8")).hexdigest()
        (self.work / "approvals.md").write_text(
            body + "- hash: " + digest + "\n", encoding="utf-8"
        )
        self.assertEqual(ca.verify_hashes(str(self.work)), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
