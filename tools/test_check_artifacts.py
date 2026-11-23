#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_artifacts 通道判定触发的回归 fixture。

使用标准库 unittest，不依赖 pytest：
    python tools/test_check_artifacts.py -v
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_artifacts  # noqa: E402


def build_plan(category: str, with_channel: bool) -> str:
    """生成一份最小 plan.md，只用于验证通道判定触发。"""
    channel = ""
    if with_channel:
        channel = """## 通道判定

| S 级 | 位置 | 下一动作 T 级 | decision | fallback | cleanup_status |
|---|---|---|---|---|---|
| S0 | 容器 | T0 | 直接执行 | 无 | n/a |

"""
    return f"""## 资产基线
| 端口 | 服务 | 版本 | 标题/技术栈 | 证据 |
|---|---|---|---|---|
| 80 | app | 1.0 | demo | evidence/x.txt |

## 攻击面账本
| # | 资产 | 端口 | 服务 | 接口/参数 | 方法 | 类别 | 状态 | 证据 | 下一步 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 10.0.0.5 | 80 | app | /x | GET | {category} | confirmed | evidence/x.txt | - |

## 技能加载
| 技能 | 时间 | 触发信号 | 依据 |
|---|---|---|---|
| pentest-flow | 10:00 | 开始 | 主流程 |

## 深度清单
| 方向 | 清单项 | 状态 | 证据/说明 |
|---|---|---|---|
| 基础 | S1 | done | evidence/x.txt |

## 覆盖清单
| 类别 | 状态 |
|---|---|
| sqli | negative |

{channel}## 复盘
- 轮次 1：账本 #1 有证据
- 轮次 2：清单 S1 完成
- 轮次 3：证据已落盘
- 轮次 4：negative 有理由
- 轮次 5：无新方向

## 结束检查
| # | 检查项 | 输出 | 状态 |
|---|---|---|---|
| 1 | a | x | PASS |
| 2 | b | x | PASS |
| 3 | c | x | PASS |
| 4 | d | x | PASS |
| 5 | e | x | PASS |
| 6 | f | x | PASS |
| 7 | g | x | PASS |
| 8 | h | x | PASS |
| 9 | i | x | PASS |
| 10 | j | x | PASS |
| 11 | k | x | PASS |
| 12 | l | x | PASS |
"""


class ChannelDecisionTriggerTest(unittest.TestCase):
    """验证检查器只在执行类 confirmed 行上要求通道判定表。"""

    def issues_for(self, category: str, with_channel: bool = False) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "roe.yaml").write_text(
                'engagement:\n  target: "10.0.0.5"\n', encoding="utf-8"
            )
            (work / "findings.md").write_text("# findings\n", encoding="utf-8")
            (work / "evidence").mkdir()
            (work / "evidence" / "x.txt").write_text("proof\n", encoding="utf-8")
            (work / "plan.md").write_text(
                build_plan(category, with_channel), encoding="utf-8"
            )
            issues, _warnings = check_artifacts.lint(str(work))
            return issues

    def assert_no_channel_issue(self, category: str) -> None:
        issues = self.issues_for(category)
        hits = [i for i in issues if "通道判定" in i]
        self.assertFalse(hits, f"{category} 不应触发通道判定: {hits}")

    def assert_channel_required(self, category: str) -> None:
        issues = self.issues_for(category)
        hits = [i for i in issues if "通道判定" in i]
        self.assertTrue(hits, f"{category} 应触发通道判定，实际 issues={issues}")

    def test_source_does_not_trigger(self) -> None:
        """source 含 rce 子串，但不应被当成 RCE。"""
        self.assert_no_channel_issue("source")

    def test_resource_does_not_trigger(self) -> None:
        """resource 含 rce 子串，但不应被当成 RCE。"""
        self.assert_no_channel_issue("resource")

    def test_rce_requires_channel_table(self) -> None:
        self.assert_channel_required("rce")

    def test_webshell_requires_channel_table(self) -> None:
        self.assert_channel_required("webshell")

    def test_cmd_injection_requires_channel_table(self) -> None:
        self.assert_channel_required("cmd_injection")

    def test_rce_with_channel_table_passes(self) -> None:
        issues = self.issues_for("rce", with_channel=True)
        hits = [i for i in issues if "通道判定" in i]
        self.assertFalse(hits, f"有通道判定表时不应再报: {hits}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
