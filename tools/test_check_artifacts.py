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


def build_k8s_plan(with_hyp=True, with_perm=True, hyp_conclusion="进路径 P-01"):
    """K8s 交战最小 plan：技能加载含 k8s-container，权限账本当前层 pod。"""
    hyp = ""
    if with_hyp:
        hyp = f"""## 假设
| # | 来源 | 攻击面 | 漏洞类 | 身份路径 | 可观察信号 | 验证方法 | 预期证据 | 状态 | 结论 |
|---|---|---|---|---|---|---|---|---|---|
| H-01 | 账本 #1 | 80 /x | rce | 无→pod | 回显 | id | evidence/x.txt | confirmed | {hyp_conclusion} |

"""
    perm = ""
    if with_perm:
        perm = """## 权限账本
| # | 身份/凭据 | 类型 | 来源 | 可达范围 | 当前层 | 权限 | 证据 | 状态 | 下一步 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | sa | token | sa 挂载 | ns | pod | list | evidence/x.txt | confirmed | - |

"""
    return f"""## 资产基线
| 端口 | 服务 | 版本 | 标题/技术栈 | 证据 |
|---|---|---|---|---|
| 80 | app | 1.0 | demo | evidence/x.txt |

## 攻击面账本
| # | 资产 | 端口 | 服务 | 接口/参数 | 方法 | 类别 | 状态 | 证据 | 下一步 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 10.0.0.5 | 80 | app | /x | GET | rce | confirmed | evidence/x.txt | - |

## 技能加载
| 技能 | 时间 | 触发信号 | 依据 |
|---|---|---|---|
| pentest-flow | 10:00 | 开始 | 主流程 |
| k8s-container | 10:01 | 6443 | 强制 |

{hyp}{perm}## 深度清单
| 方向 | 清单项 | 状态 | 证据/说明 |
|---|---|---|---|
| 基础 | S1 | done | evidence/x.txt |

## 覆盖清单
| 类别 | 状态 |
|---|---|
| sqli | negative |

## 通道判定
| S 级 | 位置 | 下一动作 T 级 | decision | fallback | cleanup_status |
|---|---|---|---|---|---|
| S0 | 容器 | T0 | 直接执行 | 无 | n/a |

## 复盘
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


def build_attack_path(with_evidence=True, blocked=False):
    evidence = "evidence/x.txt" if with_evidence else "-"
    status = "blocked" if blocked else "confirmed"
    note = "已尝试 3 条" if blocked else "-"
    return f"""## 路径

| # | 入口 | 中间节点 | 目标 | 所需权限/凭据 | 证据 | 状态 | 影响 |
|---|---|---|---|---|---|---|---|
| P-01 | 80 /x（账本 #1） | pod → SA | cluster-admin | 权限 #1 | {evidence} | {status} | 全集群 |
| P-02 | 6443 匿名 | - | kubelet | 无 | evidence/x.txt | n/a | {note} |
"""


class K8sEngagementTest(unittest.TestCase):
    """K8s 交战：假设 / 权限账本 / attack-path / cleanup 强制。"""

    def issues_for(self, plan=None, attack_path=None, cleanup=True):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "roe.yaml").write_text(
                'engagement:\n  target: "10.0.0.5"\ngoal: {highest_control: cluster-admin}\n',
                encoding="utf-8",
            )
            (work / "findings.md").write_text("# findings\n", encoding="utf-8")
            (work / "evidence").mkdir()
            (work / "evidence" / "x.txt").write_text("proof\n", encoding="utf-8")
            (work / "plan.md").write_text(plan or build_k8s_plan(), encoding="utf-8")
            if attack_path is not None:
                (work / "attack-path.md").write_text(attack_path, encoding="utf-8")
            if cleanup:
                (work / "cleanup.md").write_text("# cleanup\n", encoding="utf-8")
            issues, warnings = check_artifacts.lint(str(work))
            return issues, warnings

    def test_full_k8s_passes(self) -> None:
        issues, _ = self.issues_for(attack_path=build_attack_path())
        self.assertFalse([i for i in issues if "K8s 交战" in i], issues)

    def test_missing_hypothesis_fails(self) -> None:
        issues, _ = self.issues_for(plan=build_k8s_plan(with_hyp=False), attack_path=build_attack_path())
        self.assertTrue([i for i in issues if "假设" in i], issues)

    def test_missing_permission_ledger_fails(self) -> None:
        issues, _ = self.issues_for(plan=build_k8s_plan(with_perm=False), attack_path=build_attack_path())
        self.assertTrue([i for i in issues if "权限账本" in i], issues)

    def test_missing_attack_path_fails(self) -> None:
        issues, _ = self.issues_for(attack_path=None)
        self.assertTrue([i for i in issues if "attack-path.md" in i], issues)

    def test_missing_cleanup_fails(self) -> None:
        issues, _ = self.issues_for(attack_path=build_attack_path(), cleanup=False)
        self.assertTrue([i for i in issues if "cleanup.md" in i], issues)

    def test_old_product_warns_only(self) -> None:
        issues, warnings = self.issues_for(
            plan=build_plan("rce", with_channel=True),
            attack_path=None,
        )
        self.assertFalse([i for i in issues if "K8s 交战" in i], issues)
        self.assertTrue([w for w in warnings if "旧产物" in w], warnings)

    def test_permission_blocked_without_attempt_fails(self) -> None:
        plan = build_k8s_plan().replace("| 1 | sa | token | sa 挂载 | ns | pod | list | evidence/x.txt | confirmed | - |",
                                        "| 1 | sa | token | sa 挂载 | ns | pod | list | evidence/x.txt | blocked | - |")
        issues, _ = self.issues_for(plan=plan, attack_path=build_attack_path())
        self.assertTrue([i for i in issues if "blocked 但无已尝试" in i], issues)

    def test_attack_path_without_evidence_fails(self) -> None:
        issues, _ = self.issues_for(attack_path=build_attack_path(with_evidence=False))
        self.assertTrue([i for i in issues if "无证据" in i], issues)

    def test_attack_path_blocked_without_attempt_fails(self) -> None:
        issues, _ = self.issues_for(attack_path=build_attack_path(blocked=True))
        self.assertTrue([i for i in issues if "blocked 但无已尝试" in i], issues)

    def test_hypothesis_path_ref_missing_fails(self) -> None:
        plan = build_k8s_plan(hyp_conclusion="进路径 P-99")
        issues, _ = self.issues_for(plan=plan, attack_path=build_attack_path())
        self.assertTrue([i for i in issues if "P-99" in i], issues)


def build_env_map(node_status="confirmed", edge_status="confirmed",
                  target_status="untested", with_evidence=True):
    """生成最小 env-map.md，用于格式检查回归。"""
    evidence = "`evidence/x.txt`" if with_evidence else "-"
    return f"""# 环境心智地图 — OC-test

## 元数据

| 项 | 值 |
|---|---|
| 当前节点 | N-01 |
| 当前权限 | user |
| 当前通道 | S0 |

## 节点

| ID | 类型 | 地址 | 归属 | 版本/指纹 | 权限 | 凭据 | 状态 | 证据 |
|---|---|---|---|---|---|---|---|---|
| N-01 | app | 10.0.0.5:80 | target | demo 1.0 | anonymous | - | {node_status} | {evidence} |

## 边

| ID | 从 → 到 | 类型 | 条件 | 状态 | 证据 |
|---|---|---|---|---|---|
| E-01 | N-01 → N-02 | network | 双网卡 | {edge_status} | {evidence} |

## 目标

| ID | 目标 | 位置 | 通向它的边 | 状态 |
|---|---|---|---|---|
| G-01 | host SSH | N-02 | E-01 | {target_status} |
"""


class EnvMapFormatTest(unittest.TestCase):
    """env-map.md 可选格式检查：存在才校验，不存在不报错。"""

    def issues_for(self, env_map=None):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / "roe.yaml").write_text(
                'engagement:\n  target: "10.0.0.5"\n', encoding="utf-8"
            )
            (work / "findings.md").write_text("# findings\n", encoding="utf-8")
            (work / "evidence").mkdir()
            (work / "evidence" / "x.txt").write_text("proof\n", encoding="utf-8")
            (work / "plan.md").write_text(
                build_plan("rce", with_channel=True), encoding="utf-8"
            )
            if env_map is not None:
                (work / "env-map.md").write_text(env_map, encoding="utf-8")
            issues, _warnings = check_artifacts.lint(str(work))
            return [i for i in issues if "env-map" in i]

    def test_missing_env_map_does_not_fail(self) -> None:
        """无 env-map.md 时不报错（可选产物）。"""
        self.assertEqual(self.issues_for(), [])

    def test_valid_env_map_passes(self) -> None:
        self.assertEqual(self.issues_for(build_env_map()), [])

    def test_missing_node_table_fails(self) -> None:
        text = build_env_map().replace("## 节点", "## 节点X")
        issues = self.issues_for(text)
        self.assertTrue([i for i in issues if "## 节点" in i], issues)

    def test_invalid_status_fails(self) -> None:
        issues = self.issues_for(build_env_map(node_status="open"))
        self.assertTrue([i for i in issues if "状态非法" in i], issues)

    def test_confirmed_without_evidence_fails(self) -> None:
        issues = self.issues_for(build_env_map(with_evidence=False))
        self.assertTrue([i for i in issues if "无证据" in i], issues)

    def test_blocked_without_attempt_fails(self) -> None:
        issues = self.issues_for(build_env_map(edge_status="blocked"))
        self.assertTrue([i for i in issues if "blocked 但无已尝试" in i], issues)


if __name__ == "__main__":
    unittest.main(verbosity=2)
