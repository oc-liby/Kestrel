---
name: mcp-tool-poisoning-evidence
description: MCP 工具投毒的证据分级、测试优先级与框架/模型归因；配合 mcp-tool-poisoning-detection.md 使用。
---

# MCP Tool Poisoning：证据分级与优先级

> 来源：[S42] arXiv 2611.03555v2（2026-11，Farooq Shaikh / Biagio Montaruli）
> 用途：约束 `mcp-tool-poisoning-detection.md` 的 confirmed 判据，并给黑盒交战排序。
> 论文是受控测量：12 框架 × 18 模型 × 45 场景，9,720 个单元；结论只适用于测试配置。

## 1. 证据分级

| 层级 | 观察到什么 | 本工程状态 |
|---|---|---|
| T1 发出调用 | 工具 trace 中出现攻击者可控的工具调用/参数 | `candidate` |
| T2 网络接触 | canary HTTP/DNS 收到来自目标的请求，或有出站连接日志 | `confirmed`（外泄类） |
| T3 数据外泄 | canary secret 出现在攻击者端点/回显，且可复现 | `confirmed`（高置信） |

- 只有 T1 不得标 `confirmed`；模型口头承认、复述描述、生成未投递的调用都不算。
- T2/T3 必须有授权 OOB/canary 端点；按宪法 §9，优先公共 dnslog/interactsh，不使用真实凭据。
- 报告记录：`evidence_tier`、框架、模型/版本、场景、工具 trace、receipt 路径。

## 2. 测试优先级

论文的 ASR（受控测量，不是目标预测）：

- parameter binding 51.9% > description 27.2% > confused deputy 25.7%
- unicode 0.0%、authority spoofing 3.3%、dynamic registration 3.8%

黑盒排序：

1. 参数描述 / schema annotation / 返回值说明中的隐藏指令；
2. 工具描述投毒（仍是主量，26/45 场景）；
3. 跨 Server 遮蔽 / rug pull；
4. 低收益的编码/Unicode 变体后置。

## 3. 框架层与模型层

- 9 个核心框架 ASR 集中在 23–26%（χ²=3.30，p=0.91），测试范围内没有框架实现主动内容防御。
- Pydantic AI 16.6% 来自重名工具拒绝；AG2 4.6% 来自 executor 约束——都是偶然缓解，不是描述检测。
- 模型 ASR 0.4%（Claude Fable 5）–49.7%（Amazon Nova Pro）；模型选择是安全决策。
- Claude Sonnet 5 出现 narrate-then-comply：口头指出注入后仍执行；不要把“提到了风险”当 resisted。

## 4. 扫描器的边界

- 正则扫描：20/45 场景（44.4%）被拒，125 条良性描述误报 9 条（7.2%）。
- 有效检测主要来自指令模式；编码/长度检查无贡献。
- 逃逸：policy 措辞、其他语言、文件路径、不可见字符。
- 扫描只能作为部分控制，必须配合描述哈希固定、变更检测、结果通道校验。

## 5. 报告写法

- 不要把论文 ASR 写成目标预测；写“同配置下的测量参考”。
- 不要在框架 ASR 低时下“框架安全”结论；记录 incidental mitigation。
- 失败也要写：T1 有调用但无 receipt → `candidate` + 待回连。

参考：[S42]；配套 `mcp-tool-poisoning-detection.md`、`../operators/mcp_description_poison.md`。
