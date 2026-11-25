# Kestrel 架构演进设计（v2）

> 状态：**已评审，Q1–Q6 已定**（2026-11-26）；实施按 §10 分阶段进行
> 适用范围：Kestrel 仓库、24 个技能、4 个客户端
> 关联：`docs/RULES-LAYERING.md`（规则分层重构记录）、`README.md`、`skills/pentest-flow/references/constitution.md`
> 本文是设计文档，不是实施记录。

---

## 1. 摘要

当前架构的分层（宪法 / 流程 / 技能 / 知识）是正确的，问题不在分层，而在四个**手工耦合点**：

1. 路由表手工维护在主流程里，主流程 445 行、验收上限 450 行，已顶格；
2. 24 个技能中 12 个未声明"先加载 `pentest-flow`"，存在入口旁路；
3. 167 处跨技能文件引用 + 7 组重复文档，移动/重命名技能会断链；
4. 4140 条结构化数据（2440 CVE + 170 指纹 × 组件索引）没有查询层，只能 grep + 人读。

本设计把这四点改为**声明式 + 生成式 + 契约化**，同时保持：

- 运行时零依赖（纯 Markdown + 标准库 Python）；
- `cp -a skills/. <client>/skills/` 的安装方式不变；
- 规则唯一源（宪法）不变；
- 旧交战产物可继续读取。

四个改造（R1–R4）：

| 编号 | 改造 | 解决的问题 | 预计工时 |
|---|---|---|---|
| R1 | 路由声明化与生成 | 主流程顶格、路由漂移、入口旁路 | 1–2 天 |
| R2 | 依赖声明化与共享知识 | 167 处路径耦合、7 组重复、缺少前置声明 | 1–2 天 |
| R3 | 离线知识查询 | 2440 条数据无索引、无版本匹配、组件别名漏检 | 2–3 天 |
| R4 | 产物契约与检查器分层 | 检查器 500 行正则、覆盖窄、证据不可验证 | 2–3 天 |

---

## 2. 背景与问题

### 2.1 现状量化（2026-11-26 实测）

| 指标 | 数值 | 采集方式 |
|---|---|---|
| 技能数 | 24 | `skills/*/SKILL.md` |
| Markdown 文件 | 342 | `find skills -name '*.md'` |
| 结构化数据 | 2440 YAML（2184 CVE + 256 非 CVE）+ 170 指纹 | `find skills/cve-triage/data -name '*.yaml'` |
| Python 脚本 | 7（技能内 4 + tools 3） | `find . -name '*.py'` |
| 仓库体积 | 14 MB（CVE 数据 9.8 MB，占 70%） | `du -sh skills` |
| 常驻元数据 | 24 个 `description` 共 1633 字符 | 脚本统计 |
| 主流程体积 | 445 行 / 15426 字符 | `wc -l skills/pentest-flow/SKILL.md` |
| 知识库体积 | 314 个 reference，1.51M 字符（约 75 万 tokens） | 脚本统计 |
| 仓库内引用 | 320 处，其中跨技能 167 处，断链 0 | 自建引用图 |
| 完全重复文件 | 7 组（`client-reverse` ↔ `android-pentest`） | MD5 |
| 同名但已改写引用的文件 | 2 个（仅路径差 1 行） | `diff` |
| 主流程路由覆盖 | 24/24 | 字符串匹配 |
| 未提及 `pentest-flow` 的技能 | 12/24 | 字符串匹配 |
| 检查器测试 | 6 个用例，仅覆盖"通道判定"一项 | `test_check_artifacts.py` |
| CI / tag / CHANGELOG | 无 | 目录与 git 检查 |
| git 提交 | 13 次，2026-11-20 — 11-24，首个提交整库导入 | `git log` |

### 2.2 四个结构性问题

**问题 A：单点注册。**
`skills/pentest-flow/SKILL.md:196-248` 是唯一路由表，24 行手工维护。`docs/RULES-LAYERING.md:101` 规定主技能 ≤450 行，当前 445 行，只剩 5 行余量。新增技能必须改主流程，否则永远不会被路由。

**问题 B：入口旁路。**
12 个技能（`cve-triage`、`web-security-advanced`、`vuln-discovery`、`android-pentest`、`ctf-web`、`ctf-crypto`、`ctf-misc`、`client-reverse`、`crypto-toolkit`、`osint-recon`、`reporting`、`web-security-advanced`）的 `SKILL.md` 未出现 `pentest-flow` 字样。用户直接触发这些技能时，宪法门禁不进入上下文。"任何交战必须先加载主流程"只写在主流程自己的 `description` 里，没有在技能侧形成声明。

**问题 C：路径耦合。**
`client-reverse` 与 `android-pentest` 之间有 7 个文件内容完全相同；另有 2 个同名文件仅差一行引用路径（为适配目录而改写）。`client-reverse/SKILL.md:75-83` 引用了其中 5 个，`android-static-triage-and-callflow.md` 与 `android-dynamic-hooking-and-replay.md` 复制后未被引用。`android-pentest` 的 SOP 又反向引用 `../../client-reverse/references/02-client-api-reverse-and-burp.md`，形成双向依赖。当前断链 0，但没有自动链接检查保护下一次改动。

**问题 D：数据不可查。**
`cve-triage/data/aig-vuln/index.json` 只有 142 个组件的 `{dir, cves}` 计数，没有 CVE → 组件/版本映射，也不解析 `rule` 版本表达式。`query_cve.py` 不存在。2440 条数据只能 grep + 人读；组件别名 `open-webui`/`openwebui`、`lobechat`/`lobehub` 会漏检；256 条非 CVE 规则使"2440 条 CVE"的表述失准。

### 2.3 为什么现在做

- 技能数 24、主流程 445/450，**下一批技能就会撞上硬上限**；
- 断链 0 是手工复检的结果（`docs/RULES-LAYERING.md:107-111`），下一次改动没有自动保护；
- 数据快照（2026-11-12）会持续变旧，没有更新/查询机制，价值随时间递减；
- 现在只有 13 次提交、单一维护者，重构成本最低；越晚做，跨技能引用和重复文件越多。

---

## 3. 目标与非目标

### 3.1 目标（可量化）

| # | 目标 | 验收指标 |
|---|---|---|
| G1 | 新增技能不再改主流程 | 新技能只需在自己 `SKILL.md` 声明 `triggers/requires`，路由表由生成器产出 |
| G2 | 主流程瘦身 | `skills/pentest-flow/SKILL.md` ≤ 250 行（不含生成表） |
| G3 | 入口门禁可达 | 24/24 技能声明 `requires: [pentest-flow]`，生成前置声明 |
| G4 | 消除文件级耦合 | 跨技能 `.md` 引用全部指向 `_shared` 或声明式依赖；完全重复文件 0 |
| G5 | 数据可查询 | `tools/query_cve.py` 支持组件+版本、CVE 反查、JSON 输出；10 个样例全通过 |
| G6 | 校验可重复 | `tools/check_*.py` 全部可在 CI 一条命令跑完；检查器测试 ≥ 30 个用例 |
| G7 | 向后兼容 | 旧 `Work/OC-*` 产物仍可通过检查（WARN 不 FAIL）；`cp -a` 安装仍可用 |

### 3.2 非目标

1. **不引入运行时服务/数据库/依赖**：安装后的技能仍是纯 Markdown + 标准库脚本。
2. **不合并技能**：24 个技能边界保持不动。
3. **不改客户端加载协议**：只使用 `SKILL.md` frontmatter，不要求客户端支持新字段。
4. **不做完整状态机 / 多 agent 编排**：流程仍由文档协议 + 检查器约束。
5. **不重写 `check_artifacts.py` 的全部语义规则**：R4 只做"schema 驱动的结构层 + 证据哈希"，语义规则保留。
6. **不把证据真实性自动化**：哈希只能证明"文件未被改动"，不能证明"测试真实发生"，后者仍需人工确认。

---

## 4. 设计原则

1. **运行时零依赖，开发时可生成。** 生成器与校验器只在仓库/CI 运行；生成产物入库，用户安装时不需要构建。
2. **单一数据源。** 一条信息只存一处：授权规则在宪法；技能信号在技能 frontmatter；路由分类在 `meta/routing.yaml`；产物结构在 `meta/artifacts.schema.json`。
3. **声明式优先于手工。** 能用 frontmatter / YAML 表达的，不写在正文表格里；能用生成器产出的，不手工复制。
4. **生成物可校验、幂等。** 生成文件带 `DO NOT EDIT` 标记；`--check` 模式在 CI 中比对，不一致即失败；重复运行结果字节一致。
5. **向后兼容优先。** 旧字段、旧格式、旧产物路径保留读取路径；新格式只 WARN 不 FAIL，直到下一个大版本。
6. **安全默认。** 入口技能必须显式依赖；高影响操作必须有回滚记录；受限许可数据**保持现状不拆包**，许可限制写入 README / NOTICE。
7. **最小改动。** 优先复用现有目录与文件，不为了"架构漂亮"搬家；`skills/` 仍是安装单元。

---

## 5. 目标架构

### 5.1 逻辑分层

```
┌─────────────────────────────────────────────────────────────┐
│ 内核 Kernel（必装，稳定）                                     │
│  - 宪法 constitution.md（授权/证据/产物边界，唯一源）          │
│  - 流程协议 SKILL.md（阶段/门禁/产物/结束条件）                │
│  - 路由生成物 routing.generated.md                            │
│  - 共享知识 _shared/（Android/客户端/编码脚本）                │
└──────────────────────────┬──────────────────────────────────┘
                           │ requires（声明式，单向）
┌──────────────────────────▼──────────────────────────────────┐
│ 能力包 Skills（24 个，可独立演进）                             │
│  - SKILL.md（metadata: version/requires/triggers/entry）      │
│  - references/（本技能知识）                                   │
│  - scripts/（可选，标准库）                                    │
└──────────────────────────┬──────────────────────────────────┘
                           │ 通过 ID / 索引访问
┌──────────────────────────▼──────────────────────────────────┐
│ 知识包 Knowledge（数据 + 索引 + 许可）                         │
│  - cve-triage/data/aig-vuln/（2440 规则 + index + aliases）   │
│  - recon/data/aig-fingerprints/（170 指纹）                   │
│  - 数据集（CC-BY-NC 等，随包分发，许可限制见 NOTICE）            │
└─────────────────────────────────────────────────────────────┘

开发时工具（不安装）：
  meta/routing.yaml, meta/*.schema.json
  tools/gen_router.py, check_contracts.py, check_links.py,
        check_data.py, query_cve.py, install.py
```

### 5.2 物理布局（改动后）

```text
Kestrel/
├── meta/                                  # 新增：仓库级元数据，不安装
│   ├── routing.yaml                       # 路由分类唯一源
│   ├── skill.schema.json                  # frontmatter 契约
│   ├── artifacts.schema.json              # plan/findings 契约
│   └── knowledge.yaml                     # 知识包清单与许可
├── skills/                                # 安装单元（cp -a 不变）
│   ├── pentest-flow/
│   │   ├── SKILL.md                       # 瘦身到 ≤250 行
│   │   ├── references/
│   │   │   ├── constitution.md            # 不动
│   │   │   ├── flow.md                    # 不动（模板）
│   │   │   ├── handoff.md                 # 不动
│   │   │   ├── routing.generated.md       # 新增：生成物
│   │   │   ├── reporting.md               # 新增：播报格式移出
│   │   │   ├── review-audit.md            # 新增：复盘审计维度移出
│   │   │   └── _shared/                   # 新增：共享知识（内核附属）
│   │   │       ├── android/               # 7 个 Android 文档权威源
│   │   │       └── client/                # 客户端逆向共用文档
│   │   └── scripts/
│   │       └── shared/
│   │           └── encode.py              # 合并后的编码脚本
│   ├── <24 skills>/...
│   └── cve-triage/data/aig-vuln/
│       ├── index.json                     # 扩展
│       ├── cve-index.json                 # 新增：CVE 反查
│       └── aliases.json                   # 新增：组件别名
├── tools/                                 # 开发时工具
│   ├── gen_router.py                      # 新增
│   ├── check_contracts.py                 # 新增
│   ├── check_links.py                     # 新增
│   ├── check_data.py                      # 新增
│   ├── query_cve.py                       # 新增
│   ├── install.py                         # 新增（可选）
│   ├── check_artifacts.py                 # 改造（分层）
│   ├── check_skill_budget.py              # 保留
│   └── test_*.py
└── docs/
    ├── RULES-LAYERING.md                  # 保留
    ├── ARCHITECTURE-V2.md                 # 本文
    ├── GLOSSARY.md                        # 建议新增（非本设计范围）
    └── CONTRIBUTING.md                    # 建议新增（非本设计范围）
```

### 5.3 依赖方向（强约束）

**允许**：

- `pentest-flow`（entry）→ 任意技能：门禁依赖、大文件索引、通道验收等内核级引用
- 技能 → 内核（`requires: [pentest-flow]`）
- 技能 → `_shared`（`../pentest-flow/references/_shared/...`）
- 技能 → 自有 `references/`、`scripts/`
- 技能 → 知识包（通过 `data/` 相对路径或查询脚本）
- 工具 → 全部（只读）

**禁止**：

- **非 entry 技能** → 其他能力包的 `references/` 直接路径引用（应下沉到 `_shared` 或改为声明式 `requires`）
- 技能 → 仓库根以外的路径
- 生成物被手工修改

> 方向性约束：`check_contracts.py` 按 `skill != entry` 判断，entry 自身的跨技能引用合法。

**依赖图规则**：

- 节点 = 技能；边 = `requires`。
- `pentest-flow` 是唯一入口（`entry: true`），`requires: []`。
- 其他 23 个技能必须 `requires` 包含 `pentest-flow`。
- 图必须无环；`check_contracts.py` 强制。

### 5.4 安装单元

- **不变**：`cp -a skills/. <client>/skills/`。
- `_shared` 放在 `skills/pentest-flow/references/_shared/` 内，随整体安装存在；不新增会被误认为技能的顶层目录。
- `meta/` 与 `tools/` 不安装（与现在 `tools/` 不随技能安装一致）。
- `skills/` 内不出现符号链接（Windows 兼容）。

---

## 6. 数据模型

### 6.1 技能清单（SKILL.md frontmatter）

**原则**：顶层只保留 `name` + `description`（客户端标准字段）；所有扩展字段放在 `metadata` 下，避免客户端兼容风险。

```yaml
---
name: web-pentest
description: Web 应用渗透测试 — 面向 Web 应用的分阶段渗透流程，含技术栈识别、目录枚举、认证测试、逻辑漏洞。
metadata:
  # 现有字段（保持）
  layer: "skill"                  # constitution | flow | skill | knowledge
  risk: "medium"                  # none | low | medium | high
  phase: "recon,vuln-discovery"   # 逗号分隔，用于路由排序
  task_types: "pentest"           # 逗号分隔
  target_types: "web,api"         # 可选
  # 新增字段
  version: "0.1.0"                # 语义化版本，必填
  entry: false                    # 是否入口；仅 pentest-flow 为 true
  requires: ["pentest-flow"]      # 加载前置，必填（entry 为 []）
  provides: ["web-testing"]       # 可选，能力标签
  triggers:                       # 可观察信号，必填（entry 可空）
    - "出现 HTTP/HTTPS 端口或 Web 响应"
    - "开始 Web 漏洞测试前"
  load_mode: "on-signal"          # on-signal | always（仅 entry）
---
```

**字段规则**：

| 字段 | 必填 | 类型 | 约束 |
|---|---|---|---|
| `name` | 是 | string | 必须等于目录名 |
| `description` | 是 | string | 40–160 字符，包含触发场景，供自动加载匹配 |
| `metadata.version` | 是 | string | 语义化版本 `X.Y.Z` |
| `metadata.entry` | 是 | bool | 有且仅有一个 `true` |
| `metadata.requires` | 是 | list[string] | 技能 id；非 entry 必须包含 `pentest-flow`；无环 |
| `metadata.triggers` | 是 | list[string] | 非 entry 至少 1 条；不得与同技能其他条目重复 |
| `metadata.phase` | 是 | string | 枚举：`flow/recon/vuln-discovery/exploitation/post-exploitation/reporting/cross-cutting`，可逗号分隔 |
| `metadata.layer` | 是 | string | 枚举：`constitution/flow/skill/knowledge` |
| `metadata.risk` | 是 | string | 枚举：`none/low/medium/high` |
| `metadata.task_types` | 是 | string | 非空 |
| `metadata.provides` | 否 | list[string] | 能力标签 |
| `metadata.load_mode` | 否 | string | 默认 `on-signal` |

**兼容**：

- 现有 24 个技能已具备 `layer/risk/phase/task_types`，只需补 `version/entry/requires/triggers`。
- 现有可选字段（`target_types/tooling/...`）保留，不强制补齐。
- 客户端忽略 `metadata` 下未知字段（Claude Code / Codex / OpenCode / DSH 均按 Markdown + YAML 处理）；实施前做一次四客户端 smoke test（见 §12 R3）。

### 6.2 路由清单（`meta/routing.yaml`）

**原则**：信号只写在技能 frontmatter；`routing.yaml` 只做"分类与顺序"，不重复信号文本。

```yaml
schema_version: 1
entry: pentest-flow
# 所有非 entry 技能的默认前置（可被技能自身 requires 覆盖）
default_requires: [pentest-flow]
# 强制门禁：这些技能的 triggers 命中时，必须出现在 plan.md 的「技能加载」表
mandatory: [recon, web-pentest, cve-triage, ai-mcp-security, exploitation, post-exploitation, vuln-discovery]
# 阶段顺序：生成表按此排序；未列出的阶段排在最后，按 id 字典序
phase_order: [recon, vuln-discovery, exploitation, post-exploitation, reporting, cross-cutting]
# 生成格式
output:
  file: skills/pentest-flow/references/routing.generated.md
  marker_begin: "<!-- BEGIN GENERATED ROUTING -->"
  marker_end: "<!-- END GENERATED ROUTING -->"
```

**生成算法**（`tools/gen_router.py`）：

1. 读取 `skills/*/SKILL.md` 的 frontmatter；解析失败 → 报错退出，不生成。
2. 校验：`entry` 唯一、`requires` 无环、非 entry 均依赖 `pentest-flow`。
3. 分组：
   - `mandatory` 集合中的技能 → 「强制门禁」表；
   - 其余有 `triggers` 的技能 → 「建议加载」表；
   - `entry` → 单独一行置顶。
4. 排序：`phase_order` → `id` 字典序，保证幂等。
5. 输出固定格式（见附录 C），带 `DO NOT EDIT` 头。
6. 同时生成每个技能的前置声明（见 6.2.1）。

**幂等性**：同一输入重复运行输出字节一致；生成器不依赖时间、文件遍历顺序（显式排序）。

**`--check` 模式**：生成到内存，与磁盘文件比较；不一致输出 diff 并退出 1。CI 使用此模式。

**回退模式**（仅 P1 回退时使用，不作为实施路径）：

- 保留手工路由表；
- `gen_router.py --check` 只校验"每个技能恰好出现一次、mandatory 全覆盖、requires 已声明"；
- 主流程按 §8 手工瘦身。
- 该模式能拿到 G1/G3 的部分收益，但 G2 需要手工完成。

#### 6.2.1 前置声明块（生成到每个 SKILL.md）

生成器在 `# 标题` 之后插入以下区块（幂等替换）：

```markdown
<!-- BEGIN GENERATED PREAMBLE -->
> **前置**：本技能不构成授权依据。首次加载先读
> `../pentest-flow/references/constitution.md` §1–§8；产物写入 `Work/OC-<target>/`。
> 路由与门禁见 `../pentest-flow/SKILL.md`。
<!-- END GENERATED PREAMBLE -->
```

- 对 `pentest-flow` 自身不生成（或生成"本技能是入口"版本）。
- 路径按技能目录层级自动计算（`../pentest-flow/...`）。
- 目的：即使用户直接触发某个技能，agent 也会看到宪法入口，缓解问题 B。

### 6.3 知识索引（CVE）

#### 6.3.1 `cve-index.json`（新增）

```json
{
  "schema_version": 1,
  "generated_from": "data/aig-vuln/**/*.yaml",
  "total": 2440,
  "entries": [
    {
      "cve": "CVE-2025-55182",
      "component": "open-webui",
      "component_dir": "open-webui",
      "severity": "HIGH",
      "rule": "version < \"0.5.2\"",
      "path": "open-webui/CVE-2025-55182.yaml"
    }
  ]
}
```

- 体积估算：2440 条 × ~200 字节 ≈ 500 KB，可接受；如过大可改为按组件分片。
- 生成：`tools/check_data.py --build-index` 或独立 `tools/build_index.py`（建议合并到 `check_data.py --write`，保持工具数少）。
- 非 CVE 规则（256 条）标记 `kind: "advisory"`，不进入 `entries` 或单独 `advisories` 数组；文档统一称"漏洞规则"。

#### 6.3.2 `aliases.json`（新增）

```json
{
  "schema_version": 1,
  "aliases": {
    "openwebui": "open-webui",
    "lobehub": "lobechat",
    "litellm": "LiteLLM"
  }
}
```

- 归一化规则：小写、去空格/连字符/下划线后比较；别名表显式覆盖已知变体。
- `query_cve.py` 查询前先归一化；`check_data.py` 校验所有组件目录都有 canonical 名。

#### 6.3.3 查询接口（`tools/query_cve.py`）

```bash
# 组件 + 版本
python tools/query_cve.py --component langflow --version 1.2.3
python tools/query_cve.py --component openwebui --version 0.5.0 --json

# CVE 反查
python tools/query_cve.py --cve CVE-2025-55182

# 列出组件
python tools/query_cve.py --list-components
```

输出（人类可读）：

```text
component: open-webui (canonical: open-webui)
version:   0.5.0
matched:
  - CVE-2026-XXXX  HIGH    version < "0.5.2"    open-webui/CVE-2026-XXXX.yaml
unverified:
  - CVE-2025-46719 (rule 为空，需人工核对版本)
```

JSON 输出固定字段：`component/version/matched/unverified/errors`。

**版本比较规则**：

- 归一化：去前导 `v`，按 `.` `-` `+` 分段；数字段按整数比较，非数字段按字典序；预发布（alpha/beta/rc）低于同版本正式版。
- `rule` 语法支持：`version < "X"`、`<=`、`>`、`>=`、`==`；允许外层括号；不支持复合布尔（`and/or`）→ 归入 `unverified` 并输出原因。
- 无法解析的版本 → `unverified`，**不猜测**。

### 6.4 产物契约（`meta/artifacts.schema.json`）

**范围**：只约束结构，不约束语义真实性。

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Kestrel engagement artifacts",
  "type": "object",
  "properties": {
    "plan": {
      "required_sections": [
        "## 攻击面账本", "## 深度清单", "## 覆盖清单",
        "## 技能加载", "## 复盘", "## 结束检查"
      ],
      "ledger": {
        "required_columns": ["#", "资产", "端口", "服务", "接口/参数", "方法", "类别", "状态", "证据", "下一步"],
        "status_enum": ["untested", "testing", "confirmed", "candidate", "negative", "blocked", "n/a"]
      },
      "checklist": {
        "required_columns": ["方向", "清单项", "状态", "证据/说明"],
        "status_enum": ["todo", "doing", "done", "n/a", "blocked"]
      },
      "coverage": {
        "required_columns": ["类别", "状态"],
        "status_enum": ["confirmed", "candidate", "negative", "blocked", "not_applicable"],
        "web_categories": ["sqli", "xss", "csrf", "idor", "auth_bypass", "file_upload",
          "path_traversal", "ssrf", "xxe", "ssti", "deserialization", "request_smuggling",
          "race_condition", "info_disclosure", "business_logic", "default_credential", "cve"]
      }
    },
    "findings": {
      "required_fields": ["目标", "路径/参数", "风险", "证据", "状态"],
      "status_enum": ["confirmed", "candidate", "negative"],
      "confirmed_requires_evidence": true
    }
  }
}
```

- 检查器读取该文件，不再硬编码枚举（当前硬编码在 `check_artifacts.py:20-36`）。
- 保留少量语义规则：状态-证据一致性、复盘审计、`untested` 必须下一步、`/tmp` 禁令。
- **兼容**：schema 缺省时回退到内置默认值；旧产物缺章节 → FAIL（与现在一致），旧复盘格式 → WARN。

### 6.5 证据哈希链（可选，默认关闭）

#### findings 条目

在现有字段后新增两行（可选）：

```markdown
- 证据：evidence/src/80_home.html
- 证据哈希：sha256:9f2c...（生成命令：python tools/check_artifacts.py --stamp-hashes <work>）
```

#### approvals 追加链

```markdown
### A-003 2026-11-26T10:15:00Z

- 操作：上传测试文件 /tmp/oc-test.txt → 目标 /uploads/
- 授权：用户明确回复「授权」
- 回滚：DELETE /uploads/oc-test.txt
- prev: sha256:4a1f...
- hash: sha256:8b3e...
```

链式计算：`hash = sha256(prev + 本条正文（不含 hash 行）)`；首条 `prev = "genesis"`。

**校验**：

- `check_artifacts.py --verify-hashes <work>`：重算 evidence 文件哈希 + 校验 approvals 链；
- 默认不开启；开启后 FAIL 需显式修复；
- 旧产物无哈希 → WARN，不 FAIL。

**边界**：哈希只证明"记录后未被改动"，不能证明记录本身真实；不能替代用户确认与外部存证。

---

## 7. 改造详设

### 7.1 R1：路由声明化与生成

#### 动机

- 主流程 445/450 行，新增技能必须改主流程（问题 A）；
- 路由表与技能元数据双写，容易漂移；
- 12/24 技能无前置声明（问题 B）。

#### 设计

1. 24 个技能补 `version/entry/requires/triggers`（§6.1）。
2. 新增 `meta/routing.yaml`（§6.2）。
3. 新增 `tools/gen_router.py`：
   - 默认：写入 `routing.generated.md` + 各技能 preamble；
   - `--check`：只校验，不写；
   - `--dry-run`：输出将要变更的文件列表与 diff 摘要。
4. 主流程改造：
   - 删除 196-248 行的「技能路由」大表，替换为：
     ```markdown
     ## 技能路由

     路由按可观察信号触发，不按场景名。完整信号表见
     `references/routing.generated.md`；本节只保留不可省略的门禁原则。

     1. 目标已确定 → 必须先加载 `recon`。
     2. 出现 HTTP/HTTPS 端口或 Web 响应 → 必须先加载 `web-pentest`。
     3. 拿到组件名 + 版本 → 必须先加载 `cve-triage`。
     4. 出现 AI/Agent/MCP 端点 → 必须先加载 `ai-mcp-security`。
     5. 投递命令执行类 payload 前 → 必须先加载 `exploitation`，且资产基线已完成。
     6. 拿到 exec/shell → 必须先加载 `post-exploitation`，第一动作是通道判定。
     7. 开始列接口面深度清单前 → 必须先加载 `vuln-discovery`。
     ```
   - 「技能加载门禁」保留（表结构与记录要求），但不再重复技能清单。
5. 生成物格式见附录 C，包含：强制门禁表、建议加载表、技能清单（24 行，含 version/requires）。

#### 幂等与冲突

- 同一信号命中多个技能：按 `phase_order` → `id` 排序，全部列出，不合并。
- 同一技能多条 triggers：保留全部，表格内换行或分号分隔；生成器不做语义去重。
- `mandatory` 中的技能若无 triggers → 生成失败，提示补 triggers。

#### 验收

```bash
python tools/gen_router.py --check          # 0
python tools/check_contracts.py             # 0
grep -c "^|" skills/pentest-flow/references/routing.generated.md  # ≥ 24
wc -l skills/pentest-flow/SKILL.md          # ≤ 250
grep -L "BEGIN GENERATED PREAMBLE" skills/*/SKILL.md  # 只允许 pentest-flow
```

#### 回退

- 删除 `meta/routing.yaml` 与生成物，`git checkout -- skills/pentest-flow/SKILL.md`；
- 技能 frontmatter 的新增字段可保留（不影响客户端），也可批量删除；
- 回退成本 < 30 分钟。

### 7.2 R2：依赖声明化与共享知识

#### 动机

- 167 处跨技能引用、7 组重复文件、2 个复制后未引用（问题 C）；
- 移动/重命名技能会断链；
- 共享知识没有"权威源"。

#### 设计

**第一步：共享知识下沉到内核。**

| 现有文件 | 新位置（权威源） | 引用方 |
|---|---|---|
| `android-pentest/references/android-static-triage-and-callflow.md` 等 7 个 | `pentest-flow/references/_shared/android/` | `android-pentest`、`client-reverse` |
| `client-reverse/references/02-client-api-reverse-and-burp.md` | `pentest-flow/references/_shared/client/02-client-api-reverse-and-burp.md` | `client-reverse`、`android-pentest` |
| `waf-bypass/scripts/encode.py` + `ai-mcp-security/scripts/encodings.py` | `pentest-flow/scripts/shared/encode.py` | `waf-bypass`、`ai-mcp-security` |

- 每个原技能目录保留一层薄引用（不复制正文）：
  - `android-pentest/references/android-static-triage-and-callflow.md` 改为 3 行转发：
    ```markdown
    # 已迁移
    本文件已移至 `../../pentest-flow/references/_shared/android/android-static-triage-and-callflow.md`。
    保留此占位以兼容旧链接；新引用请直接指向新位置。
    ```
  - 或者直接删除并在 SKILL.md 中改路径（更干净，但会破坏外部对旧路径的引用）。**推荐直接删除 + 改 SKILL.md**，因为项目尚未发布、无外部消费者。
- 引用路径规则：
  - 从 `skills/<skill>/SKILL.md`：`../pentest-flow/references/_shared/android/x.md`
  - 从 `skills/<skill>/references/y.md`：`../../pentest-flow/references/_shared/android/x.md`
- 脚本调用：`$KESTREL_SKILLS_ROOT/pentest-flow/scripts/shared/encode.py`；主流程的"定位技能脚本"逻辑已支持 `$KESTREL_SKILLS_ROOT/<skill>/`（`SKILL.md:113-127`），只需补一条说明。

**第二步：合并编码脚本。**

- 以 `waf-bypass/scripts/encode.py`（212 行）为基线，吸收 `encodings.py`（221 行）的 13 种变换；
- 增加 `--profile waf|aig` 控制默认变换表；
- 保留两处调用方式：
  ```bash
  python3 "$KS/pentest-flow/scripts/shared/encode.py" --profile waf --chain base64,homoglyph --text '...'
  python3 "$KS/pentest-flow/scripts/shared/encode.py" --profile aig --list
  ```
- 迁移后删除两处旧脚本；SKILL.md 更新调用路径。

**第三步：依赖图校验。**

`tools/check_contracts.py` 检查：

1. 每个 `requires` 指向存在的技能；
2. 无环（DFS）；
3. 非 entry 技能 `requires` 包含 `pentest-flow`；
4. `entry` 唯一；
5. 禁止**非 entry 技能**直接引用其他能力包的 `references/` 路径（正则扫描 Markdown 链接与反引号路径；白名单：`_shared`、本技能目录、entry）。entry（`pentest-flow`）可引用任意技能。

**第四步：链接检查脚本化。**

`tools/check_links.py`：

- 扫描所有 `skills/**/*.md` 的反引号路径与 `[text](path)`；
- 排除交战产物名（`plan.md/findings.md/notes.md/approvals.md/cleanup.md/challenges.md/report.md/roe.yaml`）与外部示例（`CLAUDE.md/AGENTS.md`、URL）；
- 解析相对路径（文件所在目录 → skills 根 → 仓库根）；
- 通配符、`<target>` 占位跳过；
- 输出断链列表，退出码 0/1。

#### 验收

```bash
python tools/check_links.py                 # 0 断链
python tools/check_contracts.py             # 0 issue
# 完全重复文件 0
python - <<'PY'
import hashlib,pathlib,collections
g=collections.defaultdict(list)
for p in pathlib.Path('skills').rglob('*'):
    if p.is_file() and p.suffix in ('.md','.py'): g[hashlib.md5(p.read_bytes()).hexdigest()].append(str(p))
print(sum(1 for v in g.values() if len(v)>1))
PY
# 旧路径不再被引用
grep -rn "references/android-static-triage-and-callflow.md" skills --include="*.md" | grep -v "_shared" | wc -l   # 0
```

#### 回退

- `git revert` 本阶段提交；
- 共享文件恢复到原技能目录，SKILL.md 引用改回；
- 编码脚本恢复两处独立副本。

#### 风险

- 引用路径变长，agent 可能定位失败 → 主流程"定位技能脚本"补充 `_shared` 示例；错误提示明确"整体安装"。
- `_shared` 位于 `pentest-flow/references/`，会让该目录从 5 个文件增至 ~15 个，但不影响按需加载（只按路径读）。

### 7.3 R3：离线知识查询

#### 动机

- 2440 条数据只能 grep + 人读（问题 D）；
- 组件别名漏检；
- 版本规则无解析器；
- 数据快照无更新 runbook。

#### 设计

1. **索引构建**（`tools/check_data.py --write`）：
   - 解析全部 YAML（用 PyYAML；CI 安装，运行时不需要）；
   - 生成 `cve-index.json`、`aliases.json`；
   - 校验：YAML 可解析、`info.cve` 唯一性（跨组件重复需在 `aliases` 或白名单说明）、`rule` 语法、组件目录与 canonical 名；
   - `--check` 模式只校验不写。
2. **查询工具**（`tools/query_cve.py`）：
   - 零依赖实现（读 JSON 索引，不解析 YAML；索引由开发时生成）；
   - 支持 `--component/--version/--cve/--list-components/--json`；
   - 版本比较见 §6.3.3；
   - 未匹配 → 退出码 0 但输出 `matched: []`；参数错误 → 2。
3. **文档更新**：
   - `cve-triage/SKILL.md` 的"三级查询"增加第 1.5 层：`query_cve.py`（比 grep 快、可版本匹配）；
   - `INDEX.md` 改为"2440 条漏洞规则（2184 CVE + 256 安全公告/供应链规则）"；
   - 新增 `docs/UPDATE-DATA.md`：上游地址、字段映射、生成索引、校验、许可检查。
4. **许可声明（不拆包，Q5 已定 B）**：
   - 数据集保持在 `ai-mcp-security/data/eval-datasets/`，不移动目录，避免技能内 4 处引用与 README / NOTICE 断链；
   - `README` 与 `THIRD_PARTY_NOTICES.md` 写明数据集许可（含 CC-BY-NC 的商用限制）；
   - `check_data.py` 校验 `THIRD_PARTY_NOTICES.md` 覆盖全部数据集。

#### 验收

```bash
python tools/check_data.py --check          # 0 issue
python tools/query_cve.py --component openwebui --version 0.5.0 --json | jq '.matched|length'   # ≥1
python tools/query_cve.py --cve CVE-2025-55182 --json | jq '.matched|length'                     # ≥1
# 10 个样例（含版本边界、别名、无匹配、rule 为空）全部通过
python -m unittest tools.test_query_cve -v
```

#### 回退

- 删除新增索引与脚本，恢复 `SKILL.md` 的三级查询表；
- 数据目录不移动（Q5 已定 B）；许可声明变更可独立回退。

### 7.4 R4：产物契约与检查器分层

#### 动机

- `check_artifacts.py` 500+ 行、20+ 检查项，只有 6 个测试；
- 枚举硬编码在代码里（`check_artifacts.py:20-36`），规则与工具仍有同步成本；
- 证据只检查存在性，空文件可通过（`check_artifacts.py:445-451`）。

#### 设计

**分层**：

| 层 | 内容 | 实现 | 失败级别 |
|---|---|---|---|
| L1 结构 | 章节、表头、枚举、必需字段 | `meta/artifacts.schema.json` 驱动 | FAIL |
| L2 语义 | 状态-证据一致、`untested` 有下一步、复盘审计、路径入账 | 现有正则逻辑，保留 | FAIL |
| L3 证据 | 文件存在 + 可选哈希 + approvals 链 | `--verify-hashes` | 默认 WARN，开启后 FAIL |

**改造点**：

1. 新增 `meta/artifacts.schema.json`；`check_artifacts.py` 启动时读取，缺省回退内置默认值。
2. 保留 `parse_section_table/section_lines` 等 Markdown 解析函数；枚举从 schema 读。
3. 新增 `--verify-hashes` 与 `--stamp-hashes`：
   - `--stamp-hashes`：为 `findings.md` 中 `confirmed` 条目补齐 `证据哈希` 行（需用户确认后运行，会改文件）；
   - `--verify-hashes`：重算并校验；旧产物无哈希 → WARN。
4. 测试扩展：
   - 每个检查项 ≥1 正例 + 1 反例；
   - 新增 `test_query_cve.py`、`test_check_contracts.py`、`test_check_links.py`、`test_check_data.py`；
   - 目标 ≥30 个用例。
5. 检查器仍明确"不是结束门禁"（`tools/README.md:9`），不改变定位。

#### 验收

```bash
python -m unittest discover -s tools -p 'test_*.py' -v   # ≥30 tests, 0 fail
python tools/check_artifacts.py <样例>                   # 旧产物 WARN 不 FAIL
python tools/check_artifacts.py --verify-hashes <样例>   # 哈希正确时 0
```

#### 回退

- schema 文件可选；检查器保留内置默认值，删除 schema 即回退到当前行为；
- 哈希功能默认关闭，回退无影响。

---

## 8. 主流程瘦身

### 8.1 保留 / 移出清单

**必须保留在主流程**（不可省略的判断与门禁）：

- 节奏与播报：**只保留"必须播三件事 + 播报格式见 references/reporting.md"**（约 6 行）；
- 产物位置与 `plan.md` 必需章节（约 20 行）；
- 风险与授权（引用宪法，约 10 行）；
- 不可逆写入（引用宪法 W1–W6，约 5 行）；
- 回连与通道（引用宪法，约 3 行）；
- 技能路由原则 + 7 条强制门禁（约 15 行）；
- 技能加载门禁（记录要求，约 10 行）；
- 资产基线门禁（约 15 行）；
- 方向深度清单 / 攻击面账本 / Web 覆盖清单（约 20 行）；
- 挖掘循环 + 5 轮结束条件（约 10 行）；
- 「继续」next-3（约 12 行）；
- 结束检查表（保留 28 行，或移出后保留 6 行硬条件）；
- 记录格式（findings 模板，约 18 行）；
- RCE 优先（约 10 行）。

**移到 references**：

| 章节 | 现状行号 | 行数 | 去向 | 主流程保留 |
|---|---|---|---|---|
| 节奏与播报细节 | 13-94 | 82 | `references/reporting.md` | 6 行 |
| 定位技能脚本 | 111-127 | 17 | `references/tooling.md` | 4 行 |
| 技能路由建议表 | 218-240 | 23 | `routing.generated.md` | 0 |
| 复盘审计维度 X/A | 307-333 | 27 | `references/review-audit.md` | 6 行 |
| 已有工具优先 | 380-390 | 11 | `references/tooling.md` | 4 行 |
| 工具获取与镜像 | 392-396 | 5 | `references/tooling.md` | 2 行 |
| 查资料本地优先 | 398-416 | 19 | `references/tooling.md` | 4 行 |

### 8.2 目标行数

- 现状：445 行；
- 移出约 184 行，保留摘要约 26 行，新增说明约 10 行；
- 目标：**约 250 行**（≤250 验收）。

**注意**：移出的规则仍在唯一源（references），不是删除；主流程必须在对应位置写"何时读哪个文件"，否则 agent 不会加载。

---

## 9. 兼容性与安装

### 9.1 四客户端

| 客户端 | 技能目录 | 本设计影响 | 验证方式 |
|---|---|---|---|
| Claude Code | `~/.claude/skills/` | frontmatter 新增 metadata 字段；`_shared` 无 SKILL.md | 安装后 `claude` 启动，确认 24 个技能可列、`_shared` 不被当作技能 |
| Codex | `~/.codex/skills/` | 同上 | 同上 |
| OpenCode | `~/.config/opencode/skills/` | 同上 | 同上 |
| DSH | `~/.dsh/skills/` | 同上 | 同上 |

**风险**：`_shared` 位于 `pentest-flow/references/` 下，不是技能目录顶层，客户端不会扫描为技能——这是选择 S2（内核附属）而非 `skills/_shared/` 的主要原因。

### 9.2 旧产物

- 旧 `Work/OC-*` 的交战产物：检查器读取路径不变；
- 旧复盘格式（无 `[扩展-]`）：WARN 不 FAIL（保持 `check_artifacts.py:343-345` 行为）；
- 旧 RoE 顶层 `exclude`：按新语义读取，不报错（保持 `SKILL.md:169` 行为）；
- 新增哈希字段：可选，旧产物无哈希只 WARN。

### 9.3 旧引用

- 外部若已引用 `android-pentest/references/android-static-triage-and-callflow.md` 等旧路径，迁移后失效；
- 项目尚未发布（13 次提交、无 tag），判定为可接受的 breaking change；
- 如需保守，可保留 3 行转发占位文件（见 §7.2），但会重新引入重复感。**建议直接删除**。

### 9.4 安装

- 主路径不变：`cp -a skills/. <client>/skills/`；
- `_shared` 随整体安装存在；
- 可选 `tools/install.py`：
  - 校验目标目录、技能数、Python 版本；
  - 生成 `install-manifest.json`（技能版本、文件哈希）；
  - `--doctor` 自检跨技能引用可解析；
  - 不改变手动复制路径。

---

## 10. 迁移计划

### P0：校验基础设施（2–3 天，不改内容）

| 项 | 内容 |
|---|---|
| 新增 | `meta/skill.schema.json`、`meta/routing.yaml`（初版）、`tools/check_contracts.py`、`tools/check_links.py`、`tools/check_data.py`、`.github/workflows/ci.yml` |
| 修改 | 24 个 `SKILL.md` 补 `version/entry/requires/triggers`（不改正文、不改路由）；**triggers 从现有主流程 196–248 行路由表逐条迁移，不重新创作** |
| 验收 | `check_contracts` / `check_links` / `check_data --check` 全部 0；现有行为不变 |
| 回退 | 删除新增文件；frontmatter 新字段可保留 |
| 风险 | 低 |

**P0 是唯一必须做的阶段**：即使后续全部不做，CI + 契约校验也能把当前"一次性正确"变成"持续正确"。

### P1：路由生成 + 主流程瘦身（1–2 天）

| 项 | 内容 |
|---|---|
| 新增 | `tools/gen_router.py`、`references/routing.generated.md`、`references/reporting.md`、`references/review-audit.md` |
| 修改 | 主流程删除大表与细节段，插入引用；24 个技能插入 preamble |
| 验收 | §7.1 验收命令全过；主流程 ≤250 行 |
| 回退 | `git revert`；生成物删除 |
| 风险 | 中（主流程缩短可能让 agent 漏读细节；保留强制门禁摘要缓解） |

### P2：共享知识去重（1–2 天）

| 项 | 内容 |
|---|---|
| 新增 | `pentest-flow/references/_shared/android/`、`_shared/client/`、`pentest-flow/scripts/shared/encode.py` |
| 修改 | `android-pentest`、`client-reverse` 的 SKILL.md 路径；删除 7 组重复 + 2 个未引用文件；合并编码脚本 |
| 验收 | 重复文件 0；断链 0；`check_contracts` 禁止跨技能直引；脚本 `--list` 正常 |
| 回退 | `git revert`；恢复副本 |
| 风险 | 中（路径变长；需四客户端 smoke test） |

### P3：知识查询 + 证据哈希（2–3 天）

| 项 | 内容 |
|---|---|
| 新增 | `cve-index.json`、`aliases.json`、`tools/query_cve.py`、`test_query_cve.py`、`docs/UPDATE-DATA.md` |
| 修改 | `cve-triage/SKILL.md` 查询层；`INDEX.md` 数字表述；`check_artifacts.py` 增加 `--verify-hashes/--stamp-hashes` |
| 验收 | §7.3 验收；10 个查询样例；旧产物 WARN 不 FAIL |
| 回退 | 删除索引/脚本；恢复文档 |
| 风险 | 中（版本比较边界；用测试覆盖） |

### P4：可选（按需）

- `tools/install.py` + `--doctor`；
- 受限数据不拆包；许可限制写入 NOTICE / README；
- `check_artifacts.py` 完全 schema 化；
- 证据哈希默认开启（需用户决策）。

### 工时汇总

| 阶段 | 工时 | 可独立交付 |
|---|---|---|
| P0 | 1–2 天 | 是（推荐先做） |
| P1 | 1–2 天 | 是 |
| P2 | 1–2 天 | 是 |
| P3 | 2–3 天 | 是 |
| P4 | 1–2 天 | 是 |
| **合计** | **6–11 天** | 每阶段可独立回退 |

---

## 11. 验收标准

### 11.1 量化指标

| # | 指标 | 目标 | 检查方式 |
|---|---|---|---|
| A1 | 主流程行数 | ≤250 | `wc -l` |
| A2 | 技能 manifest 完整率 | 24/24 | `check_contracts.py` |
| A3 | 路由覆盖 | 24/24 | `gen_router.py --check` |
| A4 | preamble 覆盖 | 23/23（entry 除外） | `grep -L` |
| A5 | 仓库内断链 | 0 | `check_links.py` |
| A6 | 完全重复文件 | 0 | MD5 脚本 |
| A7 | 跨技能直接 references 引用 | 0（白名单除外） | `check_contracts.py` |
| A8 | CVE 查询样例 | 10/10 | `test_query_cve.py` |
| A9 | 检查器测试 | ≥30 用例，全过 | `unittest discover` |
| A10 | 旧产物兼容 | WARN 不 FAIL | 样例目录 |
| A11 | 安装后技能数 | 24（`_shared` 不计） | 四客户端 smoke test |
| A12 | CI 全绿 | 是 | GitHub Actions |

### 11.2 命令清单

```bash
# 仓库级
python tools/check_contracts.py
python tools/gen_router.py --check
python tools/check_links.py
python tools/check_data.py --check
python tools/check_skill_budget.py
python -m unittest discover -s tools -p 'test_*.py' -v

# 产物级
python tools/check_artifacts.py Work/OC-10.0.0.5
python tools/check_artifacts.py --verify-hashes Work/OC-10.0.0.5

# 查询级
python tools/query_cve.py --component langflow --version 1.2.3
python tools/query_cve.py --cve CVE-2025-55182 --json
```

### 11.3 兼容性验收

- [ ] 4 个客户端安装后均能列出 24 个技能，`_shared` 不被加载；
- [ ] 旧 `Work/OC-*` 样例通过 `check_artifacts.py`（仅 WARN）；
- [ ] `cp -a skills/.` 安装路径可用；
- [ ] 旧 RoE（顶层 `exclude`）可读；
- [ ] 旧复盘（无 `[扩展-]`）WARN 不 FAIL；
- [ ] Python 3.9 下全部脚本可运行（`from __future__ import annotations` 已在需要处使用）。

---

## 12. 风险登记

| # | 风险 | 概率 | 影响 | 缓解 | 回退 |
|---|---|---|---|---|---|
| R1 | 客户端把 `_shared` 当技能或扫描报错 | 低 | 中 | 放在 `pentest-flow/references/` 下，不在技能顶层；四客户端 smoke test | 移到 `skills/pentest-flow/references/shared/` 以外的隐藏目录，或改用 `install.py --flatten` |
| R2 | 生成物与手工编辑冲突 | 中 | 中 | `DO NOT EDIT` 标记 + `--check` CI + 文档说明 | 删除生成物，恢复手工表 |
| R3 | frontmatter 新字段被客户端拒绝 | 低 | 高 | 全部放在 `metadata` 下；先做单客户端验证 | 删除新字段，保留 schema 在 meta 侧 |
| R4 | 主流程瘦身后 agent 漏读细节 | 中 | 高 | 强制门禁保留在主流程；每个移出段落写明"何时读"；P1 后用真实交战回归 2–3 轮 | `git revert` |
| R5 | `query_cve` 版本比较错误导致漏报 | 中 | 高 | 语义化版本测试矩阵（含预发布、非数字段）；无法解析 → `unverified` 不猜 | 停用查询，回退 grep |
| R6 | 证据哈希破坏旧产物 | 低 | 中 | 默认关闭；`--verify-hashes` 才 FAIL；旧产物 WARN | 删除哈希行 |
| R7 | 数据许可处理不当 | 低 | 高 | 数据不拆包；`check_data` 校验 NOTICE / README 的许可声明 | 补声明 |
| R8 | 生成物造成 diff 噪音 | 中 | 低 | 固定排序、固定格式、无时间戳 | 只改生成器，不重生成 |
| R9 | 共享知识迁移后旧链接失效 | 中 | 中 | 项目未发布，判定可接受；如需兼容保留 3 行转发 | 恢复副本 |

---

## 13. 评审结论（Q1–Q6）

| # | 问题 | 选项 | 决定 |
|---|---|---|---|
| Q1 | 是否接受"开发时生成、生成物入库"？这会修改 `docs/RULES-LAYERING.md` 第六节"不引入构建步骤"的表述 | A. 接受（生成物入库，用户零构建）<br>B. 不接受（只做 CI 校验，手工维护） | **A（已定）**：运行时仍零依赖；生成物可审查、可回退；配套 `--check` |
| Q2 | 共享知识放哪里？ | A. `skills/pentest-flow/references/_shared/`（内核附属）<br>B. `skills/_shared/`（顶层）<br>C. 保持跨技能直接引用 | **A（已定）**：不新增技能顶层目录，客户端风险最低 |
| Q3 | 是否删除 7 组重复文件并改引用？ | A. 删除 + 改引用<br>B. 保留转发占位 | **A（已定）**：项目未发布，无外部消费者；先落 `check_links.py` |
| Q4 | 是否引入证据哈希？ | A. 默认关闭、可选开启<br>B. 默认开启<br>C. 不做 | **A（已定）**：先解决"能验证"，不强制改变旧流程；只覆盖 evidence + approvals |
| Q5 | 受限数据集是否拆为可选包？ | A. 拆 `data-optional/`（默认装或默认不装）<br>B. 保持现状 + 文档声明 | **B（已定，评审调整）**：不拆包，保持路径稳定；许可限制写入 README / NOTICE。曾考虑拆包 + 默认安装，因 `cp -a` 无法排除、4 处技能内引用需同步而放弃 |
| Q6 | 版本起点 | A. 套件 `v0.1.0`，技能 `0.1.0`<br>B. 直接 `v1.0.0` | **A（已定）**：当前是草案阶段，`1.0` 会误导稳定性 |

---

## 14. 附录

### 附录 A：SKILL.md 示例（`web-pentest`）

```yaml
---
name: web-pentest
description: Web 应用渗透测试 — 面向 Web 应用的分阶段渗透流程，含技术栈识别、目录枚举、认证测试、逻辑漏洞。
metadata:
  version: "0.1.0"
  layer: "skill"
  risk: "medium"
  phase: "recon,vuln-discovery"
  task_types: "pentest"
  target_types: "web,api"
  entry: false
  requires: ["pentest-flow"]
  provides: ["web-testing"]
  triggers:
    - "出现 HTTP/HTTPS 端口或 Web 响应"
    - "开始 Web 漏洞测试前"
---
```

### 附录 B：`meta/routing.yaml` 示例

```yaml
schema_version: 1
entry: pentest-flow
default_requires: [pentest-flow]
mandatory:
  - recon
  - web-pentest
  - cve-triage
  - ai-mcp-security
  - exploitation
  - post-exploitation
  - vuln-discovery
phase_order:
  - recon
  - vuln-discovery
  - exploitation
  - post-exploitation
  - reporting
  - cross-cutting
output:
  file: skills/pentest-flow/references/routing.generated.md
  marker_begin: "<!-- BEGIN GENERATED ROUTING -->"
  marker_end: "<!-- END GENERATED ROUTING -->"
```

### 附录 C：`routing.generated.md` 示例（片段）

```markdown
<!-- DO NOT EDIT: generated by tools/gen_router.py -->
# 技能路由（生成物）

> 本文件由 `tools/gen_router.py` 生成。修改技能 frontmatter 后运行：
> `python tools/gen_router.py && python tools/gen_router.py --check`

## 强制门禁（缺行不得进入对应阶段）

| 观察到的信号 | 加载 | 依据 |
|---|---|---|
| 目标已确定（IP / 域名 / URL） | `recon` | 侦察前 |
| 出现 HTTP/HTTPS 端口或 Web 响应 | `web-pentest` | Web 漏洞测试前 |
| 拿到组件名 + 版本 | `cve-triage` | CVE 匹配 / 利用前 |
| 发现 AI / Agent / MCP 端点 | `ai-mcp-security` | AI 动态 payload 前 |
| 打命令执行类 payload 前 | `exploitation` | 资产基线门禁完成后 |
| 拿到 exec / shell 能力 | `post-exploitation` | 第一动作是通道判定 |
| 开始列接口面深度清单前 | `vuln-discovery` | 接口面清单来源 |

## 建议加载（信号出现才加载）

| 观察到的信号 / 当前动作 | 加载 |
|---|---|
| 请求被 WAF 拦截（403 / 406 / 拦截页） | `waf-bypass` |
| 遇到编码 / 哈希 / 加密数据要还原 | `crypto-toolkit` |
| 需要完整攻击链路（K8s / CI-CD / 云 / 供应链） | `redteam-playbooks` |
| ... | ... |

## 技能清单（24）

| 技能 | 版本 | 前置 | 阶段 |
|---|---|---|---|
| pentest-flow | 0.1.0 | — | flow |
| recon | 0.1.0 | pentest-flow | recon |
| ... | ... | ... | ... |
```

### 附录 D：`cve-index.json` 片段

```json
{
  "schema_version": 1,
  "total": 2440,
  "entries": [
    {
      "cve": "CVE-2026-55638",
      "component": "9router",
      "component_dir": "9router",
      "severity": "HIGH",
      "rule": "version < \"0.5.2\"",
      "path": "9router/CVE-2026-55638.yaml"
    }
  ],
  "advisories": [
    {
      "id": "GHSA-26jh-r8g2-6fpr",
      "component": "gradio",
      "path": "gradio/GHSA-26jh-r8g2-6fpr.yaml"
    }
  ]
}
```

### 附录 E：证据哈希格式

```markdown
## F-003 未授权访问管理接口 — confirmed

- 目标：10.0.0.5:8080
- 路径/参数：GET /admin/users
- 风险：HIGH
- 证据：evidence/src/8080_admin_users.json
- 证据哈希：sha256:9f2c1d...
- 状态：confirmed
```

```markdown
### A-003 2026-11-26T10:15:00Z

- 操作：上传测试文件至 /uploads/oc-test.txt
- 授权：用户明确回复「授权」
- 回滚：DELETE /uploads/oc-test.txt
- prev: sha256:4a1f...
- hash: sha256:8b3e...
```

### 附录 F：CI 工作流

```yaml
name: kestrel-ci

on:
  push:
  pull_request:

jobs:
  check:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.9", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dev-only PyYAML
        run: python -m pip install pyyaml
      - name: Contracts
        run: python tools/check_contracts.py
      - name: Router
        run: python tools/gen_router.py --check
      - name: Links
        run: python tools/check_links.py
      - name: Data
        run: python tools/check_data.py --check
      - name: Budget
        run: python tools/check_skill_budget.py
      - name: Unit tests
        run: python -m unittest discover -s tools -p 'test_*.py' -v
```

> 说明：PyYAML 仅用于 CI/开发时校验与索引构建；运行时技能脚本仍只用标准库。

### 附录 G：与现有"不做什么"的对照

`docs/RULES-LAYERING.md:177-182` 当前承诺与本设计的关系：

| 现有承诺 | 本设计 | 结论 |
|---|---|---|
| 不引入构建步骤或运行时 | 引入**开发时**生成/校验；生成物入库；用户安装无需构建 | **已修订**（Q1 已定） |
| 不合并技能，24 个保持不动 | 不合并；仅移动共享文件 | 保持 |
| 不改安装方式（`cp -a skills/.`） | 主路径不变；`_shared` 随整体安装 | 保持 |
| 不追求 100% 无重复：L0/L1 少量交叉可接受 | 仍是目标，不强制清零 | 保持 |

---

## 15. 评审检查表

评审时请逐项确认：

- [x] Q1–Q6 六个开放问题已有结论；
- [x] 共享知识位置 `pentest-flow/references/_shared/`（随 Q2 已定）；
- [x] 删除 7 组重复文件（随 Q3 已定）；
- [x] 证据哈希默认关闭（随 Q4 已定）；
- [x] 版本起点 `v0.1.0`（随 Q6 已定）；
- [ ] P0 是否立即执行（建议先做，独立产生价值）；
- [ ] 主流程目标行数 250 是否可接受（若不同意，调整 §8 移出清单）；
- [ ] 四客户端 smoke test 由谁执行、何时执行。

## 16. 实施记录（2026-11-26）

| 阶段 | 状态 | 交付 |
|---|---|---|
| P0 校验基础设施 | ✅ 完成 | `meta/routing.yaml`、`meta/skill.schema.json`、`check_contracts.py`、`check_links.py`、`check_data.py`、CI；24 个 frontmatter |
| P1 路由生成 + 瘦身 | ✅ 完成 | `gen_router.py`、`routing.generated.md`、23 个 preamble；主流程 450 → 238 行 |
| P2 共享知识去重 | ✅ 完成 | `_shared/android/`（9 文件）、`_shared/client/`；完全重复 0；`encode.py` 合并 |
| P3 知识查询 + 哈希 | ✅ 完成 | `build_index.py`、`cve-index.json`、`query_cve.py`（技能内）、`--stamp-hashes/--verify-hashes`、14 个测试 |
| P4 可选 | ⏸ 未做 | `install.py`、schema 化、哈希默认开启（Q4 已定关闭）；许可声明已满足 |

**验收状态**：`gen_router --check`、`check_contracts`、`check_links`、`build_index --check`、`check_data --check`、`check_skill_budget` 全部 PASS；单元测试 20 个通过。
