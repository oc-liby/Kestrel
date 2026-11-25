# tools

可选辅助工具，不随技能安装。

## check_artifacts.py

结束前静态格式检查，帮助发现 `plan.md` / `findings.md` 的结构问题。

**它不是结束门禁。** 结束条件以 `plan.md` 的 `## 结束检查` 表和用户确认为准；
本工具不能替代证据审计，也不能证明测试质量。

```bash
# Kali / Linux
python3 tools/check_artifacts.py Work/OC-<target>

# Windows
python tools/check_artifacts.py Work/OC-<target>

# 额外扫描本机 /tmp、/var/tmp、/dev/shm 中比 roe.yaml 更新的文件（默认关闭）
python tools/check_artifacts.py --check-tmp Work/OC-<target>
```

检查项：必需章节、账本状态、深度清单、技能加载（表存在且非空；具体加载哪些技能由
`pentest-flow` 的技能路由信号表判定）、17 类 Web 覆盖清单、5 轮复盘、
结束检查 12 条、`/tmp` 引用、`report.md`、`confirmed` 证据路径及文件存在性。
它不检查证据内容真实性。

退出码：`0` = 结构 PASS，`1` = FAIL，`2` = 参数错误。

## check_skill_budget.py

检查 `skills/ai-mcp-security` 与 `skills/post-exploitation` 新增参考文件的行数预算，并校验 `[Sxx]` 来源 ID 是否有断链。

```bash
python tools/check_skill_budget.py
```

退出码：`0` = PASS，`1` = 超预算或文件缺失。

## gen_router.py

从技能 frontmatter + `meta/routing.yaml` 生成 `skills/pentest-flow/references/routing.generated.md` 与各技能前置声明；`--check` 用于 CI。

```bash
python tools/gen_router.py            # 生成/更新
python tools/gen_router.py --check    # CI：不一致则退出 1
python tools/gen_router.py --dry-run  # 列出将变更的文件
```

## check_contracts.py

校验 24 个技能 frontmatter 的必填字段、`entry` 唯一、`requires` 无环且指向存在；跨技能直接引用先以 WARN 输出，P2 迁移后启用 `--strict-refs`。

```bash
python tools/check_contracts.py
python tools/check_contracts.py --strict-refs   # P2 后
```

## check_links.py

扫描 `skills/**/*.md` 中的相对 `.md` 引用（反引号与 Markdown 链接），输出断链；跳过 URL、通配符、产物名与外部示例。

```bash
python tools/check_links.py
```

## check_data.py

校验 2440 个 CVE YAML 可解析、组件内 CVE 唯一、`index.json` 与实际目录一致、`THIRD_PARTY_NOTICES.md` 覆盖全部数据集。

```bash
python tools/check_data.py --check
```

## 开发 / CI 依赖

- `tools/check_data.py`（P0 新增）需要 **PyYAML** 解析 CVE YAML；只在开发/CI 运行。
- 运行时脚本（`check_artifacts.py`、`check_skill_budget.py`）仍只用标准库，保持零依赖。