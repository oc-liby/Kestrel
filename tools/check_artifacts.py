#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kestrel 可选静态检查工具。

用法：
    python3 tools/check_artifacts.py <Work/OC-target>
    python3 tools/check_artifacts.py --check-tmp <Work/OC-target>
    Windows: python tools/check_artifacts.py <Work/OC-target>

退出码：0 = 结构 PASS，1 = FAIL，2 = 参数错误。

这不是结束门禁。结束条件以 plan.md 的结束检查表和用户确认为准；
本工具只检查结构，不检查证据真实性，也不能证明测试质量。
"""

import hashlib
import os
import re
import sys

REQUIRED_SECTIONS = [
    "## 攻击面账本",
    "## 技能加载",
    "## 深度清单",
    "## 覆盖清单",
    "## 复盘",
    "## 结束检查",
]
LEDGER_STATUSES = {"untested", "testing", "confirmed", "candidate", "negative", "blocked", "n/a"}
CHECK_STATUSES = {"todo", "doing", "done", "n/a", "blocked"}
WEB_STATUSES = {"confirmed", "candidate", "negative", "blocked", "not_applicable"}
WEB_CATEGORIES = [
    "sqli", "xss", "csrf", "idor", "auth_bypass", "file_upload",
    "path_traversal", "ssrf", "xxe", "ssti", "deserialization",
    "request_smuggling", "race_condition", "info_disclosure",
    "business_logic", "default_credential", "cve",
]

# 执行类账本类别：用词边界匹配，避免 source / resource 里的 "rce" 子串误报。
SHELL_CATEGORY_PATTERN = re.compile(
    r"\b(?:rce|web[ _-]?shell|cmd[ _-]?injection|command[ _-]?injection|"
    r"deserialization|deser|code[ _-]?exec|execution|exec)\b",
    re.I,
)

# 只匹配绝对临时路径；相对路径 evidence/src/tmp/ 不算。
TMP_PAT = re.compile(r"(?<![\w:/])/(?:var/)?tmp/|(?<![\w:/])/dev/shm/")
# 否定句豁免：只保留明确的否定词，避免“检查 /tmp”这类句子被误豁免。
NEGATION = re.compile(r"不写|禁止|不得|不要|避免|没有|无需|no\b|not\b", re.I)
SKIP_TMP_DIRS = (
    ".bun-",
    "hsperfdata",
    "node-compile-cache",
    "opencode",
    "systemd-private",
    ".X11-unix",
    "codeg-delegation",
    "codeg-acp",
)
TMP_MAX_FILES = 5000
TMP_MAX_DEPTH = 2


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return None


def parse_section_table(text, heading):
    """返回 heading 之后第一张 Markdown 表的 (header, rows)。"""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == heading:
            start = i + 1
            break
    if start is None:
        return None, []

    header = None
    rows = []
    for line in lines[start:]:
        s = line.strip()
        if s.startswith("## ") or s.startswith("### "):
            break
        if not s.startswith("|"):
            # 表头之后出现非表格行，说明这张表已结束；
            # 不再继续扫描后续表格，避免把下一节表误当本节表。
            if header is not None:
                break
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if header is None:
            header = cells
            continue
        if cells and all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            continue
        rows.append(cells)
    return header, rows


def section_lines(text, heading):
    """返回 heading 到下一个 ## / ### 之间的原始行。"""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == heading:
            start = i + 1
            break
    if start is None:
        return []
    out = []
    for line in lines[start:]:
        s = line.strip()
        if s.startswith("## ") or s.startswith("### "):
            break
        out.append(line)
    return out


def col(header, name):
    if not header:
        return None
    for i, h in enumerate(header):
        if name in h:
            return i
    return None


def cell(row, idx):
    if idx is None or idx >= len(row):
        return ""
    return row[idx].strip()


def is_empty(value):
    return value in ("", "-", "—", "n/a", "N/A", "无")


def lint(work, check_tmp=False):
    issues = []
    warnings = []

    if not os.path.isdir(work):
        return ["工作目录不存在: " + work], warnings

    roe_path = os.path.join(work, "roe.yaml")
    plan_path = os.path.join(work, "plan.md")
    findings_path = os.path.join(work, "findings.md")

    if not os.path.isfile(roe_path):
        issues.append("roe.yaml 缺失")
    plan = read_text(plan_path)
    findings = read_text(findings_path)
    if plan is None:
        issues.append("plan.md 缺失")
        plan = ""
    if findings is None:
        issues.append("findings.md 缺失")
        findings = ""

    for section in REQUIRED_SECTIONS:
        if section not in plan:
            issues.append("plan.md 缺少章节: " + section)

    # 攻击面账本
    ledger_header, ledger_rows = parse_section_table(plan, "## 攻击面账本")
    if ledger_header is None:
        issues.append("plan.md 无 ## 攻击面账本 表")
        ledger_rows = []
    else:
        status_idx = col(ledger_header, "状态")
        evidence_idx = col(ledger_header, "证据")
        next_idx = col(ledger_header, "下一步")
        if status_idx is None:
            issues.append("攻击面账本缺少「状态」列")
        for n, row in enumerate(ledger_rows, 1):
            status = cell(row, status_idx).lower()
            if not status:
                issues.append("账本第 %d 行状态为空" % n)
                continue
            if status not in LEDGER_STATUSES:
                issues.append("账本第 %d 行状态非法: %s" % (n, status))
            if status == "untested":
                issues.append("账本第 %d 行仍为 untested: %s" % (n, " | ".join(row)[:160]))
                if is_empty(cell(row, next_idx)):
                    issues.append("账本第 %d 行 untested 但无下一步" % n)
            if status in ("confirmed", "negative", "candidate"):
                if is_empty(cell(row, evidence_idx)):
                    issues.append("账本第 %d 行 %s 但无证据" % (n, status))
            if status == "blocked":
                blob = cell(row, evidence_idx) + " " + cell(row, next_idx)
                if "已尝试" not in blob and "尝试" not in blob:
                    issues.append("账本第 %d 行 blocked 但无已尝试说明" % n)

    # 深度清单
    header, rows = parse_section_table(plan, "## 深度清单")
    if header is None:
        issues.append("plan.md 无 ## 深度清单 表")
    else:
        status_idx = col(header, "状态")
        if status_idx is None:
            issues.append("深度清单缺少「状态」列")
        for n, row in enumerate(rows, 1):
            status = cell(row, status_idx).lower()
            if not status:
                issues.append("深度清单第 %d 行状态为空" % n)
                continue
            if status not in CHECK_STATUSES:
                issues.append("深度清单第 %d 行状态非法: %s" % (n, status))
            if status in ("todo", "doing"):
                issues.append("深度清单第 %d 行仍为 %s" % (n, status))
            if status == "blocked":
                blob = " ".join(row)
                if "已尝试" not in blob and "尝试" not in blob:
                    issues.append("深度清单第 %d 行 blocked 但无已尝试说明" % n)

    # 是否为 Web 目标：只看账本「服务」列；正文里的参考链接不算
    service_text = ""
    if ledger_header:
        svc_idx = col(ledger_header, "服务")
        service_text = " ".join(cell(r, svc_idx) for r in ledger_rows).lower()
    web_like = any(
        k in service_text
        for k in ("http", "web", "nginx", "tomcat", "apache", "iis", "spring",
                  "node", "django", "flask", "php")
    )

    # 覆盖清单：Web 目标必须覆盖 17 类，每类有状态
    header, rows = parse_section_table(plan, "## 覆盖清单")
    if header is None:
        issues.append("plan.md 无 ## 覆盖清单 表")
    else:
        cat_idx = col(header, "类别")
        status_idx = col(header, "状态")
        if cat_idx is None or status_idx is None:
            issues.append("覆盖清单缺少「类别」或「状态」列")
        else:
            seen = {}
            for n, row in enumerate(rows, 1):
                cat = cell(row, cat_idx).lower()
                status = cell(row, status_idx).lower()
                if not cat:
                    issues.append("覆盖清单第 %d 行类别为空" % n)
                    continue
                seen[cat] = status
                if status not in WEB_STATUSES:
                    issues.append("覆盖清单第 %d 行状态非法: %s" % (n, status))
            if web_like:
                missing = [c for c in WEB_CATEGORIES if c not in seen]
                if missing:
                    issues.append("覆盖清单缺少 Web 类别: " + ", ".join(missing))

    # 通道判定：账本出现已确认的 RCE / WebShell / 命令执行时，plan.md 必须有 ## 通道判定
    shell_rows = []
    if ledger_header:
        cat_idx = col(ledger_header, "类别")
        st_idx = col(ledger_header, "状态")
        for row in ledger_rows:
            cat = cell(row, cat_idx).lower()
            st = cell(row, st_idx).lower()
            if st == "confirmed" and SHELL_CATEGORY_PATTERN.search(cat):
                shell_rows.append(row)
    if shell_rows:
        ch_header, ch_rows = parse_section_table(plan, "## 通道判定")
        if ch_header is None:
            issues.append("账本有已确认的 RCE/WebShell/命令执行，但 plan.md 缺 ## 通道判定")
        elif not ch_rows:
            issues.append("## 通道判定 表为空")

    # 技能加载表：只查存在与非空。
    # 具体该加载哪些技能由 skills/pentest-flow/SKILL.md 的「技能路由」信号表定义，
    # 属于规则内容，不在检查器里复制。
    header, rows = parse_section_table(plan, "## 技能加载")
    if header is None:
        issues.append("plan.md 无 ## 技能加载 表")
    elif not rows:
        issues.append("## 技能加载 表为空")

    # 5 轮有效复盘：每条必须记录「扩展来源 + 核对项 + 具体对象」
    review_lines = section_lines(plan, "## 复盘")
    review_items = [
        l.strip() for l in review_lines
        if re.match(r"^([-*]|\d+[.、])\s*", l.strip())
    ]
    # 任一条使用新格式即视为新交战；完全没有 [扩展-] 标记时按旧格式兼容
    new_review_format = any("[扩展" in item for item in review_items)
    if len(review_items) < 5:
        issues.append("复盘记录不足 5 条: %d" % len(review_items))
    elif new_review_format:
        # 扩展来源：编号（X1–X7）或关键词，映射到同一组来源名
        X_SOURCES = [
            ("JS/前端", r"JS|前端|sourcemap|javascript"),
            ("源码/备份", r"源码|备份|\.git|\.svn|www\.zip"),
            ("文档/配置", r"swagger|actuator|robots|sitemap|文档|配置|错误页"),
            ("同类横向", r"同类|横向|同参数|同组件"),
            ("版本/CVE", r"版本|CVE|banner|指纹"),
            ("凭据", r"凭据|凭证|token|session"),
            ("响应线索", r"响应|错误信息|重定向|header|cookie"),
        ]
        X_BY_ID = {"X1": "JS/前端", "X2": "源码/备份", "X3": "文档/配置",
                   "X4": "同类横向", "X5": "版本/CVE", "X6": "凭据", "X7": "响应线索"}
        # 核对项：A–G 编号或关键词
        CHECK_ITEMS = r"资产|接口|类别|negative|blocked|回连"
        # 具体对象：账本行号 / 清单项 ID / 证据路径 / 接口路径；X 编号不算对象
        OBJECT = (r"#\d+|第\s*\d+\s*行|(?!X\d)[A-Z]\d{1,2}\b|evidence/"
                  r"|/[A-Za-z0-9_\-][A-Za-z0-9_\-./]{2,}")
        weak, sources_hit = [], set()
        for i, item in enumerate(review_items, 1):
            # 只在 [扩展-...] 段内找来源，避免核对段里的“响应/CVE”被误算
            ext = re.search(r"\[扩展[-\s]?([^\]]*)\](.*?)(?=\[核对|$)", item, re.S)
            if not ext:
                weak.append("%d(缺扩展段)" % i)
            else:
                ext_text = ext.group(1) + " " + ext.group(2)
                ids = [x.upper() for x in re.findall(r"\bX[1-7]\b", ext_text, re.I)]
                hit = [X_BY_ID[x] for x in ids if x in X_BY_ID]
                if not hit:
                    hit = [name for name, pat in X_SOURCES if re.search(pat, ext_text, re.I)]
                if not hit:
                    weak.append("%d(缺扩展来源)" % i)
                else:
                    sources_hit.add(hit[0])
            # 只在 [核对-...] 段内找核对项
            chk = re.search(r"\[核对[-\s]?([^\]]*)\](.*)$", item, re.S)
            if not chk:
                weak.append("%d(缺核对段)" % i)
            else:
                chk_text = chk.group(1) + " " + chk.group(2)
                if not re.search(r"\b[A-G]\b", chk_text) and not re.search(CHECK_ITEMS, chk_text, re.I):
                    weak.append("%d(缺核对项)" % i)
            if not re.search(OBJECT, item):
                weak.append("%d(缺具体对象)" % i)
        if weak:
            issues.append("复盘条目不合格: " + ", ".join(weak))
        if len(sources_hit) < 3:
            issues.append(
                "5 轮复盘扩展来源不足 3 种: %d 种（%s）"
                % (len(sources_hit), "、".join(sorted(sources_hit)) or "无")
            )
    else:
        # 旧格式兼容：复盘完全没有 [扩展-] 标记时沿用旧判据，并提示升级
        warnings.append("复盘为旧格式（无 [扩展-] 标记），按旧规则校验；新交战请使用复盘审计格式")
        weak = []
        for i, item in enumerate(review_items, 1):
            if not re.search(r"账本|清单|证据|negative|blocked|理由|轮", item, re.I):
                weak.append(str(i))
        if weak:
            issues.append("复盘第 %s 条缺少账本/清单/证据/理由记录" % ", ".join(weak))

    # 资产基线 vs 账本：基线端口必须被账本覆盖（旧交战无基线表时只提示）
    base_header, base_rows = parse_section_table(plan, "## 资产基线")
    if base_header is None:
        if new_review_format:
            issues.append("新交战的 plan.md 缺少 ## 资产基线 表")
        else:
            warnings.append("plan.md 无 ## 资产基线 表，跳过端口比对（旧交战兼容）")
    else:
        bp_idx = col(base_header, "端口")
        if bp_idx is None:
            issues.append("资产基线缺少「端口」列")
        else:
            base_ports = set()
            for row in base_rows:
                p = cell(row, bp_idx).split("/")[0].strip()
                if p:
                    base_ports.add(p)
            ledger_ports = set()
            if ledger_header:
                lp_idx = col(ledger_header, "端口")
                for row in ledger_rows:
                    p = cell(row, lp_idx).split("/")[0].strip()
                    if p:
                        ledger_ports.add(p)
            missing = base_ports - ledger_ports
            if missing:
                issues.append("资产基线端口未进账本: " + ", ".join(sorted(missing)))

    # 复盘提到的新路径必须在账本或覆盖清单中（扩展发现不能只写不测）
    if review_items:
        cov_header, cov_rows = parse_section_table(plan, "## 覆盖清单")
        ledger_text = " ".join(" ".join(r) for r in ledger_rows) if ledger_header else ""
        cov_text = " ".join(" ".join(r) for r in cov_rows) if cov_header else ""
        review_text = "\n".join(review_items)
        found_paths = set(re.findall(r"/[A-Za-z0-9_\-][A-Za-z0-9_\-./]{2,}", review_text))
        ignore = {"/tmp", "/var/tmp", "/dev/shm", "/etc/passwd", "/bin/sh", "/bin/bash"}
        # 系统工具/运行目录不作为目标路径要求入账，避免复盘提到 nmap 等工具路径时误报
        SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
                           "/proc/", "/sys/", "/dev/", "/run/")
        paths = [p for p in found_paths
                 if p not in ignore and not p.startswith(SYSTEM_PREFIXES)]
        unlogged = [p for p in paths if p not in ledger_text and p not in cov_text]
        if unlogged:
            issues.append(
                "复盘提到但账本/覆盖清单未记录的路径: " + ", ".join(sorted(unlogged)[:5])
            )
        # 已入账的复盘路径不能仍是 untested/testing
        status_idx = col(ledger_header, "状态") if ledger_header else None
        pending = set()
        for p in paths:
            for row in ledger_rows:
                if p in " ".join(row):
                    st = cell(row, status_idx).lower() if status_idx is not None else ""
                    if st in ("untested", "testing"):
                        pending.add(p)
                    break
        if pending:
            issues.append("复盘路径仍为 untested/testing: " + ", ".join(sorted(pending)[:5]))

    # 结束检查：至少 12 条记录，且不得有 FAIL
    end_items = [l.strip() for l in section_lines(plan, "## 结束检查") if l.strip()]
    if len(end_items) < 12:
        issues.append("结束检查记录不足 12 条: %d" % len(end_items))
    if any("FAIL" in l.upper() for l in end_items):
        issues.append("结束检查存在 FAIL 项")

    # /tmp 引用：只检查 agent 产物四文件
    for name in ("plan.md", "findings.md", "notes.md", "approvals.md"):
        text = read_text(os.path.join(work, name)) or ""
        for lineno, line in enumerate(text.splitlines(), 1):
            if TMP_PAT.search(line) and not NEGATION.search(line):
                issues.append("%s:%d 引用临时目录: %s" % (name, lineno, line.strip()[:160]))

    # 禁止 report.md
    if os.path.exists(os.path.join(work, "report.md")):
        issues.append("存在 report.md（禁止）")

    # confirmed 必须有证据，且证据文件真实存在
    # 用 finditer 保留标题行，避免 split 把标题切掉导致标题内的状态漏检
    header_matches = list(re.finditer(r"(?m)^##\s+F-.*$", findings))
    for i, m in enumerate(header_matches):
        start = m.start()
        end = header_matches[i + 1].start() if i + 1 < len(header_matches) else len(findings)
        block = findings[start:end]
        title = m.group(0).strip()
        is_confirmed = bool(
            re.search(r"\bconfirmed\b", m.group(0), re.I)
            or re.search(r"(?m)^\s*-\s*状态[：:]\s*confirmed\b", block, re.I)
        )
        has_evidence = re.search(r"证据(?:路径)?[：:]|evidence/|\|\s*证据(?:路径)?\s*\|", block) is not None
        if is_confirmed and not has_evidence:
            issues.append("findings 中 confirmed 无证据: " + title[:80])
        if is_confirmed:
            for rel in re.findall(r"evidence/[A-Za-z0-9._/\-]+", block):
                rel = rel.rstrip(".,;:)")
                if "*" in rel or "?" in rel:
                    continue
                if not os.path.exists(os.path.join(work, rel)):
                    issues.append("findings 证据文件不存在: " + rel)

    # 本地临时目录较新文件（WARN，默认关闭；--check-tmp 开启）
    if check_tmp and os.path.isfile(roe_path):
        try:
            roe_mtime = os.path.getmtime(roe_path)
        except OSError:
            roe_mtime = None
        if roe_mtime:
            for base in ("/tmp", "/var/tmp", "/dev/shm"):
                if not os.path.isdir(base):
                    continue
                count = 0
                stop = False
                for root, dirs, files in os.walk(base):
                    # 限制深度，避免在共享机/容器上遍历整棵临时目录树
                    if root[len(base):].count(os.sep) >= TMP_MAX_DEPTH:
                        dirs[:] = []
                    dirs[:] = [d for d in dirs if not any(x in d for x in SKIP_TMP_DIRS)]
                    for filename in files:
                        count += 1
                        if count > TMP_MAX_FILES:
                            warnings.append("临时目录扫描超过 %d 个文件，已停止: %s" % (TMP_MAX_FILES, base))
                            stop = True
                            break
                        path = os.path.join(root, filename)
                        try:
                            if os.path.getmtime(path) > roe_mtime:
                                warnings.append("临时目录有较新文件: " + path)
                        except OSError:
                            pass
                    if stop:
                        break

    return issues, warnings


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _evidence_paths(block):
    paths = re.findall(r"evidence/[A-Za-z0-9._/\-]+", block)
    paths = [p.rstrip(".,;:)") for p in paths if "*" not in p and "?" not in p]
    return list(dict.fromkeys(paths))


def stamp_hashes(work):
    """为 findings 的每个 F- 块追加/更新证据哈希行（可选功能）。"""
    path = os.path.join(work, "findings.md")
    text = read_text(path)
    if text is None:
        return ["findings.md 缺失"]
    issues = []
    matches = list(re.finditer(r"(?m)^##\s+F-.*$", text))
    if not matches:
        return issues
    parts, last = [], 0
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        paths = _evidence_paths(block)
        if paths:
            block = re.sub(r"(?m)^- 证据哈希：.*\n?", "", block)
            lines = []
            for rel in paths:
                full = os.path.join(work, rel)
                if os.path.exists(full):
                    lines.append("- 证据哈希：%s（%s）" % (sha256_file(full), rel))
                else:
                    issues.append("证据文件不存在: " + rel)
            if lines:
                block = block.rstrip() + "\n" + "\n".join(lines) + "\n\n"
        parts.append(text[last:start] + block)
        last = end
    parts.append(text[last:])
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(parts))
    return issues


def verify_hashes(work):
    """校验 findings 证据哈希与 approvals 链（可选功能）。"""
    issues = []
    text = read_text(os.path.join(work, "findings.md")) or ""
    for m in re.finditer(r"(?m)^- 证据哈希：(sha256:[0-9a-f]{64})（([^）]+)）", text):
        expected, rel = m.groups()
        full = os.path.join(work, rel)
        if not os.path.exists(full):
            issues.append("哈希对应文件不存在: " + rel)
            continue
        if sha256_file(full) != expected:
            issues.append("证据哈希不一致: " + rel)

    approvals = read_text(os.path.join(work, "approvals.md")) or ""
    prev = "genesis"
    for block in re.split(r"(?m)^(?=###\s+A-)", approvals):
        if not re.match(r"^###\s+A-", block):
            continue
        pm = re.search(r"(?m)^- prev:\s*(sha256:[0-9a-f]{64}|genesis)\s*$", block)
        hm = re.search(r"(?m)^- hash:\s*(sha256:[0-9a-f]{64})\s*$", block)
        if not pm or not hm:
            continue
        if pm.group(1) != prev:
            issues.append("approvals prev 不连续: " + block.splitlines()[0][:40])
        body = re.sub(r"(?m)^- hash:.*\n?", "", block)
        calc = "sha256:" + hashlib.sha256((pm.group(1) + body).encode("utf-8")).hexdigest()
        if calc != hm.group(1):
            issues.append("approvals 链哈希不一致: " + block.splitlines()[0][:40])
        prev = hm.group(1)
    return issues


def main():
    # Windows 控制台默认 GBK，统一按 UTF-8 输出，避免中文乱码
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    check_tmp = "--check-tmp" in sys.argv[1:]
    stamp = "--stamp-hashes" in sys.argv[1:]
    verify = "--verify-hashes" in sys.argv[1:]
    if len(args) != 1:
        print("usage: check_artifacts.py [--check-tmp] [--stamp-hashes|--verify-hashes] <Work/OC-target>")
        return 2
    work = args[0]

    if stamp:
        issues = stamp_hashes(work)
        for issue in issues:
            print("FAIL: " + issue)
        if issues:
            return 1
        print("已写入证据哈希: " + work)
        return 0

    if verify:
        issues = verify_hashes(work)
        has_any = bool(re.search(r"(?m)^- 证据哈希：", read_text(os.path.join(work, "findings.md")) or ""))
        if not has_any:
            print("WARN: 旧产物无哈希行，跳过 findings 校验")
        if issues:
            print("FAIL: %d hash issue(s)" % len(issues))
            for issue in issues:
                print("- " + issue)
            return 1
        print("HASH VERIFY PASS: " + work)
        return 0

    issues, warnings = lint(work, check_tmp=check_tmp)
    for warning in warnings[:20]:
        print("WARN: " + warning)
    if len(warnings) > 20:
        print("WARN: ... 另有 %d 条" % (len(warnings) - 20))
    if issues:
        print("FAIL: %d issue(s)" % len(issues))
        for issue in issues:
            print("- " + issue)
        return 1
    print("STRUCTURE PASS (not an end-of-engagement gate): " + work)
    return 0


if __name__ == "__main__":
    sys.exit(main())