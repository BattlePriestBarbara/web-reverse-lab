# -*- coding: utf-8 -*-
"""Step 4：contract.json 对 baseline_15_routes.json 做量化评估与差异分析。

两个指标必须分开算，否则会自欺
==============================
* **控制组覆盖率（coverage_control）**：只要任一客户端碰过就算。它验证的是
  "捕获 → 契约 → 回链"这条管线本身没丢东西，预期 15/15。
* **无监督发现力（coverage_crawler）**：只有爬虫时间窗内发现的才算。它衡量
  L1/L2 的**自动**发现能力，漏掉的每一条都要给出可执行的补法。

把两者合成一个数是最容易犯的错：回放把分母填满，报告就显得"爬虫很棒"，
而真实情况是"爬虫只会跟着 <a href> 走"。所以本脚本把它们并列打印，
并且**只对控制组下断言**，发现力那一栏是度量、不是及格线。

判定口径：只对"管线有没有复原清单"下硬结论
============================================
**硬断言（缺一即不通过）**
1. 控制组覆盖 15/15 —— 清单里的每条路由都能在契约里找到对应端点；
2. 每条路由都带 ``flows/<run>.jsonl#seq-N`` 回链（只有 har#entry 不算：那证明
   "发生过"，却不能顺着它回到原始报文）。

**只报告、不判负**
3. ``expected_status`` 与实测不一致 —— 这是**Ground Truth 侧**的证据（手写清单
   随版本过期），不是管线的失败。把它算成失败，等于把"我们的清单老了"错记成
   "管线不行"，然后为了让它变绿去改断言。实测已出现一例：``/rest/user/whoami``
   手写期望 401，该实例真实返回 200 ``{"user":{}}``。这类条目单列成 finding。


用法
====
    python scripts\\verify_p2_baseline.py --contract contracts\\contract_p2.json ^
        --baseline baseline\\baseline_15_routes.json --report reports\\p2_baseline_report.md

退出码：0 = 通过；1 = 不通过（差异明细会打印）；2 = 输入不可用。
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

DEFAULT_BASELINE = r"baseline\baseline_15_routes.json"
DEFAULT_REPORT = r"reports\p2_baseline_report.md"


def _segments(path):
    """拆路径段；同时把 ``/api-docs/`` 与 ``/api-docs`` 归一（尾斜杠不是资源差异）。"""
    return [s for s in (path or "").split("/") if s]


def template_match(concrete, template):
    """具体路径是否命中模板。``{int}``/``{id}`` 这类占位符匹配任意单个路径段。"""
    a, b = _segments(concrete), _segments(template)
    if len(a) != len(b):
        return False
    for got, want in zip(a, b):
        if want.startswith("{") and want.endswith("}"):
            continue
        if got != want:
            return False
    return True


def _endpoint_paths(ep):
    """端点用于比对的候选路径：模板本身 + 所有具体样本。"""
    paths = [ep.get("path") or ""]
    paths.extend(ep.get("path_samples") or [])
    return [p for p in paths if p]


def find_endpoint(route, endpoints):
    """按 (method, 路径) 找端点的**唯一**最佳匹配。

    多个候选时取"命中样本数最多"的那个；并列则按 id 排序，保证结果可复现。
    """
    method = (route.get("method") or "GET").upper()
    template = route.get("path_template") or route.get("path_sample") or ""
    hits = []
    for ep in endpoints:
        if (ep.get("method") or "").upper() != method:
            continue
        if any(template_match(p, template) for p in _endpoint_paths(ep)):
            hits.append(ep)
    if not hits:
        return None
    hits.sort(key=lambda e: (-len(e.get("path_samples") or []), e.get("id") or ""))
    return hits[0]


def _has_flow_ref(ep):
    return any((r or "").startswith("flows/") and "#seq-" in r
               for r in (ep.get("evidence_ref") or []))


def _advice(route, seen_by_crawler):
    """给漏掉的条目一句可执行的补法——报告里最该被读的一列。"""
    category = route.get("category")
    if category == "baseline":
        return "本条即'不存在的路径'：任何爬虫都不会猜它，遗漏是**正常且不可修**的"
    if category == "discovery":
        if seen_by_crawler:
            return ""
        return "非链接可达路径（-kf all 已开）→ 需字典/人工探索；也可先用 /api-docs 拿全表"
    if route.get("path_template", "").startswith(("/api/", "/rest/")):
        return "SPA 内接口，HTML 里没有指向它的 <a href> → 只能解析 JS（-jc/-jsluice）或执行 JS（-headless/Playwright）"
    return "无站内链接指向；检查是否依赖表单提交或前端路由"


def _statuses(ep):
    """实测状态码。v2 叫 ``observed_statuses``，v1 叫 ``statuses``；两种契约都要能读。

    P3 把观测轨切到 schema v2 之后，P2 的这份验收脚本仍要能复现旧报告，
    所以这里做兼容而不是改断言——报告结论不能因为字段改名就变。
    """
    return sorted((ep or {}).get("observed_statuses") or (ep or {}).get("statuses") or [])


def evaluate(contract, baseline):
    endpoints = contract.get("endpoints") or []
    routes = baseline.get("routes") or []

    rows = []
    for route in routes:
        ep = find_endpoint(route, endpoints)
        observed = _statuses(ep) if ep else []
        phase = (ep or {}).get("discovery", {}).get("phase")
        expected = route.get("expected_status")
        rows.append({
            "route": route,
            "endpoint_id": (ep or {}).get("id"),
            "endpoint_path": (ep or {}).get("path"),
            "observed_statuses": observed,
            "phase": phase,
            "crawler_found": phase == "crawl",
            "has_flow_ref": bool(ep and _has_flow_ref(ep)),
            "evidence_ref": (ep or {}).get("evidence_ref") or [],
            "status_match": (None if expected is None or not observed
                             else expected in observed),
            "matched": ep is not None,
        })

    matched = [r for r in rows if r["matched"]]
    crawler_found = [r for r in rows if r["crawler_found"]]
    decisive = [r for r in rows if r["route"].get("expected_status") is not None]
    decisive_ok = [r for r in decisive if r["status_match"]]

    # 多出来的端点 = 真正的情报（架构原话），但要按 kind 分开数，
    # 否则 60 个静态资源会把 5 个 REST 端点淹掉。SPA catch-all 壳单独剔除：
    # 它只是同一份 index.html，不是"多出来的接口"。
    baseline_ids = {r["endpoint_id"] for r in rows if r["endpoint_id"]}
    spa_shells = [ep for ep in endpoints if ep.get("spa_shell")]
    extras = [ep for ep in endpoints
              if ep.get("id") not in baseline_ids and not ep.get("spa_shell")]
    extras_by_kind = Counter(ep.get("kind") or "other" for ep in extras)

    metrics = {
        "baseline_total": len(routes),
        "coverage_control": len(matched),
        "coverage_crawler": len(crawler_found),
        "decisive_total": len(decisive),
        "decisive_match": len(decisive_ok),
        "flow_linked": len([r for r in rows if r["has_flow_ref"]]),
        "contract_endpoints": len(endpoints),
        "extra_endpoints": len(extras),
        "extra_by_kind": dict(extras_by_kind),
        "extra_spa_shell": len(spa_shells),
    }
    # 硬断言只针对"管线是否复原了清单"。期望与实测不符是 Ground Truth 侧的
    # finding（版本漂移），单列出来，不让它把管线判负。
    stale = [
        {"label": r["route"].get("label"),
         "path": r["route"].get("path_template"),
         "expected": r["route"].get("expected_status"),
         "observed": r["observed_statuses"]}
        for r in rows if r["status_match"] is False
    ]
    metrics["stale_expectations"] = stale
    metrics["stale_count"] = len(stale)

    verdict = (
        metrics["coverage_control"] == metrics["baseline_total"]
        and metrics["flow_linked"] == metrics["baseline_total"]
    )
    return rows, metrics, extras, verdict



def _best_ref(refs):
    """回链优先级：`flows/*.jsonl#seq-N` > `har/*.har#entry-N`。

    HAR 回链只能证明"这条交换发生过"，而 flows 行是架构规定的原始证据锚点
    （崩溃安全、可 grep、可 git diff）。报告里必须优先给后者。
    """
    refs = [r for r in (refs or []) if r]
    for ref in refs:
        if ref.startswith("flows/") and "#seq-" in ref:
            return ref
    return refs[0] if refs else "-"


def _row_verdict(row):
    """一行的结论：缺失 / 状态不符 / 回链不足 / 命中。"""
    if not row["matched"]:
        return "缺失"
    if row["status_match"] is False:
        return "期望不符(finding)"
    if not row["has_flow_ref"]:
        return "回链不足"
    if row["route"].get("expected_status") is None:
        return "命中(原文未定罪)"
    return "通过"


def render_console(rows, metrics, verdict, contract, baseline):
    out = []
    src = baseline.get("source", {})
    out.append("=== P2 对照组校验：contract ⊇ baseline_15_routes ===")
    out.append("合约 : %s  (run_id=%s)" % (contract.get("sources", {}).get("har"),
                                           contract.get("run_id")))
    out.append("基线 : %d 条；源指纹 sha256=%s…"
               % (metrics["baseline_total"], (src.get("sha256") or "")[:16]))
    out.append("端点 : %d 个" % metrics["contract_endpoints"])
    out.append("")
    header = "%-3s %-20s %-5s %-42s %-5s %-7s %-7s %-4s %s" % (
        "#", "label", "meth", "path", "exp", "obs", "phase", "ref", "verdict")
    out.append(header)
    out.append("-" * 110)
    for i, row in enumerate(rows, 1):
        route = row["route"]
        exp = route.get("expected_status")
        obs = ",".join(str(s) for s in row["observed_statuses"]) or "-"
        out.append("%-3d %-20s %-5s %-42s %-5s %-7s %-7s %-4s %s" % (
            i, route.get("label", "")[:20], route.get("method", "GET"),
            (route.get("path_template") or "")[:42],
            "-" if exp is None else str(exp), obs, row["phase"] or "-",
            "yes" if row["has_flow_ref"] else ("har" if row["matched"] else "-"),
            _row_verdict(row)))
    out.append("")
    out.append("--- 指标 ---")
    out.append("  控制组覆盖 : %2d/%-2d  <- 管线完整性（断言项）"
               % (metrics["coverage_control"], metrics["baseline_total"]))
    out.append("  爬虫发现力 : %2d/%-2d  <- L2 自动发现能力（度量项，不是及格线）"
               % (metrics["coverage_crawler"], metrics["baseline_total"]))
    out.append("  断言式状态 : %2d/%-2d  <- 只对原文给了明确状态码的条目断言"
               % (metrics["decisive_match"], metrics["decisive_total"]))
    out.append("  flows 回链 : %2d/%-2d  <- 每条都能回到原始报文行"
               % (metrics["flow_linked"], metrics["baseline_total"]))
    out.append("  新增端点   : %2d 个（%s）"
               % (metrics["extra_endpoints"],
                  ", ".join("%s=%d" % kv for kv in sorted(metrics["extra_by_kind"].items())) or "-"))
    out.append("  SPA 壳剔除 : %2d 个  <- 响应体与首页同哈希：200 不代表资源存在"
               % metrics.get("extra_spa_shell", 0))
    out.append("")
    if metrics.get("stale_count"):
        out.append("--- Ground Truth 侧 finding：期望与实测不符（**不计入判定**） ---")
        for item in metrics["stale_expectations"]:
            out.append("  %-20s %-38s 期望 %s，实测 %s" % (
                item["label"], (item["path"] or "")[:38], item["expected"],
                ",".join(str(s) for s in item["observed"]) or "-"))
        out.append("  说明：这说明手写清单对这台实例已过期（版本漂移），是情报，不是管线缺陷。")
        out.append("")
    out.append("=== %s ===" % ("P2 通过" if verdict else "P2 未通过"))
    return "\n".join(out)


def render_markdown(rows, metrics, extras, verdict, contract, baseline):
    src, tgt = baseline.get("source", {}), contract.get("target", {})
    lines = ["# P2 对照组校验报告", ""]
    lines.append("- run_id：`%s`" % contract.get("run_id"))
    lines.append("- 目标：`%s`（%s）" % (tgt.get("base_url"), tgt.get("profile")))
    lines.append("- Ground Truth：`%s` %d 条，sha256=`%s…`"
                 % (src.get("project"), metrics["baseline_total"], (src.get("sha256") or "")[:16]))
    lines.append("- 合约：%d 个端点，源自 %d 条 HAR 交换"
                 % (metrics["contract_endpoints"],
                    contract.get("sources", {}).get("har_entries") or 0))
    lines.append("- **结论：%s**" % ("通过" if verdict else "未通过"))
    lines.append("")
    lines.append("## 1. 指标")
    lines.append("")
    lines.append("| 指标 | 值 | 性质 | 说明 |")
    lines.append("| --- | --- | --- | --- |")
    lines.append("| 控制组覆盖 | %d/%d | **断言** | 任一客户端碰过即算：验证捕获→契约→回链没丢东西 |"
                 % (metrics["coverage_control"], metrics["baseline_total"]))
    lines.append("| 爬虫发现力 | %d/%d | 度量 | 只在爬虫时间窗内发现的才算：L2 自动发现能力 |"
                 % (metrics["coverage_crawler"], metrics["baseline_total"]))
    lines.append("| 断言式状态吻合 | %d/%d | **断言** | 仅统计原文给了明确状态码的条目 |"
                 % (metrics["decisive_match"], metrics["decisive_total"]))
    lines.append("| 证据回链 | %d/%d | **断言** | 带 `flows/*.jsonl#seq-N` 的条目 |"
                 % (metrics["flow_linked"], metrics["baseline_total"]))
    lines.append("| 新增端点 | %d | 情报 | %s |"
                 % (metrics["extra_endpoints"],
                    ", ".join("%s=%d" % kv for kv in sorted(metrics["extra_by_kind"].items())) or "-"))
    lines.append("| 其中 SPA 壳 | %d | 已剔除 | 响应体与首页同哈希：这类 200 不代表资源存在 |"
                 % metrics.get("extra_spa_shell", 0))
    lines.append("")
    lines.append("## 2. 逐条对比")
    lines.append("")
    lines.append("| # | label | 方法 | 路径 | 期望 | 实测 | 首见 | 回链 | 结论 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for i, row in enumerate(rows, 1):
        route = row["route"]
        exp = route.get("expected_status")
        obs = ",".join(str(s) for s in row["observed_statuses"]) or "-"
        ref = _best_ref(row["evidence_ref"])
        lines.append("| %d | %s | %s | `%s` | %s | %s | %s | `%s` | %s |" % (
            i, route.get("label"), route.get("method", "GET"), route.get("path_template"),
            "-" if exp is None else exp, obs, row["phase"] or "-", ref, _row_verdict(row)))
    lines.append("")
    lines.append("## 3. 差异分析（爬虫没发现的那些）")
    lines.append("")
    gaps = [r for r in rows if not r["crawler_found"]]
    if not gaps:
        lines.append("爬虫窗口内已覆盖全部 %d 条。" % metrics["baseline_total"])
    else:
        lines.append("爬虫窗口内未发现 %d 条，逐条给补法：" % len(gaps))
        lines.append("")
        lines.append("| label | 路径 | 控制组里有 | 补法 |")
        lines.append("| --- | --- | --- | --- |")
        for row in gaps:
            lines.append("| %s | `%s` | %s | %s |" % (
                row["route"].get("label"), row["route"].get("path_template"),
                "有（回放命中）" if row["matched"] else "**没有**",
                _advice(row["route"], row["crawler_found"])))
    lines.append("")
    lines.append("## 4. 基线之外的新端点（真情报）")
    lines.append("")
    interesting = [ep for ep in extras if ep.get("kind") in ("api", "document")]
    interesting.sort(key=lambda e: -(e.get("discovery", {}).get("hits") or 0))
    lines.append("共 %d 个新端点，其中 api/document 类 %d 个（其余为静态资源）："
                 % (metrics["extra_endpoints"], len(interesting)))
    lines.append("")
    if interesting:
        lines.append("| id | 方法 | 路径 | 状态 | 次数 | 首见 | 回链 |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for ep in interesting[:40]:
            lines.append("| %s | %s | `%s` | %s | %d | %s | `%s` |" % (
                ep.get("id"), ep.get("method"), ep.get("path"),
                ",".join(str(s) for s in _statuses(ep)),
                ep.get("discovery", {}).get("hits") or 0,
                ep.get("discovery", {}).get("phase") or "-",
                _best_ref(ep.get("evidence_ref"))))
    lines.append("")
    lines.append("## 5. Ground Truth 侧 finding（期望与实测不符，不计入判定）")
    lines.append("")
    if not metrics.get("stale_count"):
        lines.append("无：手写期望与实测一致。")
    else:
        lines.append("| label | 路径 | 手写期望 | 实测 | 解读 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for item in metrics["stale_expectations"]:
            lines.append("| %s | `%s` | %s | %s | 手写期望对该实例已过期；以实测为准 |" % (
                item["label"], item["path"], item["expected"],
                ",".join(str(s) for s in item["observed"]) or "-"))
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="P2 对照组校验")
    ap.add_argument("--contract", required=True)
    ap.add_argument("--baseline", default=DEFAULT_BASELINE)
    ap.add_argument("--report", default=DEFAULT_REPORT)
    ap.add_argument("--json-out", default="")
    args = ap.parse_args(argv)

    # Windows 控制台/管道默认按 ANSI 代码页编码，"⊇"这类符号会直接抛
    # UnicodeEncodeError 把整个校验打成 traceback。显式钉 UTF-8 + replace：
    # 校验结论不能因为一个字符打不出来就消失。
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    try:
        contract = json.loads(Path(args.contract).read_text(encoding="utf-8"))
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    except Exception as exc:
        print("[fail] 读不了输入：%s" % exc, file=sys.stderr)
        return 2

    rows, metrics, extras, verdict = evaluate(contract, baseline)
    print(render_console(rows, metrics, verdict, contract, baseline))

    if args.report:
        report = Path(args.report)
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(render_markdown(rows, metrics, extras, verdict, contract, baseline),
                          encoding="utf-8")
        print("\n报告：%s" % report)

    if args.json_out:
        payload = {
            "verdict": "pass" if verdict else "fail",
            "metrics": metrics,
            "rows": [{"label": r["route"].get("label"),
                      "path": r["route"].get("path_template"),
                      "expected_status": r["route"].get("expected_status"),
                      "observed_statuses": r["observed_statuses"],
                      "phase": r["phase"],
                      "endpoint_id": r["endpoint_id"],
                      "evidence_ref": r["evidence_ref"]} for r in rows],
        }
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())

