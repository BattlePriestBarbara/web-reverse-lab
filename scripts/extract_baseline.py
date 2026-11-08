# -*- coding: utf-8 -*-
"""Step 1：把 web_logic_reverse_lab 的 15 条 RouteProbe 抽成标准 JSON（Ground Truth）。

三条设计纪律
============
1. **不 import 对方工程**。``import labkit.targets.juice_shop`` 需要把另一个工程的
   根目录塞进 sys.path，还得装齐它那串依赖（pydantic / httpx）。Ground Truth 只是
   一组字面量，用 ``ast`` 读 ``ROUTES`` 的赋值表达式即可：零依赖，也不会因为对方
   工程换了依赖就把本工程的验收卡住。
   代价是只认 ``RouteProbe(...)`` 这种调用写法——所以下面会**比对解析条数与源码里
   ``RouteProbe(`` 的出现次数**，不一致直接报错。静默少抽两条是最坏的失败模式：
   分母悄悄变小，recall 反而更漂亮。

2. **不替原文下结论**。``RouteProbe`` 没有 ``method`` 字段，源码里也没有任何 POST
   探测，所以全部按 GET 记录，并把这个推断依据写进 ``source.probe_method``。
   ``expected_status`` / ``expected_auth_status`` 只在原文是**断言式**表述时填值；
   凡是写"未知""A 或 B""二者必居其一"的，一律 ``undetermined``。
   Juice Shop 版本一变，这 7 条本来就该变——把它们当断言，报告第一次跑就会
   "全部符合预期"，那等于没有证据。

3. **带指纹**。记录源文件 sha256 与条数。这 15 条是硬编码的、会腐烂的资产；
   源文件一动，baseline 就该重抽，否则对照组比的是上一版的标准答案。

用法
====
    python scripts\\extract_baseline.py
    python scripts\\extract_baseline.py --out baseline\\baseline_15_routes.json

退出码：0 = 抽出并写入；1 = 解析条数与源码计数不一致；2 = 源文件不存在。
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_SOURCE = r"D:\web_logic_reverse_lab\labkit\targets\juice_shop.py"
DEFAULT_OUT = r"baseline\baseline_15_routes.json"

#: 断言式预期：以状态码开头。例 "200 + JSON 数组…" / "401 未带令牌…"
DECISIVE_STATUS = re.compile(r"^(\d{3})(?:\s|$)")

#: 出现这些词说明原文自己都没给定论，抽取器不许替它定。
HEDGES = ("未知", "或", "可能", "二者必居其一", "随版本")

#: 源码里出现这个字符串的次数，就是"应该抽到几条"的分母。
PROBE_CALLEE = "RouteProbe"


def _literal(node):
    """取字面量；取不到就返回 None（不猜）。"""
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _find_routes_tuple(tree):
    """找 ``ROUTES = (...)`` 或 ``ROUTES: T = (...)`` 里的那个元组。"""
    found = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        else:
            continue
        if isinstance(target, ast.Name) and target.id == "ROUTES" and isinstance(value, ast.Tuple):
            found = value
    if found is None:
        raise SystemExit("在源码里找不到 ROUTES 元组（写法变了？需要更新抽取器）")
    return found


def _classify(category, expect):
    """返回 (expected_status | None, expected_auth_status)。

    只有原文既给了状态码又没有含糊措辞时，才认为它是断言。
    """
    text = (expect or "").strip()
    hedged = any(h in text for h in HEDGES)
    m = DECISIVE_STATUS.match(text)
    if m and not hedged:
        code = int(m.group(1))
        return code, ("auth_gated" if code in (401, 403) else "public")
    if hedged or text.startswith("未知"):
        return None, "undetermined"
    return None, {"public": "public", "auth": "auth_gated"}.get(category, "undetermined")


def _render(template, params):
    out = template
    for key, value in params.items():
        out = out.replace("{%s}" % key, str(value))
    return out

def extract(source):
    raw = source.read_bytes()
    text = raw.decode("utf-8")
    tree = ast.parse(text)

    per_source_occurrences = text.count(PROBE_CALLEE + "(")
    routes_node = _find_routes_tuple(tree)

    routes = []
    for element in routes_node.elts:
        if not isinstance(element, ast.Call):
            raise SystemExit("ROUTES 里出现了不是 RouteProbe(...) 的元素：%r"
                             % ast.dump(element)[:120])
        kw = {k.arg: k.value for k in element.keywords if k.arg}

        path = _literal(kw.get("path"))
        label = _literal(kw.get("label"))
        category = _literal(kw.get("category"))
        expect = _literal(kw.get("expect")) or ""
        provenance = _literal(kw.get("provenance")) or ""
        query = _literal(kw.get("query")) or ""

        if not (path and label and category):
            raise SystemExit("RouteProbe 缺必填字段（path/label/category）：%r" % label)

        raw_params = _literal(kw.get("default_params")) or ()
        params = {str(k): str(v) for k, v in raw_params}
        expected_status, expected_auth = _classify(category, expect)

        routes.append({
            "id": "juice_shop.%s" % label,
            "label": label,
            "method": "GET",
            "path_template": path,
            "path_sample": _render(path, params),
            "query": query or None,
            "path_params": params or None,
            "category": category,
            "provenance": provenance,
            "expected_status": expected_status,
            "expected_auth_status": expected_auth,
            "expect": expect,
        })

    if len(routes) != per_source_occurrences:
        raise SystemExit(
            "解析条数 %d 与源码里 %s( 出现次数 %d 不一致——有写法没被覆盖，"
            "拒绝写出半份 Ground Truth。" % (len(routes), PROBE_CALLEE, per_source_occurrences))
    if not routes:
        raise SystemExit("ROUTES 是空的")

    m = re.search(r'default_base_url\s*=\s*"([^"]+)"', text)
    base_url = m.group(1) if m else "http://127.0.0.1:3000"

    decisive = [r for r in routes if r["expected_status"] is not None]
    return {
        "schema": "web-reverse-lab/baseline-routes",
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_by": "scripts/extract_baseline.py",
        "purpose": "P2 对照组：用已知答案校准自动提取管线，量化 recall 与差异",
        "source": {
            "project": "web_logic_reverse_lab",
            "file": str(source),
            "symbol": "ROUTES",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "probe_callee_occurrences": per_source_occurrences,
            "probe_method": "GET —— RouteProbe 无 method 字段，源码中亦无 POST 探测，故全部按 GET 记录",
            "policy": "expected_* 仅取原文的断言式表述；含『未知/或/可能/二者必居其一』的一律 undetermined",
        },
        "target": {"profile": "juice_shop", "base_url": base_url},
        "counts": {
            "total": len(routes),
            "decisive_expected_status": len(decisive),
            "expected_auth_gated": sum(1 for r in routes if r["expected_auth_status"] == "auth_gated"),
            "expected_public": sum(1 for r in routes if r["expected_auth_status"] == "public"),
            "undetermined": sum(1 for r in routes if r["expected_auth_status"] == "undetermined"),
        },
        "routes": routes,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="抽 RouteProbe -> baseline JSON")
    ap.add_argument("--source", default=DEFAULT_SOURCE)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    source = Path(args.source)
    if not source.is_file():
        print("[fail] 源文件不存在：%s" % source, file=sys.stderr)
        return 2

    try:
        payload = extract(source)
    except SystemExit as exc:
        print("[fail] %s" % exc, file=sys.stderr)
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    c = payload["counts"]
    print("[ok] %d 条路由 -> %s" % (c["total"], out))
    print("     断言式 expected_status: %d 条；public %d / auth_gated %d / undetermined %d"
          % (c["decisive_expected_status"], c["expected_public"],
             c["expected_auth_gated"], c["undetermined"]))
    print("     源码指纹 sha256=%s…" % payload["source"]["sha256"][:16])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
