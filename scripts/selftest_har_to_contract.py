# -*- coding: utf-8 -*-
"""har_to_contract.py 的冒烟测试：合成一对 HAR + flows，跑通后再动真容器。

为什么要它
==========
真实链路一轮要起 mitmproxy、跑爬虫、等 HAR 落盘，一次几分钟；而 join、模板化、
凭据推断都是纯函数，先用合成数据把边界打穿，真跑时就只剩"网络通不通"这种一眼能
看出来问题。

覆盖的四个易错点
================
1. **join 必须按毫秒对齐**：差 1 毫秒就该算未对齐，而不是"差不多对上"；
2. **模板化不能吞掉字面量段**：``/api/Products`` 里的 ``Products`` 是大写字面量，
   不能被当成 id；
3. **两种 authority 都要认**：``127.0.0.1:3000``（宿主机视角）与
   ``host.docker.internal:3000``（容器爬虫视角）都是本目标；
4. **跳界流量要单独记账**：``0.0.0.20`` 那条 Windows 代理探测不能混进端点表。

用法：python scripts\\selftest_har_to_contract.py    （0 = 全过）
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "collectors"))

import har_to_contract as h  # noqa: E402

BASE_URL = "http://127.0.0.1:3000"
RUN_ID = "selftest"
TS0 = 1762527097.666


def _har_entry(method, url, status, mime, headers, query=None, ts=TS0):
    return {
        "startedDateTime": datetime.fromtimestamp(ts, timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "request": {"method": method, "url": url, "headers": headers,
                    "queryString": query or []},
        "response": {"status": status, "content": {"mimeType": mime}},
    }


def _flow(seq, method, path, authority, ts, redirected=None, hints=None, note=None, sha=None):
    entry = {
        "seq": seq, "run_id": RUN_ID, "ts": ts,
        "client_authority": authority, "redirected_to": redirected,
        "client_algo_hints": hints or [],
        "request": {"method": method, "path": path},
    }
    if note:
        entry["note"] = note
    if sha:
        entry["response"] = {"status": 200, "body_sha256_16": sha}
    return entry



def main():
    failures = []
    stats = {"n": 0}

    def check(name, got, want):
        stats["n"] += 1
        if got != want:
            failures.append("%s: got %r, want %r" % (name, got, want))

    # ---- 1. 纯函数 ---------------------------------------------------------
    check("templatize.int", h.templatize("/rest/products/1/reviews"),
          "/rest/products/{int}/reviews")
    check("templatize.literal", h.templatize("/api/Products"), "/api/Products")
    check("templatize.case", h.templatize("/api/Users"), "/api/Users")
    check("kind.js", h.classify_kind("/main.js", "application/javascript"), "static")
    check("kind.api", h.classify_kind("/api/Products", "application/json"), "api")
    check("kind.html", h.classify_kind("/", "text/html"), "document")
    check("kind.api.charset",
          h.classify_kind("/rest/user/whoami", "application/json; charset=utf-8"), "api")
    check("parse_iso", h._ms(h._parse_iso("2026-11-07T15:31:37.666Z")), 1794065497666)

    # ---- 2. 端到端：合成 HAR + flows --------------------------------------
    ua_crawl = "katana/v1.1.2"
    ua_replay = "curl/8.11.0"
    entries = [
        _har_entry("GET", "http://host.docker.internal:3000/", 200, "text/html",
                   [{"name": "User-Agent", "value": ua_crawl}], ts=TS0),
        _har_entry("GET", "http://host.docker.internal:3000/api/Products", 200,
                   "application/json", [{"name": "User-Agent", "value": ua_crawl}], ts=TS0 + 0.1),
        _har_entry("GET", "http://host.docker.internal:3000/rest/products/search?q=apple", 200,
                   "application/json", [{"name": "User-Agent", "value": ua_replay}],
                   query=[{"name": "q", "value": "apple"}], ts=TS0 + 1.0),
        _har_entry("GET", "http://host.docker.internal:3000/rest/user/whoami", 401,
                   "application/json", [{"name": "User-Agent", "value": ua_replay}], ts=TS0 + 1.1),
        _har_entry("GET", "http://host.docker.internal:3000/rest/basket/1", 401,
                   "application/json", [{"name": "User-Agent", "value": ua_replay}], ts=TS0 + 1.2),
        _har_entry("GET", "http://0.0.0.20/", 502, "text/plain",
                   [{"name": "User-Agent", "value": ua_replay}], ts=TS0 + 0.5),
        # 未知路径返回与首页同一份壳（SPA catch-all）
        _har_entry("GET", "http://host.docker.internal:3000/nope", 200, "text/html",
                   [{"name": "User-Agent", "value": ua_crawl}], ts=TS0 + 1.3),
    ]
    flows = [
        _flow(1, "GET", "/", "host.docker.internal:3000", TS0, sha="shellsha"),
        _flow(2, "GET", "/api/Products", "host.docker.internal:3000", TS0 + 0.1),
        _flow(3, "GET", "/rest/products/search?q=apple", "127.0.0.1:3000", TS0 + 1.0,
              redirected="host.docker.internal:3000", hints=["sign", "timestamp"]),
        _flow(4, "GET", "/rest/user/whoami", "127.0.0.1:3000", TS0 + 1.1,
              redirected="host.docker.internal:3000"),
        _flow(5, "GET", "/rest/basket/1", "127.0.0.1:3000", TS0 + 1.2,
              redirected="host.docker.internal:3000"),
        _flow(6, "GET", "/", "0.0.0.20", TS0 + 0.5,
              note="windows_loopback_proxy_probe"),
        _flow(7, "GET", "/nope", "host.docker.internal:3000", TS0 + 1.3, sha="shellsha"),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        har_p = Path(tmp) / "selftest.har"
        flows_p = Path(tmp) / "selftest.jsonl"
        har_p.write_text(json.dumps({"log": {"creator": {"name": "test"}, "entries": entries}}),
                         encoding="utf-8")
        flows_p.write_text("\n".join(json.dumps(f, ensure_ascii=False) for f in flows) + "\n",
                           encoding="utf-8")
        payload = h.build_contract(har_p, flows_p, BASE_URL, RUN_ID,
                                   (TS0 - 1, TS0 + 0.5), "juice_shop")

    eps = {(e["method"], e["path"]): e for e in payload["endpoints"]}
    check("endpoint_count", len(payload["endpoints"]), 6)
    check("has_products", ("GET", "/api/Products") in eps, True)
    check("has_basket_template", ("GET", "/rest/basket/{int}") in eps, True)
    check("join_all", payload["sources"]["flow_lines_unjoined"], 0)
    check("out_of_scope", payload["counts"]["out_of_scope_flows"], 1)
    # SPA catch-all：/nope 与首页同哈希 → 标成壳；首页自己不算壳
    check("spa_shell_flag", eps[("GET", "/nope")]["spa_shell"], True)
    check("root_not_shell", eps[("GET", "/")]["spa_shell"], False)
    check("spa_shell_count", payload["counts"]["spa_shell"], 1)

    search = eps[("GET", "/rest/products/search")]
    check("query_param", search["params"][0]["name"], "q")
    check("query_value", search["params"][0]["observed_values"], ["apple"])
    check("algo_hint", "hint:sign" in search["client_algo"], True)
    check("authority_host", search["observed_authorities"], ["127.0.0.1:3000"])

    whoami = eps[("GET", "/rest/user/whoami")]
    check("auth_required", whoami["auth"]["required"], True)
    check("auth_401", whoami["auth"]["statuses_without_credentials"], [401])
    check("phase_replay", whoami["discovery"]["phase"], "replay")
    check("phase_crawl", eps[("GET", "/api/Products")]["discovery"]["phase"], "crawl")
    check("first_client_set", eps[("GET", "/api/Products")]["discovery"]["first_client"], ua_crawl)
    check("evidence_seq",
          any(r.startswith("flows/%s.jsonl#seq-" % RUN_ID) for r in whoami["evidence_ref"]), True)
    check("ids_assigned", all(e["id"].startswith("ep_") for e in payload["endpoints"]), True)

    # ---- 3. JSONL 只认 "\n" 作行界 ----------------------------------------
    # U+2028 是 JS 里合法出现的字符（也出现在二进制响应体里）。若用 str.splitlines()
    # 读证据，这一行会被劈成两半、两半都解析失败，表现成"join 不上"。
    with tempfile.TemporaryDirectory() as tmp:
        tricky = Path(tmp) / "tricky.jsonl"
        body = {"seq": 1, "ts": TS0, "client_authority": "127.0.0.1:3000",
                "request": {"method": "GET", "path": "/x"}}
        body["request"]["body"] = "line1\u2028line2\u0085line3\u000cend"
        tricky.write_text(json.dumps(body, ensure_ascii=False) + "\n", encoding="utf-8")
        loaded, bad = h.load_flows(tricky)
    check("jsonl_unicode_line_boundary", (len(loaded), bad), (1, 0))

    total = stats["n"]
    if failures:
        print("[fail] %d/%d 项未通过：" % (len(failures), total))
        for item in failures:
            print("   - " + item)
        return 1
    print("[ok] har_to_contract 冒烟测试全部通过（%d 断言）" % total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
