# -*- coding: utf-8 -*-
"""contract_schema.py 的离线自检：把"融合规则"钉成可执行的断言。

为什么要有它
============
融合逻辑最怕的不是报错，而是**默默合错**：占位符没通配导致重合度恒为 0、
观测值把声明的 ``required: true`` 覆盖成 false、SPA 壳混进 hidden 清单……
这些都跑得通、都有输出，只有对着真数据看结果才会发现。所以先用合成数据把
每条规则钉死，再拿去跑真实的 OpenAPI / HAR。

覆盖的规则（对应 CONTRACT_SCHEMA.md 的编号）
==========================================
R1 占位符互通：``{int}`` 与 ``{id}`` 是同一接口
R2 尾斜杠归一；大小写敏感（``/api/Products`` ≠ ``/api/products``）
R3 声明定 required/schema，观测只加 observed_values（**观测永不反推必填**）
R4 path 参数按位置合并，保留声明侧的参数名
R5 响应：同状态码既保留声明 schema 也保留观测命中数；未声明状态码标 undeclared
R6 鉴权：声明与实测冲突进 contradictions，不静默选边
R7 活性：active / deprecated / unverified / hidden / unknown 六种情形
R8 v1 -> v2 升级只搬运事实
R9 校验器能抓出"没有 provenance"这类红线

用法：python scripts\\selftest_contract_schema.py    （0 = 全过）
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "collectors"))

import contract_schema as cs  # noqa: E402


def _declared(method, path, *, params=None, sec_required=None, schemes=None,
              responses=None, deprecated=False, kind="api"):
    ep = cs.new_endpoint(method, path, kind=kind)
    ep["parameters"] = params or []
    ep["deprecated"] = deprecated
    ep["security"]["required"] = sec_required
    ep["security"]["source"] = "OPENAPI" if sec_required is not None else None
    ep["security"]["declared"] = [{"scheme": s, "type": "http", "scopes": []}
                                  for s in (schemes or [])]
    ep["responses"] = responses or {}
    cs.add_provenance(ep, "OPENAPI", {"track": "OPENAPI", "spec": "openapi.json"})
    return ep


def _openapi_doc():
    reviews = _declared(
        "GET", "/rest/products/{id}/reviews",
        params=[{"name": "id", "in": "path", "required": True,
                 "schema": {"type": "integer"}, "source": "OPENAPI"}],
        sec_required=False,
        responses={"200": {"description": "OK", "schema": {"type": "array"},
                           "content_types": ["application/json"], "source": "OPENAPI"}})
    basket = _declared(
        "GET", "/rest/basket/{id}",
        params=[{"name": "id", "in": "path", "required": True,
                 "schema": {"type": "integer"}, "source": "OPENAPI"}],
        sec_required=True, schemes=["bearerAuth"],
        responses={"200": {"description": "OK", "source": "OPENAPI"}})
    login = _declared(
        "POST", "/rest/user/login",
        params=[{"name": "email", "in": "body", "required": True,
                 "schema": {"type": "string"}, "source": "OPENAPI"}],
        sec_required=False,
        responses={"200": {"description": "OK", "source": "OPENAPI"}})
    legacy = _declared("GET", "/legacy/thing", deprecated=True, sec_required=False)
    authz = _declared("GET", "/rest/user/authentication-details/{id}",
                      sec_required=False,
                      params=[{"name": "id", "in": "path", "required": True,
                               "schema": {"type": "string"}, "source": "OPENAPI"}])
    return {"schema": cs.SCHEMA, "schema_version": 2, "endpoints":
            [reviews, basket, login, legacy, authz]}


def _har_ep(path, *, statuses, samples=None, params=None, auth_required=None,
            noauth=None, seq=65, shell=False, hits=1):
    return {
        "id": None, "method": "GET", "path": path,
        "path_samples": samples or [],
        "source": "HAR", "kind": "api",
        "statuses": statuses,
        "content_types": ["application/json"],
        "observed_authorities": ["127.0.0.1:3000"],
        "params": params or [],
        "auth": {"schemes": [] if auth_required is not True else ["bearer"],
                 "required": auth_required,
                 "statuses_without_credentials": noauth or []},
        "client_algo": [],
        "body_sha256_16": "deadbeefdeadbeef",
        "spa_shell": shell,
        "discovery": {"first_ts": 1794118686.344, "first_client": "wr-harness",
                      "clients": ["wr-harness"], "phase": "replay", "hits": hits},
        "evidence_ref": ["har/p3.har#entry-3",
                         "flows/p3.jsonl#seq-%d" % seq],
    }


def _har_doc():
    """一份 schema v1 的 HAR 契约（P2 的真实形态），用来同时验证升级 + 融合。"""
    return {
        "schema": "web-reverse-lab/contract", "schema_version": 1, "run_id": "p3_har",
        "endpoints": [
            # 与声明的 /rest/products/{id}/reviews 对应（占位符不同名）
            _har_ep("/rest/products/{int}/reviews", statuses=[200],
                    samples=["/rest/products/1/reviews", "/rest/products/2/reviews"],
                    params=[{"name": "q", "in": "query", "observed_values": ["apple"]}],
                    auth_required=False, seq=65, hits=2),
            # 声明 required=True，实测也 401 —— 一致
            _har_ep("/rest/basket/{int}", statuses=[401], samples=["/rest/basket/1"],
                    auth_required=True, noauth=[401], seq=66),
            # 声明 required=False，实测无凭据 401 —— 冲突
            _har_ep("/rest/user/authentication-details/{int}", statuses=[401],
                    samples=["/rest/user/authentication-details/1"], noauth=[401], seq=67),
            # OpenAPI 里没有 —— undeclared 表面
            _har_ep("/ftp/quarantine", statuses=[200], seq=70),
            # SPA catch-all 壳：200 但不算存在
            _har_ep("/juice-shop/build/lib/insecurity.js", statuses=[200], seq=71,
                    shell=True),
        ],
    }


def main():
    failures = []
    total = 0

    def check(name, got, want):
        nonlocal total
        total += 1
        if got != want:
            failures.append("%s: got %r, want %r" % (name, got, want))

    # ---- R1/R2：路径匹配与占位符互通 ----
    check("R1_int_vs_id", cs.paths_match("/rest/products/{int}/reviews",
                                         "/rest/products/{id}/reviews"), True)
    check("R1_template_vs_concrete", cs.paths_match("/rest/products/1/reviews",
                                                    "/rest/products/{id}/reviews"), True)
    check("R2_trailing_slash", cs.paths_match("/api-docs/", "/api-docs"), True)
    check("R2_case_sensitive", cs.paths_match("/api/Products", "/api/products"), False)
    check("R2_segment_count", cs.paths_match("/rest/basket/1", "/rest/basket"), False)
    check("R1_key_equal",
          cs.endpoint_key("get", "/rest/products/{int}/reviews")
          == cs.endpoint_key("GET", "/rest/products/{id}/reviews"), True)

    merged = cs.merge_contracts([("OPENAPI", _openapi_doc()), ("HAR", _har_doc())],
                                run_id="selftest")
    eps = {(e["method"], e["path"]): e for e in merged["endpoints"]}

    reviews = eps[("GET", "/rest/products/{id}/reviews")]
    # ---- R3/R4：参数合并 ----
    path_params = [p for p in reviews["parameters"] if p["in"] == "path"]
    check("R4_single_path_param", len(path_params), 1)
    check("R4_keep_declared_name", path_params[0]["name"], "id")
    check("R4_observed_values", path_params[0]["observed_values"], ["1", "2"])
    check("R4_declared_required", path_params[0]["required"], True)
    check("R4_declared_schema", path_params[0]["schema"], {"type": "integer"})
    check("R4_observed_alias", path_params[0].get("name_aliases"), ["{int}"])
    query = [p for p in reviews["parameters"] if p["in"] == "query"]
    check("R3_query_only_from_har", len(query), 1)
    check("R3_required_not_inferred", query[0]["required"], None)
    check("R3_observed_values_kept", query[0]["observed_values"], ["apple"])

    # ---- R5：响应合并不覆盖 ----
    ok = reviews["responses"]["200"]
    check("R5_declared_schema_kept", ok.get("schema"), {"type": "array"})
    check("R5_observed_hits_kept", ok.get("observed_hits"), 1)
    check("R5_declared_flag", ok.get("declared"), True)
    basket = eps[("GET", "/rest/basket/{id}")]
    check("R5_undeclared_status", basket["responses"]["401"].get("undeclared"), True)
    check("R5_declared_200_unobserved", basket["responses"]["200"].get("observed_hits"), 0)

    # ---- R6：鉴权对账 ----
    check("R6_basket_agrees", [c for c in basket["contradictions"]
                               if c["field"] == "security.required"], [])
    check("R6_basket_required", basket["security"]["required"], True)
    check("R6_basket_scheme", basket["security"]["declared"][0]["scheme"], "bearerAuth")
    authz = eps[("GET", "/rest/user/authentication-details/{id}")]
    conflicts = [c for c in authz["contradictions"] if c["field"] == "security.required"]
    check("R6_conflict_recorded", len(conflicts), 1)
    check("R6_conflict_values", (conflicts[0]["declared"], conflicts[0]["observed"]),
          (False, True))

    # ---- R7：活性判定 ----
    check("R7_active", reviews["status"], "active")
    check("R7_active_basket", basket["status"], "active")
    check("R7_unverified_login", eps[("POST", "/rest/user/login")]["status"], "unverified")
    check("R7_deprecated", eps[("GET", "/legacy/thing")]["status"], "deprecated")
    check("R7_hidden_ftp", eps[("GET", "/ftp/quarantine")]["status"], "hidden")
    shell_ep = eps[("GET", "/juice-shop/build/lib/insecurity.js")]
    check("R7_shell_unknown", shell_ep["status"], "unknown")
    check("R7_shell_flag", shell_ep["spa_shell"], True)

    # ---- provenance：审计基石 ----
    check("R_prov_multi", reviews["provenance"], ["OPENAPI", "HAR_SEQ_65"])
    check("R_prov_hidden", eps[("GET", "/ftp/quarantine")]["provenance"], ["HAR_SEQ_70"])
    check("R_prov_detail", reviews["provenance_detail"]["HAR_SEQ_65"]["run_id"], "p3")
    check("R_multi_source", merged["counts"]["multi_source"], 3)
    check("R_hidden_count", merged["counts"]["by_status"].get("hidden"), 1)

    # ---- R8：v1 -> v2 升级只搬事实 ----
    upgraded = cs.upgrade_endpoint(_har_ep(
        "/rest/products/{int}/reviews", statuses=[200, 401],
        samples=["/rest/products/7/reviews"], seq=9))
    check("R8_statuses", upgraded["observed_statuses"], [200, 401])
    check("R8_prov", upgraded["provenance"], ["HAR_SEQ_9"])
    check("R8_responses", sorted(upgraded["responses"]), ["200", "401"])
    check("R8_path_param_from_samples",
          [p["observed_values"] for p in upgraded["parameters"] if p["in"] == "path"],
          [["7"]])
    check("R8_schema_version", cs.normalize_contract(_har_doc())["schema_version"], 2)
    check("R8_upgraded_from",
          cs.normalize_contract(_har_doc()).get("upgraded_from_schema_version"), 1)

    # ---- 纯 HAR 契约（P2 形态）：没有声明轨时不该冒出 hidden ----
    only_har = cs.merge_contracts([("HAR", _har_doc())], run_id="selftest")
    check("R7_no_declared_track_flag", only_har["declared_track_present"], False)
    check("R7_no_hidden_without_declared",
          only_har["counts"]["by_status"].get("hidden"), None)
    check("R7_ftp_active_without_declared",
          {(e["method"], e["path"]): e["status"] for e in only_har["endpoints"]}
          [("GET", "/ftp/quarantine")], "active")

    # ---- R9：校验器 ----
    errors, _ = cs.validate_contract(merged)
    check("R9_merged_valid", errors, [])
    bad = {"schema": cs.SCHEMA, "schema_version": 2, "endpoints": [
        {"id": "ep_bad", "method": "get", "path": "no-slash", "status": "alive",
         "provenance": []}]}
    errors, _ = cs.validate_contract(bad)
    check("R9_catches_provenance", any("provenance" in e for e in errors), True)
    check("R9_catches_status", any("status" in e for e in errors), True)
    check("R9_catches_method", any("method" in e for e in errors), True)
    check("R9_catches_path", any("path" in e for e in errors), True)

    if failures:
        print("[fail] %d/%d 项未通过：" % (len(failures), total))
        for item in failures:
            print("   - %s" % item)
        return 1
    print("[ok] contract_schema 自检全部通过（%d 断言）" % total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


