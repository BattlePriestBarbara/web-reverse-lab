# -*- coding: utf-8 -*-
"""contract.json 的 schema v2：定义、归一化、融合、校验（全工程唯一真源）。

为什么必须升到 v2
=================
v1（P2 产物）里的每个字段都是**观测事实**：``statuses``、``content_types``、
``params[].observed_values``、``auth.schemes``。它能回答"发生过什么"，但回答不了
L3–L6 真正要问的问题：

* 这个参数是必填还是可选？类型是 string 还是 number？（``observed_values`` 只能给样本）
* 某些参数在本次观测里没出现，是"不存在"还是"这次没传"？
* 鉴权是 Bearer 还是 API Key？OpenAPI 声明的和实测的一致吗？
* ``/rest/user/login`` 在 OpenAPI 里有、本次没被调用——它是废弃了，还是只是没人碰？

所以 v2 把每个端点拆成三层，**层与层不互相覆盖**：

    declared（声明：应当怎样）  <- OpenAPI / Swagger
    observed（观测：实际上怎样） <- HAR + flows JSONL
    verdict （结论：本条到底算不算活）<- 由前两层按固定规则推出

三条融合纪律
============
1. **声明优先、观测补充，冲突入账**。OpenAPI 定 ``parameters``/``security``/
   ``responses`` 的"应当"，HAR 定"实际"。两者不一致时**绝不静默合并**，写进
   ``contradictions`` 并在报告里单列——不一致本身就是最有价值的情报
   （声明了鉴权却实测免认证 = 越权线索）。
2. **路径按"段签名"匹配，占位符互通**。HAR 模板化出的是 ``{int}``/``{uuid}``，
   OpenAPI 写的是 ``{id}``/``{productId}``:它们是**同一位置的同一个参数**。
   若按字符串精确匹配，多源重合度会恒为 0，整条融合形同虚设。
3. **200 不等于存在**。SPA 对未知路径普遍回同一份 index.html。``spa_shell`` 的端点
   既不进 ``hidden``，也不进召回率分母的分子——否则爬虫会被自己的假流量喂饱。

用法
====
    # 校验+打印一份契约（自动把 v1 升级到 v2 后再校验）
    python collectors\\contract_schema.py --validate contracts\\contract_p2_final.json

    # 作为库使用
    from contract_schema import merge_contracts, validate_contract
    payload = merge_contracts([("OPENAPI", oa_doc), ("HAR", har_doc)])
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "web-reverse-lab/contract"
SCHEMA_VERSION = 2

#: 端点活性。语义严格区分，不许复用：
#: * active      声明过 + 实测活着（或没有声明轨时，实测活着）
#: * deprecated  OpenAPI 明确标记 deprecated（即使还能访问也按声明走，另记 observed_after_deprecation）
#: * unverified  声明过，但没有任何实测调用（可能是废弃、可能是没人碰、可能是只在后台用）
#: * hidden      实测存在、OpenAPI 从未声明（未声明表面，人工复核的重点）
#: * unknown     证据不足：只抓到 SPA 壳、或声明与实测都无法判定
STATUS = ("active", "deprecated", "unverified", "hidden", "unknown")

PARAM_LOCATIONS = ("path", "query", "header", "cookie", "body")

#: provenance 的合法取值形态。``HAR_SEQ_42`` 指向 flows JSONL 的具体一行，
#: 是"可回链"的最小单位；只写 ``HAR`` 表示来自 HAR 但没有单行锚点（降级证据）。
PROVENANCE_RE = re.compile(r"^(OPENAPI|BASELINE|PROFILE|JS_STATIC|CRAWL|REPLAY|HAR|HAR_SEQ_\d+)$")

#: 声明轨与观测轨的优先级。融合按此顺序做，前者写 declared，后者只写 observed。
TRACK_DECLARED = ("OPENAPI", "BASELINE", "PROFILE")
TRACK_OBSERVED = ("HAR", "CRAWL", "REPLAY", "JS_STATIC")

PLACEHOLDER = re.compile(r"^\{[^{}]*\}$")
NUMERIC = re.compile(r"^\d{1,12}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEXISH = re.compile(r"^[0-9a-f]{16,}$")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- 路径与匹配


def path_segments(path):
    """拆路径段，顺手归一：去掉空段与尾斜杠。

    ``/api-docs/`` 与 ``/api-docs`` 是同一个资源——OpenAPI 常带尾斜杠，
    HAR 侧不加，不归一就会凭空多出一对"只差一个斜杠"的假重合失败。
    """
    return [s for s in (path or "").split("/") if s]


def is_placeholder(segment):
    return bool(PLACEHOLDER.match(segment or ""))


def path_signature(path):
    """把路径压成可比较的签名：占位符一律记为 ``{}``，字面量原样保留（大小写敏感）。

    ``/rest/products/{int}/reviews`` -> ``('rest', 'products', '{}', 'reviews')``
    ``/rest/products/{id}/reviews``  -> 同上（这就是占位符互通的含义）
    """
    return tuple("{}" if is_placeholder(s) else s for s in path_segments(path))


def paths_match(a, b):
    """两个路径（模板或具体值）是否指向同一个接口。占位符与任意单段互通。"""
    sa, sb = path_segments(a), path_segments(b)
    if len(sa) != len(sb):
        return False
    for x, y in zip(sa, sb):
        if x == y:
            continue
        if is_placeholder(x) or is_placeholder(y):
            continue
        return False
    return True


def path_param_slots(template):
    """模板里每个占位符的 (段下标, 占位符原文)。

    用于"按位置"合并路径参数：HAR 的 ``{int}`` 与 OpenAPI 的 ``{id}`` 名字不同，
    但位置相同，合并时必须保留 OpenAPI 的名字、把 HAR 的观测值挂上去。
    """
    return [(i, seg) for i, seg in enumerate(path_segments(template)) if is_placeholder(seg)]


def templatize(path):
    """具体路径 -> 模板（与 har_to_contract.templatize 同一套规则，此处为 v2 内部复用）。"""
    out = []
    for seg in path_segments(path):
        if NUMERIC.match(seg):
            out.append("{int}")
        elif UUID_RE.match(seg):
            out.append("{uuid}")
        elif HEXISH.match(seg.lower()):
            out.append("{hex}")
        else:
            out.append(seg)
    return "/" + "/".join(out)


def endpoint_key(method, path):
    """融合主键。方法大写 + 段签名（占位符已归一）。"""
    return ((method or "GET").upper(), path_signature(path))


# ---------------------------------------------------------------- 端点骨架


def new_endpoint(method, path, kind=None):
    """一个 v2 端点的空骨架。所有"应当"字段初始为 None/空，由各轨填。"""
    return {
        "id": None,
        "method": (method or "GET").upper(),
        "path": path,
        "path_samples": [],
        "kind": kind,
        # --- 声明层（OpenAPI 为主） ---
        "parameters": [],
        "security": {
            "declared": [],          # [{"scheme": "bearerAuth", "type": "http", "scopes": []}]
            "required": None,        # True/False/None —— 声明优先；仅观测可推断时才填
            "source": None,          # 该结论来自哪一轨（"OPENAPI" / "OBSERVED"）
        },
        "responses": {},             # {"200": {"description":..., "schema":..., "source":"OPENAPI"}}
        # --- 观测层（HAR 为主） ---
        "observed_statuses": [],
        "observed_content_types": [],
        "observed_authorities": [],
        "observed_security": {
            "schemes": [],                  # 实测出现过的凭据类型（bearer/cookie/...）
            "statuses_without_credentials": [],
            "required": None,               # 实测推断：见过 401/403 无凭据 -> True
        },
        # --- 结论层 ---
        "status": "unknown",
        "spa_shell": False,
        "deprecated": False,
        "provenance": [],            # ["OPENAPI", "HAR_SEQ_65"] —— 审计基石
        "provenance_detail": {},     # 每个 tag 一条可追溯的元信息
        "contradictions": [],        # [{"field":..., "declared":..., "observed":...
                                     #   "note": "声明与实测冲突，人工复核"}]
        "client_algo": [],
        "discovery": {"first_ts": None, "first_client": None, "clients": [],
                      "phase": None, "hits": 0},
        "evidence_ref": [],
        "notes": [],
    }


def add_provenance(ep, tag, detail=None):
    """登记一个来源 tag。重复登记不覆盖已有 detail（首条证据优先，符合"最早发现"语义）。"""
    if not PROVENANCE_RE.match(tag or ""):
        raise ValueError("非法 provenance tag: %r" % (tag,))
    if tag not in ep["provenance"]:
        ep["provenance"].append(tag)
    if detail and tag not in ep["provenance_detail"]:
        ep["provenance_detail"][tag] = detail


def add_ref(ep, ref):
    """登记一条证据锚点（``har/<run>.har#entry-7`` 或 ``flows/<run>.jsonl#seq-65``）。"""
    ref = (ref or "").strip()
    if ref and ref not in ep["evidence_ref"]:
        ep["evidence_ref"].append(ref)


def add_contradiction(ep, field, declared, observed, note=""):
    """登记一处"声明 vs 实测"冲突。**这是 v2 存在的意义之一，绝不能吞掉。**"""
    item = {"field": field, "declared": declared, "observed": observed}
    if note:
        item["note"] = note
    if item not in ep["contradictions"]:
        ep["contradictions"].append(item)


def find_param(ep, location, name):
    """在 parameters 里按 (in, name) 找已有参数。"""
    for p in ep["parameters"]:
        if p.get("in") == location and p.get("name") == name:
            return p
    return None


# ---------------------------------------------------------------- v1 -> v2 升级


def _v1_status_refs(ep):
    """从 v1 的 evidence_ref 里挑出可用的回链锚点，决定 provenance tag 的精度。"""
    seq_refs = [r for r in (ep.get("evidence_ref") or [])
                if r.startswith("flows/") and "#seq-" in r]
    har_refs = [r for r in (ep.get("evidence_ref") or []) if r.startswith("har/")]
    return seq_refs, har_refs


def upgrade_endpoint(v1):
    """把一个 schema v1 端点升级成 v2。**只搬运事实，不做任何推断**。

    v1 的全部观测字段在新结构里都能找到对应位置，映射表见下方代码；
    推断类结论（required/status）留给 :func:`decide_status` 与融合阶段，
    避免"读旧文件时顺手猜一把"这种最难查的 bug。
    """
    ep = new_endpoint(v1.get("method"), v1.get("path") or "/", v1.get("kind"))
    ep["id"] = v1.get("id")
    ep["path_samples"] = list(v1.get("path_samples") or [])
    ep["spa_shell"] = bool(v1.get("spa_shell"))
    ep["client_algo"] = list(v1.get("client_algo") or [])
    ep["discovery"] = dict(v1.get("discovery") or ep["discovery"])
    ep["evidence_ref"] = list(v1.get("evidence_ref") or [])
    ep["body_sha256_16"] = v1.get("body_sha256_16")

    ep["observed_statuses"] = sorted(v1.get("statuses") or [])
    ep["observed_content_types"] = list(v1.get("content_types") or [])
    ep["observed_authorities"] = list(v1.get("observed_authorities") or [])

    # auth -> 拆成"观测到的凭据"与"未带凭据时的状态码"两半
    auth = v1.get("auth") or {}
    ep["observed_security"] = {
        "schemes": list(auth.get("schemes") or []),
        "statuses_without_credentials": sorted(auth.get("statuses_without_credentials") or []),
        "required": auth.get("required"),
    }
    if auth.get("required") is not None:
        ep["security"]["required"] = auth.get("required")
        ep["security"]["source"] = "OBSERVED"

    # params -> parameters；补上 path 参数（v1 只在 path_samples 里留了具体值）
    for p in v1.get("params") or []:
        ep["parameters"].append({
            "name": p.get("name"),
            "in": p.get("in") or "query",
            "required": None,
            "schema": None,
            "source": "HAR",
            "observed_values": list(p.get("observed_values") or []),
        })
    for idx, ph in path_param_slots(ep["path"]):
        if find_param(ep, "path", ph):
            continue
        values = []
        for sample in ep["path_samples"]:
            segs = path_segments(sample)
            if idx < len(segs) and segs[idx] not in values and len(values) < 5:
                values.append(segs[idx])
        ep["parameters"].append({
            "name": ph,
            "in": "path",
            "required": True,              # 路径参数天然必填（HTTP 语义，不是推断）
            "schema": {"type": "string"},
            "source": "HAR",
            "observed_values": values,
        })

    # 观测到的状态码 -> responses（只有状态码，没有 schema：v1 没记录响应结构）
    for code in ep["observed_statuses"]:
        ep["responses"][str(code)] = {
            "source": "HAR",
            "observed_hits": 1,            # v1 没有分状态计数，至少为 1；升级不夸大
            "content_types": list(ep["observed_content_types"]),
        }

    # provenance：有 flows#seq-N 就用 HAR_SEQ_N（可回链的最小单位），否则降级为 HAR
    seq_refs, har_refs = _v1_status_refs(v1)
    if seq_refs:
        seq = int(seq_refs[0].rsplit("#seq-", 1)[1])
        add_provenance(ep, "HAR_SEQ_%d" % seq, {
            "track": "HAR",
            "ref": seq_refs[0],
            "phase": (ep["discovery"] or {}).get("phase"),
            "run_id": seq_refs[0].split("/", 1)[1].split(".jsonl")[0],
        })
    elif har_refs:
        add_provenance(ep, "HAR", {"track": "HAR", "ref": har_refs[0]})
    return ep


def decide_status(ep, *, is_declared, is_observed, declared_track_present):
    """活性判定。**只在这里判一次**，避免各脚本各写一套口径。

    * SPA 壳一律 ``unknown``：返回 200 不等于资源存在（P2 已踩过）；
    * 声明轨说 deprecated 就以声明为准，实测仍可调用是另一条情报；
    * 没有声明轨时（纯 HAR 契约，如 P2），观测到的都是 ``active``——
      此时 ``hidden`` 无意义（"未声明"要相对于一份声明才成立）。
    """
    if ep.get("spa_shell"):
        return "unknown"
    if is_declared:
        if ep.get("deprecated"):
            return "deprecated"
        return "active" if is_observed else "unverified"
    if not declared_track_present:
        return "active" if is_observed else "unknown"
    return "hidden" if is_observed else "unknown"


# ---------------------------------------------------------------- 融合


def _param_match_key(ep_path, param):
    """参数匹配键（**不含 path 参数**：path 参数按位置配对，见 `_merge_parameters`）。

    * query/header/cookie 用**小写名**：HTTP 头不区分大小写；Express 这类后端
      的 query 名在实测中同样不敏感；
    * body 用原名：JSON 字段是大小写敏感的。
    """
    loc = param.get("in")
    name = param.get("name")
    if loc in ("query", "header", "cookie"):
        return (loc, (name or "").lower())
    return (loc, name)


def _slot_index(template, name):
    """参数名 -> 它在路径模板里的段下标。

    ``{id}`` 与 ``id`` 都算命中：HAR 侧拿占位符原文当参数名，OpenAPI 侧用去掉
    花括号的名字。不把这两种写法归一，"同位置的同一个参数"就永远配不上对，
    结果是一个端点里冒出两个 path 参数（一个叫 {int}、一个叫 id）。
    """
    if not name:
        return None
    for idx, ph in path_param_slots(template):
        if name == ph or ph.strip("{}") == name:
            return idx
    return None



def _merge_one_param(target, p, declared, dst):
    """单个参数并入 target：观测值无条件并集，声明值优先但冲突入账。"""
    tvals = target.setdefault("observed_values", [])
    for v in p.get("observed_values") or []:
        if v not in tvals and len(tvals) < 8:
            tvals.append(v)
    if not declared:
        return
    if target.get("required") is not None and p.get("required") is not None \
            and target["required"] != p["required"]:
        add_contradiction(dst, "parameters.%s.required" % p.get("name"),
                          p["required"], target["required"],
                          "两份声明对同一参数给出不同的必填性")
    if p.get("required") is not None:
        target["required"] = p["required"]
    if p.get("schema") and not target.get("schema"):
        target["schema"] = p["schema"]
    if p.get("description") and not target.get("description"):
        target["description"] = p.get("description")
    if p.get("source"):
        target["source"] = p["source"]


def _merge_parameters(dst, src, declared):
    """参数合并。声明定 required/schema，观测只加 ``observed_values``。

    为什么观测**不能**反推 ``required``：一次请求里参数没出现，可能是不需要，
    也可能是这次恰好没传（例如只在搜索时才带的 ``q``）。把"没观测到"记成
    "非必填"，L4/L5 就会生成缺参请求，最后把真实缺陷误判成误报。

    path 参数按**段下标**配对（R4）：``/rest/products/{int}/reviews`` 与
    ``/rest/products/{id}/reviews`` 的第 3 段是同一个参数，合并后保留声明侧的
    名字（``id``），观测侧的写法记进 ``name_aliases``。
    """
    src_params = src.get("parameters") or []
    path_dst = [p for p in dst["parameters"] if p.get("in") == "path"]
    src_path = [p for p in src_params if p.get("in") == "path"]

    for order, sp in enumerate(src_path):
        want = _slot_index(src.get("path") or dst["path"], sp.get("name"))
        target = None
        for dp in path_dst:
            have = _slot_index(dst["path"], dp.get("name"))
            if want is not None and have is not None:
                if want == have:
                    target = dp
                    break
            elif dp.get("name") == sp.get("name"):
                target = dp
                break
        if target is None and want is None and order < len(path_dst):
            target = path_dst[order]        # 兜底：两边都没有下标时按出现顺序
        if target is None:
            dst["parameters"].append(dict(sp))
            path_dst.append(dst["parameters"][-1])
            continue
        _merge_one_param(target, sp, declared, dst)
        if sp.get("name") and target.get("name") != sp.get("name"):
            alias = target.setdefault("name_aliases", [])
            if sp["name"] not in alias:
                alias.append(sp["name"])

    for p in src_params:
        if p.get("in") == "path":
            continue
        key = _param_match_key(dst["path"], p)
        target = None
        for cand in dst["parameters"]:
            if cand.get("in") == "path":
                continue
            if _param_match_key(dst["path"], cand) == key:
                target = cand
                break
        if target is None:
            dst["parameters"].append(dict(p))
            continue
        _merge_one_param(target, p, declared, dst)



def _merge_security(dst, src, declared):
    """鉴权合并：``declared`` 列表取并集（按 scheme 去重），``required`` 留到最后统一裁定。"""
    s, t = src.get("security") or {}, dst["security"]
    for item in s.get("declared") or []:
        if item not in t["declared"]:
            t["declared"].append(item)
    if declared and s.get("required") is not None:
        t["required"] = s["required"]
        t["source"] = s.get("source") or "OPENAPI"
    o, to = src.get("observed_security") or {}, dst["observed_security"]
    for scheme in o.get("schemes") or []:
        if scheme not in to["schemes"]:
            to["schemes"].append(scheme)
    for code in o.get("statuses_without_credentials") or []:
        if code not in to["statuses_without_credentials"]:
            to["statuses_without_credentials"].append(code)
    if o.get("required") is not None and to.get("required") is None:
        to["required"] = o["required"]


def _merge_responses(dst, src, declared, declared_track_present):
    """响应合并：同一状态码下，声明补 schema、观测补命中次数，**互不覆盖**。"""
    for code, item in (src.get("responses") or {}).items():
        cur = dst["responses"].setdefault(code, {})
        if declared:
            cur["source"] = "OPENAPI"
            cur["declared"] = True
            for field in ("description", "schema", "content_types"):
                if item.get(field) and not cur.get(field):
                    cur[field] = item[field]
            if cur.get("observed_hits") is None:
                cur["observed_hits"] = 0
            continue
        cur["observed_hits"] = (cur.get("observed_hits") or 0) + (item.get("observed_hits") or 0)
        for ct in item.get("content_types") or []:
            cts = cur.setdefault("content_types", [])
            if ct not in cts:
                cts.append(ct)
        if not cur.get("source"):
            cur["source"] = "HAR"

    if declared or not declared_track_present:
        return
    # 观测侧收尾：声明里没有的状态码 = 未声明分支（越权/错误处理/调试口子）
    for code, cur in dst["responses"].items():
        if cur.get("declared"):
            continue
        cur["undeclared"] = True
        add_contradiction(dst, "responses.%s" % code, None, int(code),
                          "实测返回了声明里没有的状态码（可能是错误分支、权限位或调试口子）")


def merge_into(dst, src, *, declared):
    """把一条同键端点记录并入 ``dst``。``declared=True`` 表示 src 来自声明轨。"""
    for sample in src.get("path_samples") or []:
        if sample not in dst["path_samples"] and len(dst["path_samples"]) < 20:
            dst["path_samples"].append(sample)
    if declared and src.get("path") and not dst.get("declared_path"):
        # 声明轨的模板形式更规范（{id} 可读，{int} 不可读），单独记下来供展示
        dst["declared_path"] = src["path"]
    if dst.get("kind") is None and src.get("kind"):
        dst["kind"] = src["kind"]
    if src.get("deprecated"):
        dst["deprecated"] = True
    if src.get("spa_shell"):
        dst["spa_shell"] = True

    _merge_parameters(dst, src, declared)
    _merge_security(dst, src, declared)
    _merge_responses(dst, src, declared, bool(dst.get("_declared_track_present")))

    for key, bucket in (("observed_statuses", "observed_statuses"),
                        ("observed_content_types", "observed_content_types"),
                        ("observed_authorities", "observed_authorities"),
                        ("client_algo", "client_algo")):
        for v in src.get(key) or []:
            if v not in dst[bucket]:
                dst[bucket].append(v)
    for ref in src.get("evidence_ref") or []:
        add_ref(dst, ref)
    for note in src.get("notes") or []:
        if note not in dst["notes"]:
            dst["notes"].append(note)

    # provenance：tag 并集 + detail 合并（审计基石，一个都不能丢）
    for tag in src.get("provenance") or []:
        add_provenance(dst, tag, (src.get("provenance_detail") or {}).get(tag))

    # discovery：取最早首次发现，hits 相加，客户端/阶段并集
    s_disc, t_disc = src.get("discovery") or {}, dst["discovery"]
    t_disc["hits"] = (t_disc.get("hits") or 0) + (s_disc.get("hits") or 0)
    if t_disc.get("first_ts") is None or (
            s_disc.get("first_ts") is not None and s_disc["first_ts"] < t_disc["first_ts"]):
        t_disc["first_ts"] = s_disc.get("first_ts")
        t_disc["first_client"] = s_disc.get("first_client")
        t_disc["phase"] = s_disc.get("phase")
    for c in s_disc.get("clients") or []:
        if c not in t_disc["clients"]:
            t_disc["clients"].append(c)
    phases = t_disc.setdefault("phases", [])
    for ph in (s_disc.get("phases") or ([s_disc["phase"]] if s_disc.get("phase") else [])):
        if ph and ph not in phases:
            phases.append(ph)
    for item in src.get("contradictions") or []:
        if item not in dst["contradictions"]:
            dst["contradictions"].append(item)
    for key in ("body_sha256_16", "openapi_operation_id", "tags", "summary"):
        if src.get(key) is not None and dst.get(key) is None:
            dst[key] = src[key]
    return dst


def _ensure_v2(ep):
    """补齐 v2 骨架里缺失的键（已经是 v2 的记录原样保留，只 setdefault）。"""
    skeleton = new_endpoint(ep.get("method"), ep.get("path") or "/")
    for key, value in skeleton.items():
        if key not in ep:
            ep[key] = value
    for block in ("security", "observed_security", "discovery"):
        for key, value in skeleton[block].items():
            ep[block].setdefault(key, value)
    return ep


def normalize_contract(payload, track=None):
    """任意版本的契约 -> v2 契约（v1 现场升级，v2 只补缺失键）。"""
    if not isinstance(payload, dict):
        raise ValueError("契约必须是 JSON 对象")
    endpoints = payload.get("endpoints")
    if endpoints is None:
        raise ValueError("契约缺少 endpoints 字段")
    version = payload.get("schema_version")
    if isinstance(version, int) and version >= SCHEMA_VERSION:
        out = dict(payload)
        # 深拷贝：融合阶段会原地往端点里写（并集参数、补 response 标记）。
        # 共享嵌套对象会让"输入 payload"被悄悄改写——这类别名 bug 极难查。
        out["endpoints"] = [_ensure_v2(copy.deepcopy(ep)) for ep in endpoints]
        if track in TRACK_DECLARED:
            for ep in out["endpoints"]:
                add_provenance(ep, track, {"track": track})
        return out
    out = {k: v for k, v in payload.items() if k not in ("endpoints", "schema_version")}
    out["schema"] = SCHEMA
    out["schema_version"] = SCHEMA_VERSION
    out["upgraded_from_schema_version"] = version if version is not None else 1
    out["endpoints"] = []
    for raw_ep in endpoints:
        ep = upgrade_endpoint(raw_ep)
        # 单独升级一份旧契约时也要给出活性结论（结论走同一个 decide_status，
        # 不另写一套口径）。旧契约没有声明轨，所以不会冒出 hidden。
        observed = bool(ep["observed_statuses"]) or any(
            r.startswith(("flows/", "har/")) for r in ep["evidence_ref"])
        ep["status"] = decide_status(ep, is_declared=False, is_observed=observed,
                                     declared_track_present=False)
        out["endpoints"].append(ep)
    return out


def _reconcile_security(ep):
    """把"声明要求的鉴权"与"实测有没有真的挡住"对账，冲突入账。

    这是 v2 最值钱的一条推理：声明 ``required: true`` 而实测无凭据即 401 —— 一致；
    声明 ``required: false`` 而实测无凭据返回 401 —— **至少有一边是错的**。
    """
    obs = ep["observed_security"]
    codes = set(obs.get("statuses_without_credentials") or [])
    observed_required = True if codes & {401, 403} else None
    obs["required"] = observed_required

    declared = ep["security"].get("required")
    if declared is None:
        if observed_required is not None:
            ep["security"]["required"] = observed_required
            ep["security"]["source"] = "OBSERVED"
        return
    if observed_required is not None and observed_required != declared:
        add_contradiction(
            ep, "security.required", declared, observed_required,
            "声明与实测冲突：要么声明过期，要么存在免认证旁路——必须人工确认（L4 入口）")
    elif declared and not obs.get("schemes") and 200 in (ep.get("observed_statuses") or []):
        note = ("声明要求鉴权，但实测出现过 200 且未观测到凭据头："
                "无法区分'未带凭据仍放行'与'HAR 未保留凭据头'")
        if note not in ep["notes"]:
            ep["notes"].append(note)


def merge_contracts(docs, *, run_id=None, target=None):
    """多源融合主入口。

    ``docs``：``[("OPENAPI", openapi_payload), ("HAR", har_payload), ...]``。
    轨迹顺序不影响结果：**声明轨永远先合并**（定"应当"），观测轨后合并（补"实际"），
    两类信息写在不同字段里，所以不存在"谁覆盖谁"的问题。
    """
    normalized = [((track or "UNKNOWN").upper(), normalize_contract(payload, track))
                  for track, payload in docs]
    declared_track_present = any(t in TRACK_DECLARED for t, _ in normalized)

    order = [t for t in TRACK_DECLARED if t in dict(normalized)]
    order += [t for t, _ in normalized if t not in TRACK_DECLARED]
    normalized.sort(key=lambda kv: order.index(kv[0]) if kv[0] in order else 99)

    index, declared_keys, observed_keys = {}, set(), set()
    for track, payload in normalized:
        declared = track in TRACK_DECLARED
        for ep in payload["endpoints"]:
            key = endpoint_key(ep.get("method"), ep.get("path"))
            if declared:
                declared_keys.add(key)
            if ep.get("observed_statuses") or any(
                    r.startswith(("flows/", "har/")) for r in ep.get("evidence_ref") or []):
                observed_keys.add(key)
            dst = index.get(key)
            if dst is None:
                dst = index[key] = _ensure_v2(dict(ep))
                dst["parameters"] = [dict(p) for p in ep.get("parameters") or []]
                dst["responses"] = {k: dict(v) for k, v in (ep.get("responses") or {}).items()}
                if declared:
                    # 首个创建者是声明轨时，要在这里就把"声明"标记补上：
                    # 否则该端点永远不会经过 _merge_responses 的声明分支，
                    # "声明了但这个状态码从未被观测到"和"从没声明过"就分不清了。
                    for item in dst["responses"].values():
                        item["source"] = "OPENAPI"
                        item["declared"] = True
                        item.setdefault("observed_hits", 0)
                dst["evidence_ref"] = list(ep.get("evidence_ref") or [])
                dst["provenance"] = list(ep.get("provenance") or [])
                dst["provenance_detail"] = dict(ep.get("provenance_detail") or {})
                dst["_declared_track_present"] = declared_track_present
                dst["_tracks"] = [track]
            else:
                merge_into(dst, ep, declared=declared)
                if track not in dst["_tracks"]:
                    dst["_tracks"].append(track)

    eplist = []
    for key, ep in index.items():
        ep.pop("_declared_track_present", None)
        tracks = ep.pop("_tracks", [])
        _reconcile_security(ep)
        ep["status"] = decide_status(ep, is_declared=key in declared_keys,
                                     is_observed=key in observed_keys,
                                     declared_track_present=declared_track_present)
        # 展示用路径：声明轨的 {id} 形式更可读，观测轨的 {int} 退到另一个字段
        ep["path_observed_template"] = ep["path"]
        if ep.get("declared_path"):
            ep["path"] = ep.pop("declared_path")
        ep["sources_detail"] = {"tracks": tracks,
                                "declared": key in declared_keys,
                                "observed": key in observed_keys,
                                "multi_source": len(ep["provenance"]) > 1}
        ep["observed_statuses"] = sorted(ep["observed_statuses"])
        eplist.append(ep)

    eplist.sort(key=lambda e: (e.get("path") or "", e.get("method") or ""))
    for n, ep in enumerate(eplist, 1):
        ep["id"] = "ep_%04d" % n

    by_status, by_kind = {}, {}
    for ep in eplist:
        by_status[ep["status"]] = by_status.get(ep["status"], 0) + 1
        kind = ep.get("kind") or "unknown"
        by_kind[kind] = by_kind.get(kind, 0) + 1

    sources = {}
    for track, payload in normalized:
        rec = sources.setdefault(track, {"documents": 0, "endpoints": 0, "schema_versions": []})
        rec["documents"] += 1
        rec["endpoints"] += len(payload["endpoints"])
        sv = payload.get("upgraded_from_schema_version", payload.get("schema_version"))
        if sv not in rec["schema_versions"]:
            rec["schema_versions"].append(sv)

    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "generated_at": _now(),
        "generated_by": "collectors/contract_schema.py:merge_contracts",
        "target": target or {},
        "sources": sources,
        "declared_track_present": declared_track_present,
        "counts": {
            "endpoints": len(eplist),
            "by_status": by_status,
            "by_kind": by_kind,
            "multi_source": sum(1 for ep in eplist if ep["sources_detail"]["multi_source"]),
            "spa_shell": sum(1 for ep in eplist if ep["spa_shell"]),
            "contradictions": sum(len(ep["contradictions"]) for ep in eplist),
        },
        "notes": [
            "declared（OpenAPI 声明）与 observed（HAR 实测）写在不同字段，融合不覆盖任何一方",
            "provenance 是审计基石：HAR_SEQ_<n> 可顺着 flows/<run>.jsonl#seq-<n> 回到原始报文",
            "status 由 decide_status 单点判定；spa_shell 一律 unknown，不计入存活与召回",
            "contradictions 记录声明与实测的冲突，必须人工复核，不允许下游脚本静默忽略",
        ],
        "endpoints": eplist,
    }


# ---------------------------------------------------------------- 校验


def validate_contract(payload):
    """结构校验。返回 ``(errors, warnings)``——**永不抛异常**。

    与"解析 OpenAPI 时遇到怪 Schema 就记 warning 跳过"同一原则：一份契约里有 3 个
    端点不合格，不应该让另外 60 个也进不了下游；但错误必须显式列出来，不能静默。
    """
    errors, warnings = [], []
    if not isinstance(payload, dict):
        return ["契约不是 JSON 对象"], warnings
    if payload.get("schema") != SCHEMA:
        warnings.append("schema 字段应为 %r，实际 %r" % (SCHEMA, payload.get("schema")))
    if payload.get("schema_version") != SCHEMA_VERSION:
        warnings.append("schema_version 应为 %d，实际 %r"
                        % (SCHEMA_VERSION, payload.get("schema_version")))
    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        return errors + ["endpoints 缺失或为空"], warnings

    for ep in endpoints:
        eid = ep.get("id") or ep.get("path") or "?"
        method = (ep.get("method") or "")
        if method != method.upper() or not method:
            errors.append("%s: method 必须是非空大写（实际 %r）" % (eid, method))
        path = ep.get("path") or ""
        if not path.startswith("/"):
            errors.append("%s: path 必须以 / 开头（实际 %r）" % (eid, path))
        status = ep.get("status")
        if status not in STATUS:
            errors.append("%s: status 非法（实际 %r，允许 %s）" % (eid, status, "/".join(STATUS)))
        provenance = ep.get("provenance") or []
        if not provenance:
            errors.append("%s: provenance 为空——没有来源的端点不可入库（证据卫生红线）" % eid)
        for tag in provenance:
            if not PROVENANCE_RE.match(str(tag)):
                errors.append("%s: 非法 provenance tag %r" % (eid, tag))
        if status == "hidden" and not (ep.get("observed_statuses") or ep.get("evidence_ref")):
            warnings.append("%s: status=hidden 却没有任何实测证据" % eid)
        if ep.get("spa_shell") and status != "unknown":
            warnings.append("%s: spa_shell=true 但 status=%s（应为 unknown）" % (eid, status))
        if ep.get("deprecated") and status == "active":
            warnings.append("%s: deprecated=true 但 status=active（声明应优先）" % eid)

        for p in ep.get("parameters") or []:
            loc = p.get("in")
            if loc not in PARAM_LOCATIONS:
                errors.append("%s: 参数 %r 的 in 非法（实际 %r）"
                              % (eid, p.get("name"), loc))
            if not p.get("name"):
                errors.append("%s: 存在没有 name 的参数" % eid)
        placeholders = [ph for _, ph in path_param_slots(path)]
        declared_path_params = [(p.get("name") or "").strip("{}")
                                for p in ep.get("parameters") or []
                                if p.get("in") == "path"]
        for ph in placeholders:
            if ph.strip("{}") not in declared_path_params:
                warnings.append("%s: 模板占位符 %s 没有对应的 path 参数定义" % (eid, ph))

        sec = ep.get("security") or {}
        if sec.get("required") not in (True, False, None):
            errors.append("%s: security.required 必须是 true/false/null" % eid)
        for code in (ep.get("responses") or {}):
            if not str(code).isdigit():
                warnings.append("%s: responses 的键 %r 不是状态码" % (eid, code))

        observed_any = bool(ep.get("observed_statuses"))
        if observed_any and not any(r.startswith(("flows/", "har/"))
                                    for r in ep.get("evidence_ref") or []):
            warnings.append("%s: 有实测状态码却没有 har/flows 证据锚点" % eid)
    return errors, warnings


def main(argv=None):
    ap = argparse.ArgumentParser(description="contract.json schema v2 工具")
    ap.add_argument("--validate", required=True, help="待校验的契约 JSON（v1 会先升级）")
    ap.add_argument("--dump-upgraded", default="", help="把升级/规范化后的 v2 契约写到该路径")
    ap.add_argument("--stats", action="store_true", help="打印状态分布与来源分布")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    path = Path(args.validate)
    if not path.is_file():
        print("[fail] 文件不存在：%s" % path, file=sys.stderr)
        return 2
    raw = json.loads(path.read_text(encoding="utf-8"))
    payload = normalize_contract(raw)
    errors, warnings = validate_contract(payload)

    print("[schema] %s -> v%d（源文件 schema_version=%r）"
          % (path.name, SCHEMA_VERSION, raw.get("schema_version")))
    print("         端点 %d 个" % len(payload["endpoints"]))
    if args.stats:
        by_status, by_prov = {}, {}
        for ep in payload["endpoints"]:
            by_status[ep["status"]] = by_status.get(ep["status"], 0) + 1
            for tag in ep["provenance"]:
                key = "HAR_SEQ_*" if tag.startswith("HAR_SEQ_") else tag
                by_prov[key] = by_prov.get(key, 0) + 1
        print("         status: %s" % ", ".join("%s=%d" % kv for kv in sorted(by_status.items())))
        print("         provenance: %s" % ", ".join("%s=%d" % kv for kv in sorted(by_prov.items())))
    if warnings:
        print("[warn] %d 条：" % len(warnings))
        for w in warnings[:20]:
            print("   - %s" % w)
        if len(warnings) > 20:
            print("   ... 另有 %d 条" % (len(warnings) - 20))
    if errors:
        print("[FAIL] %d 条结构错误：" % len(errors))
        for e in errors[:20]:
            print("   - %s" % e)
        return 1
    print("[ok] 结构校验通过")
    if args.dump_upgraded:
        out = Path(args.dump_upgraded)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
        print("     升级后的 v2 契约 -> %s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())






