# -*- coding: utf-8 -*-
"""Step 3 的第三段：HAR（+ 本轮 flows JSONL）-> contract.json。

为什么必须同时读 flows JSONL，而不只看 HAR
==========================================
HAR 记录的是**改写后**的请求。addon 把 ``127.0.0.1:3000`` 改投到
``host.docker.internal:3000``，HAR 又是从 flow 对象序列化出来的，于是 HAR 里的
``request.url`` 全是 ``host.docker.internal``。而"客户端以为自己访问的是哪个
authority"这件事，只存在于 flows JSONL 的 ``client_authority`` 字段里。
所以：**HAR 提供"哪些交换真的发生过"，JSONL 提供"客户端视角的 authority"和
可点回的 ``seq`` 回链锚点**。缺前者就没有覆盖度，缺后者契约会失真且无法回链。

这正是把 P1 的"证据必须可回链"落到 L2 的方式：contract 里的每个端点都带
``flows/<run>.jsonl#seq-N``，报告里的每条结论都能顺着它回到那一行原始报文。

实现约定
========
* 只依赖标准库（宿主机 Python 3.14 与容器内 3.13 都能跑）；
* 时间戳按毫秒 join：HAR 的 ``startedDateTime`` 与 JSONL 的 ``ts`` 都源自同一个
  ``flow.request.timestamp_start``，因此可以精确对齐；对不上就记账，不猜。
* 数字/UUID 段模板化成 ``{int}``/``{uuid}``，同一资源的不同 id 归并为一个端点，
  原始具体路径保留在 ``path_samples``——契约要的是"接口"，不是"某个 id 的副本"。

用法
====
    python collectors\\har_to_contract.py --har evidence\\har\\p2.har ^
        --flows evidence\\flows\\p2.jsonl --out contracts\\contract_p2.json ^
        --crawl-window 1762528000,1762528060

退出码：0 = 写出；1 = 输入不可用；2 = 文件名/参数问题。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

#: 与 collectors/mitm_observe.py 保持同一套线索词：契约里的 client_algo 必须是
#: 证据里已经标出来的那些，不能在这里凭空多出几个。
ALGO_KEYWORDS = (
    "sign", "signature", "token", "timestamp", "nonce", "encrypt", "decrypt",
    "aes", "rsa", "hmac", "sha", "md5", "captcha", "verify", "deviceid",
)

NUMERIC = re.compile(r"^\d{1,12}$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEXISH = re.compile(r"^[0-9a-f]{16,}$")

STATIC_EXT = {
    ".js", ".mjs", ".css", ".map", ".json", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4",
    ".txt", ".xml", ".webmanifest",
}


def _parse_iso(text):
    """HAR 的 ``2026-11-07T15:31:37.666Z`` -> epoch 秒（float）。"""
    if not text:
        return None
    s = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def _ms(ts):
    """epoch 秒 -> 毫秒整数，作为 join 键（round 掉浮点噪声）。"""
    return None if ts is None else int(round(float(ts) * 1000))


def load_har(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    log = data.get("log") or {}
    entries = log.get("entries") or []
    return {"creator": log.get("creator") or {}, "entries": entries}


def load_flows(path):
    """读 JSONL 证据；坏行跳过但记账（崩溃前的行仍是有效证据，不能因一行坏掉全丢）。

    **只按 ``"\\n"`` 切行，绝不用 ``str.splitlines()``**：后者还认 U+2028/U+2029/
    U+0085/换页符这些 Unicode 行界，而 JS 大文件与二进制（如 .kdbx）的响应体里
    恰好有这类字符，于是"一行证据"会被切成几段碎片、逐段 json.loads 失败，
    表现为"有 8 条 HAR 记录 join 不上"，看上去像时间戳对不齐，实际是读文件读坏了。
    JSONL 的行界只有一个：``\\n``。
    """
    flows, bad = [], 0
    if not path:
        return flows, bad
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            flows.append(json.loads(line))
        except Exception:
            bad += 1
    return flows, bad


def templatize(path):
    parts = []
    for seg in path.split("/"):
        if NUMERIC.match(seg):
            parts.append("{int}")
        elif UUID.match(seg):
            parts.append("{uuid}")
        elif HEXISH.match(seg.lower()):
            parts.append("{hex}")
        else:
            parts.append(seg)
    return "/".join(parts)


def classify_kind(path, mime):
    mime = (mime or "").split(";")[0].strip().lower()
    if "json" in mime:
        return "api"
    if mime.startswith("image/") or mime.startswith("font/") or mime in ("text/css", "text/javascript", "application/javascript"):
        return "static"
    if mime in ("text/html", "application/xhtml+xml"):
        return "document"
    suffix = Path(path).suffix.lower()
    if suffix in STATIC_EXT:
        return "static"
    return "other"



def _headers_to_map(items):
    out = {}
    for item in items or []:
        name = (item.get("name") or "").strip().lower()
        if name and name not in out:
            out[name] = item.get("value") or ""
    return out


def _auth_scheme(headers):
    """从请求头判断凭据类型；没有凭据返回 None。"""
    authz = headers.get("authorization", "")
    if authz:
        first = authz.split(" ", 1)[0].strip().lower()
        return first if first in ("bearer", "basic", "digest", "jwt") else "other"
    if headers.get("cookie"):
        return "cookie"
    return None


def build_contract(har_path, flows_path, base_url, run_id, crawl_window, profile):
    """HAR + flows -> 契约字典。返回 (payload, stats)。"""
    har = load_har(har_path)
    flows, bad_lines = load_flows(flows_path)

    # ---- join 索引：HAR 与 JSONL 共用同一个 timestamp_start，按毫秒对齐 --------
    flow_index = {}
    for flow in flows:
        req = flow.get("request") or {}
        key = (req.get("method"), req.get("path"), _ms(flow.get("ts")))
        flow_index.setdefault(key, flow)

    canonical = urlsplit(base_url)
    canonical_origin = canonical.netloc                       # 127.0.0.1:3000
    alias_authority = "host.docker.internal:%s" % (canonical.port or 80)
    accepted = {canonical_origin, alias_authority}

    endpoints = {}
    out_of_scope = []
    join_ok = join_fail = 0

    for idx, entry in enumerate(har.get("entries") or []):
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        method = (req.get("method") or "GET").upper()
        parts = urlsplit(req.get("url") or "")
        plain_path = parts.path or "/"
        path_q = plain_path + ("?" + parts.query if parts.query else "")
        ts = _parse_iso(entry.get("startedDateTime"))

        flow = flow_index.get((method, path_q, _ms(ts)))
        if flow is not None:
            join_ok += 1
        else:
            join_fail += 1

        # authority：优先取证据里的客户端视角（HAR 已被 addon 改写，见模块文档）
        authority = (flow or {}).get("client_authority") or parts.netloc
        redirected = (flow or {}).get("redirected_to")
        if authority not in accepted and not redirected:
            out_of_scope.append({
                "authority": authority,
                "method": method,
                "path": path_q,
                "status": resp.get("status"),
                "har_ref": "har/%s#entry-%d" % (Path(har_path).name, idx),
                "note": (flow or {}).get("note") or "",
            })
            continue

        template = templatize(plain_path)
        ep = endpoints.get((method, template))
        if ep is None:
            ep = endpoints[(method, template)] = {
                "id": None,
                "method": method,
                "path": template,
                "path_samples": [],
                "source": "HAR",
                "kind": classify_kind(plain_path, (resp.get("content") or {}).get("mimeType")),
                "statuses": [],
                "content_types": [],
                "observed_authorities": [],
                "params": [],
                "auth": {"schemes": [], "required": None,
                         "statuses_without_credentials": []},
                "client_algo": [],
                "body_sha256_16": None,
                "spa_shell": False,
                "discovery": {"first_ts": ts, "first_client": None, "clients": [],
                              "phase": None, "hits": 0},
                "evidence_ref": [],
                "_params": {},
                "_noauth": [],
            }
        _fold(ep, req, resp, plain_path, authority, resp.get("status"), flow, ts,
              "har/%s#entry-%d" % (Path(har_path).name, idx), run_id)
    return _finalize(endpoints, crawl_window, har_path, flows_path, har, run_id,
                     base_url, profile, join_ok, join_fail, bad_lines, out_of_scope)


def _fold(ep, req, resp, plain_path, authority, status, flow, ts, har_ref, run_id):
    """把一条 HAR 交换折叠进所属端点。所有字段都是"观察到的事实"，不做推断。"""
    mime = ((resp.get("content") or {}).get("mimeType") or "").split(";")[0].strip()
    if plain_path not in ep["path_samples"] and len(ep["path_samples"]) < 20:
        ep["path_samples"].append(plain_path)
    if status is not None and status not in ep["statuses"]:
        ep["statuses"].append(status)
    if mime and mime not in ep["content_types"]:
        ep["content_types"].append(mime)
    if authority and authority not in ep["observed_authorities"]:
        ep["observed_authorities"].append(authority)

    # 参数：query 取 HAR 的 queryString，body 只取 JSON 顶层 key（值可能含凭据，不落）
    for item in req.get("queryString") or []:
        name = item.get("name")
        if not name:
            continue
        slot = ep["_params"].setdefault(("query", str(name)), [])
        value = item.get("value") or ""
        if value and value not in slot and len(slot) < 5:
            slot.append(value)
    post = (req.get("postData") or {}).get("text") or ""
    if post[:1] in ("{", "["):
        try:
            body = json.loads(post)
            if isinstance(body, dict):
                for name in body:
                    ep["_params"].setdefault(("body", str(name)), [])
        except Exception:
            pass

    hmap = _headers_to_map(req.get("headers"))
    scheme = _auth_scheme(hmap)
    if scheme and scheme not in ep["auth"]["schemes"]:
        ep["auth"]["schemes"].append(scheme)
    if scheme is None and status in (401, 403) and status not in ep["_noauth"]:
        ep["_noauth"].append(status)
    for hint in (flow or {}).get("client_algo_hints") or []:
        tag = "hint:%s" % hint
        if tag not in ep["client_algo"]:
            ep["client_algo"].append(tag)

    ua = hmap.get("user-agent") or "unknown"
    disc = ep["discovery"]
    disc["hits"] += 1
    if ua not in disc["clients"]:
        disc["clients"].append(ua)
    # 初值只给了 first_ts，所以这里必须同时判两个字段：只看 ts 会让首条交换
    # 永远进不来（first_ts 在创建时就等于它），first_client 一路是 null。
    if disc["first_client"] is None or (ts is not None and
                                        (disc["first_ts"] is None or ts < disc["first_ts"])):
        # first_client 必须与 first_ts 同源，否则"谁先发现的"会前后矛盾
        disc["first_ts"] = ts
        disc["first_client"] = ua

    if har_ref not in ep["evidence_ref"]:
        ep["evidence_ref"].append(har_ref)
    if flow is not None and flow.get("seq") is not None:
        seqref = "flows/%s.jsonl#seq-%s" % (run_id, flow["seq"])
        if seqref not in ep["evidence_ref"]:
            ep["evidence_ref"].append(seqref)

    # 响应体哈希：用于识别 SPA catch-all（见 _finalize）。取第一条带响应的交换。
    if ep["body_sha256_16"] is None and flow is not None:
        sha = (flow.get("response") or {}).get("body_sha256_16")
        if sha:
            ep["body_sha256_16"] = sha



def _iso(ts):
    if not ts:
        return None
    return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _finalize(endpoints, crawl_window, har_path, flows_path, har, run_id,
              base_url, profile, join_ok, join_fail, bad_lines, out_of_scope):
    cw_start, cw_end = crawl_window if crawl_window else (None, None)

    eplist = []
    for (method, _template), ep in endpoints.items():
        ep["params"] = [{"name": name, "in": where, "observed_values": values}
                        for (where, name), values in sorted(ep.pop("_params").items())]
        noauth = ep.pop("_noauth")
        ep["auth"]["statuses_without_credentials"] = sorted(noauth)
        if ep["auth"]["required"] is None:
            if any(s in (401, 403) for s in noauth):
                ep["auth"]["required"] = True
            elif 200 in ep["statuses"]:
                ep["auth"]["required"] = False

        # 阶段归属：靠"爬虫窗口"这条外部时间线判定，不靠猜 UA。
        # 只在起点留 1s 余量（编排脚本先记 start 再拉爬虫，浮点/取整噪声）；
        # 结尾**不加**余量：编排脚本在爬虫退出后 sleep 一下才记 crawl_end，
        # 迟到的在途请求仍然落在窗口内，给结尾放宽反而会吞掉紧随其后的回放流量。
        ts = ep["discovery"]["first_ts"]
        if cw_start is None:
            phase = "unknown"
        elif ts is not None and cw_start - 1 <= ts <= (cw_end if cw_end else cw_start + 900):
            phase = "crawl"
        else:
            phase = "replay"
        ep["discovery"]["phase"] = phase
        ep["discovery"]["first_ts"] = None if ts is None else round(float(ts), 3)
        ep["discovery"]["first_seen_iso"] = _iso(ts)
        ep["statuses"].sort()
        eplist.append(ep)

    eplist.sort(key=lambda e: (e["discovery"]["first_ts"] or 0, e["path"]))

    # SPA catch-all 识别：很多 SPA 对**任何**未知路径都返回同一份 index.html，
    # 于是"200"不再意味着"这个资源存在"。判据取**文档类端点里最常见的响应体哈希**
    # （众数），而不是"首页的哈希"——因为首页自己也可能被 catch-all 接管，
    # 且不同客户端带上/不带 Accept-Encoding 会拿到不同字节（见 mitm_observe 的说明）。
    # 不标的话，几十个假端点会一路污染 L3 的算法归属和 L5 的漏洞筛查。
    doc_hashes = Counter(ep["body_sha256_16"] for ep in eplist
                         if ep["kind"] == "document" and ep["body_sha256_16"])
    shell_hash = doc_hashes.most_common(1)[0][0] if doc_hashes else None
    for ep in eplist:
        ep["spa_shell"] = bool(shell_hash and ep["path"] != "/"
                               and ep["body_sha256_16"] == shell_hash)

    for n, ep in enumerate(eplist, 1):
        ep["id"] = "ep_%04d" % n

    kinds = {}
    for ep in eplist:
        kinds[ep["kind"]] = kinds.get(ep["kind"], 0) + 1

    return {
        "schema": "web-reverse-lab/contract",
        "schema_version": 1,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_by": "collectors/har_to_contract.py",
        "target": {
            "base_url": base_url,
            "profile": profile,
            "canonical_origin": urlsplit(base_url).netloc,
        },
        "sources": {
            "har": str(har_path),
            "har_creator": har.get("creator"),
            "har_entries": len(har.get("entries") or []),
            "flows": str(flows_path) if flows_path else None,
            "flow_lines_joined": join_ok,
            "flow_lines_unjoined": join_fail,
            "flow_bad_lines": bad_lines,
            "join_key": "method + path?query + timestamp_start(ms)",
        },
        "counts": {
            "endpoints": len(eplist),
            "by_kind": kinds,
            "spa_shell": sum(1 for ep in eplist if ep["spa_shell"]),
            "out_of_scope_flows": len(out_of_scope),
        },
        "notes": [
            "HAR 里是 addon 改写后的 authority；客户端原始 authority 见各端点 observed_authorities（来自 flows JSONL）",
            "evidence_ref 同时给 har#entry-N 与 flows#seq-N：前者证明交换发生过，后者是崩溃安全的单行证据锚点",
            "params 的 observed_values 只记 query 值；body 只记字段名（值可能含凭据）",
        ],
        "endpoints": eplist,
        "out_of_scope": out_of_scope[:50],
    }




def main(argv=None):
    ap = argparse.ArgumentParser(description="HAR + flows JSONL -> contract.json")
    ap.add_argument("--har", required=True, help="mitmproxy 导出的 HAR")
    ap.add_argument("--flows", default="", help="同一轮的 evidence/flows/<run_id>.jsonl")
    ap.add_argument("--out", required=True)
    ap.add_argument("--base-url", default="http://127.0.0.1:3000")
    ap.add_argument("--run-id", default="")
    ap.add_argument("--profile", default="juice_shop")
    ap.add_argument("--crawl-window", default="",
                    help="爬虫阶段时间窗 <start>,<end>（epoch 秒）；给了才能区分 crawl/replay")
    args = ap.parse_args(argv)

    # 控制台/管道默认按 ANSI 代码页编码，中文输出会变成乱码甚至抛异常；
    # 产物文件的编码另有明确规定（见 write_text 的 encoding），两者互不替代。
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    har_path = Path(args.har)
    if not har_path.is_file():
        print("[fail] HAR 不存在：%s" % har_path, file=sys.stderr)
        return 1
    flows_path = Path(args.flows) if args.flows else None
    if flows_path is not None and not flows_path.is_file():
        print("[fail] flows 不存在：%s" % flows_path, file=sys.stderr)
        return 1

    crawl_window = None
    if args.crawl_window:
        a, _, b = args.crawl_window.partition(",")
        try:
            crawl_window = (float(a), float(b) if b else None)
        except ValueError:
            print("[fail] --crawl-window 格式应为 <start>,<end>", file=sys.stderr)
            return 2

    run_id = args.run_id or har_path.stem
    payload = build_contract(har_path, flows_path, args.base_url, run_id,
                             crawl_window, args.profile)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    c, s = payload["counts"], payload["sources"]
    print("[ok] %d 个端点 -> %s" % (c["endpoints"], out))
    print("     HAR 条目 %d；与 flows 对齐 %d / 未对齐 %d；跳界 %d"
          % (s["har_entries"], s["flow_lines_joined"], s["flow_lines_unjoined"],
             c["out_of_scope_flows"]))
    print("     kind: %s" % ", ".join("%s=%d" % kv for kv in sorted(c["by_kind"].items())))
    phases = {}
    for ep in payload["endpoints"]:
        p = ep["discovery"]["phase"]
        phases[p] = phases.get(p, 0) + 1
    print("     phase: %s" % ", ".join("%s=%d" % kv for kv in sorted(phases.items())))
    if s["flow_lines_unjoined"]:
        print("     [warn] %d 条 HAR 条目没能与 flows 行对齐——这些端点只有 har#entry 回链，"
              "按『回链等级较低』处理" % s["flow_lines_unjoined"], file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
