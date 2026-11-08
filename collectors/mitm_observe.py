# -*- coding: utf-8 -*-
"""mitm_observe —— 流量观测 addon：本工程的**唯一证据来源**。

它做三件事，每一件都对应架构里的一条约束
==========================================
1. **逐条落盘**：每一条 HTTP 交换写成一行 JSONL 到 ``/evidence/flows/<run_id>.jsonl``。
   为什么不是 HAR：HAR 是一个需要整体合成的容器格式，中途崩溃就全军覆没；
   JSONL 一行一条、崩溃前的行仍然是有效证据，也便于直接 grep。

2. **目标重写**：宿主机浏览器把 Host 写成 ``127.0.0.1:3000``，但容器里的
   ``127.0.0.1`` 是容器自己。``TARGET_HOST_ALIAS`` 把"发往宿主回环的请求"
   改投到 ``host.docker.internal``，**并在证据里同时记下原始 authority 与实际去向**
   ——只记改写后的值，等于把"这次到底打到哪"这个事实抹掉。

3. **算法线索标注**：请求里出现 sign/token/timestamp/nonce/encrypt 这类字段时，
   在证据行里打 ``client_algo_hints``。这是 L3（前端算法还原）的入口索引：
   没有它，L3 就得把整份 JSONL 从头读一遍才知道该看哪几条。

刻意不做的事
============
* 不改写响应体（观测点只记录，与 net_attack_defense_lab 的 sensor 同一原则）；
* 不做 TLS 指纹复现（mitmproxy 终止 TLS 后客户端的 JA3/JA4 已变，这一点必须在
  报告里显式声明，不能假装抓到的就是目标看到的）；
* 不屏蔽 Authorization 头：它本身就是待逆向的协议对象。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from mitmproxy import http

#: 单条报文落盘上限。超过即截断并标 ``truncated``——"我读到 2 MB"不能被读成
#: "响应就是 2 MB"。与 labkit/targets/base.py 的 DEFAULT_MAX_BODY_BYTES 同一思路。
MAX_BODY = 256 * 1024

#: 出现这些字段名（小写子串匹配）就打算法线索标签。
ALGO_KEYWORDS = (
    "sign", "signature", "token", "timestamp", "nonce", "encrypt", "decrypt",
    "aes", "rsa", "hmac", "sha", "md5", "captcha", "verify", "deviceid",
)


def _sha16(data: bytes) -> str:
    """短哈希：用于"这条响应和那条是否同一份"，不用于完整性证明。"""
    return hashlib.sha256(data).hexdigest()[:16] if data else ""


def _clip(data: bytes) -> tuple[str, bool]:
    """按上限截断并解码；返回 (文本, 是否截断)。"""
    if not data:
        return "", False
    truncated = len(data) > MAX_BODY
    return data[:MAX_BODY].decode("utf-8", "replace"), truncated


def _parse_alias(raw: str) -> dict[str, str]:
    """``"a:1=b:2,c:3=d:4"`` -> ``{"a:1": "b:2", "c:3": "d:4"}``。

    格式非法（缺等号、空值）的条目直接跳过而不是抛错：addon 起不来会让
    整个观测网不可用，而一条写错的别名只该让那一条映射失效。
    """
    table: dict[str, str] = {}
    for item in (raw or "").split(","):
        item = item.strip()
        if "=" not in item:
            continue
        src, dst = item.split("=", 1)
        src, dst = src.strip(), dst.strip()
        if src and dst:
            table[src] = dst
    return table


def _algo_hints(flow: http.HTTPFlow) -> list[str]:
    """从 query key、请求体 key、头名里提取算法线索词（去重、保持稳定顺序）。"""
    haystack: list[str] = [str(k) for k in flow.request.query.keys()]
    try:
        body = flow.request.get_text(strict=False) or ""
    except Exception:  # 二进制体（protobuf/上传）解析失败是正常情况
        body = ""
    if body[:1] in ("{", "["):
        try:
            payload = json.loads(body)
            if isinstance(payload, dict):
                haystack.extend(str(k) for k in payload.keys())
        except Exception:
            pass
    haystack.extend(str(k) for k in flow.request.headers.keys())

    hits: list[str] = []
    for name in haystack:
        low = name.casefold()
        for kw in ALGO_KEYWORDS:
            if kw in low and kw not in hits:
                hits.append(kw)
    return hits



class Observe:
    """mitmproxy addon。

    无状态的部分（别名表、证据路径）在 ``__init__`` 里一次固定，
    这样"这一轮按什么规则落盘"在启动日志里就能复核，而不是随流量变化。
    """

    def __init__(self) -> None:
        evidence = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))
        run_id = (os.environ.get("RUN_ID") or "").strip()
        self.run_id = run_id or time.strftime("%Y%m%dT%H%M%S")
        flows_dir = evidence / "flows"
        flows_dir.mkdir(parents=True, exist_ok=True)
        self.path = flows_dir / f"{self.run_id}.jsonl"
        # HAR 与 JSONL 是同一份流量的两种序列化：一个崩溃安全、一行一条；一个方便
        # 喂给外部工具（DevTools 导入、OpenAPI 生成）。目录与文件名在这里统一生成，
        # 避免 compose 里再拼一次 run_id 而与证据文件漂移。
        har_dir = evidence / "har"
        har_dir.mkdir(parents=True, exist_ok=True)
        self.har_path = har_dir / f"{self.run_id}.har"
        self.alias = _parse_alias(os.environ.get("TARGET_HOST_ALIAS", ""))
        self.seq = 0
        # 同名 run 再跑一次时，把上一份证据**改名保留**，而不是接着追加：
        # 追加会让 seq 从 0 重新计数、与旧行撞号，回链锚点（flows#seq-N）当场失效；
        # 直接截断则是销毁证据。改名是唯一同时满足"可复跑"与"不丢证据"的做法。
        if self.path.exists() and self.path.stat().st_size > 0:
            rotated = self.path.with_name(
                f"{self.run_id}.prev-{time.strftime('%Y%m%dT%H%M%S')}.jsonl")
            self.path.rename(rotated)
            print(f"[mitm_observe] 同名证据已存在，旧文件改名为 {rotated.name}", flush=True)
        self._fh = open(self.path, "a", encoding="utf-8")
        print(f"[mitm_observe] run_id={self.run_id}", flush=True)
        print(f"[mitm_observe] evidence={self.path}", flush=True)
        print(f"[mitm_observe] alias={self.alias or '(none)'}", flush=True)

    # -- mitmproxy 生命周期 ---------------------------------------------------
    def done(self) -> None:
        """进程退出时关文件。容器被 kill 时走不到这里，所以才逐行 flush。"""
        try:
            self._fh.close()
        except Exception:
            pass

    def running(self) -> None:
        """把内置 save addon 的 ``hardump`` 指到本轮 HAR 路径。

        为什么不在 compose 的 command 里写 ``--set hardump=...``：那样 run_id 要在
        compose 里再算一遍，和 addon 生成的那份必然漂移；而 HAR 必须与 JSONL 同名，
        才能一眼看出"这两份是同一轮"。`running()` 是 mitmproxy 起好之后、开始
        处理流量之前的钩子，此时改选项是受支持的。
        """
        try:
            from mitmproxy import ctx
            ctx.options.hardump = str(self.har_path)
            print(f"[mitm_observe] hardump={self.har_path}", flush=True)
        except Exception as exc:  # noqa: BLE001
            # HAR 只是附加交付物：导出失败不该让观测网起不来，证据仍然在 JSONL 里。
            print(f"[mitm_observe] hardump 未启用：{exc}", flush=True)

    def request(self, flow: http.HTTPFlow) -> None:
        """改投目标（见模块文档第 2 条）。Host 头保持客户端原值。"""
        port = flow.request.port
        authority = flow.request.pretty_host
        if port not in (80, 443):
            authority = f"{authority}:{port}"
        flow.metadata["wr_client_authority"] = authority

        target = self.alias.get(authority)
        if not target:
            return

        host, _, raw_port = target.partition(":")
        original_host_header = flow.request.headers.get("Host")
        flow.request.host = host
        flow.request.port = int(raw_port) if raw_port else port
        # mitmproxy 改 host 时会顺带改写 Host 头，这里复原：上游看到的主机名应当
        # 与客户端发的一致，否则"同一请求打到不同 vhost"这件事会被掩埋。
        if original_host_header:
            flow.request.headers["Host"] = original_host_header
        flow.metadata["wr_redirected_to"] = target

    def response(self, flow: http.HTTPFlow) -> None:
        self._write(flow, error=None)

    def error(self, flow: http.HTTPFlow) -> None:
        """连接层失败也落盘：``error`` 行是"这条通路不通"的直接证据，
        比一个空响应更有信息量（比如 allow_hosts 把目标拒了就在这一行）。"""
        msg = flow.error.msg if flow.error is not None else "unknown"
        self._write(flow, error=msg)

    # -- 落盘 -----------------------------------------------------------------
    def _write(self, flow: http.HTTPFlow, error: str | None) -> None:
        self.seq += 1
        req = flow.request
        resp = flow.response
        req_raw = req.raw_content or b""
        # 请求体同样解码后落盘（Content-Encoding: gzip 的 API 不少见），raw 长度另记。
        req_decoded = req.content or b""
        req_body, req_trunc = _clip(req_decoded)
        entry: dict[str, Any] = {
            "seq": self.seq,
            "run_id": self.run_id,
            "ts": round(req.timestamp_start or time.time(), 3),
            "client_authority": flow.metadata.get("wr_client_authority"),
            "redirected_to": flow.metadata.get("wr_redirected_to"),
            "client_algo_hints": _algo_hints(flow),
            "request": {
                "method": req.method,
                "scheme": req.scheme,
                "host": req.pretty_host,
                "port": req.port,
                "path": req.path,
                "url": req.pretty_url,
                "headers": {str(k): str(v) for k, v in req.headers.items()},
                "body_len": len(req_decoded),
                "body_raw_len": len(req_raw),
                "content_encoding": req.headers.get("Content-Encoding", ""),
                "body_sha256_16": _sha16(req_decoded),
                "body": req_body,
                "body_truncated": req_trunc,
            },
        }

        if resp is not None:
            # **落盘用解码后的内容，不用 raw_content**：raw 是未解压的上游字节，
            # 客户端只要发了 Accept-Encoding: gzip（浏览器、katana 都会），raw 就是
            # gzip 流。直接 sha 它 = 同一个页面在不同客户端下算出不同哈希、body 变乱码。
            # 实测：index.html 解码后 9984 B，gzip 后 3242 B，两条证据的哈希对不上，
            # 下游"SPA catch-all 判定"直接把真页面误判成壳。传输量另记 raw 长度。
            resp_raw = resp.raw_content or b""
            resp_decoded = resp.content or b""
            resp_body, resp_trunc = _clip(resp_decoded)
            duration = None
            if resp.timestamp_end and req.timestamp_start:
                duration = round((resp.timestamp_end - req.timestamp_start) * 1000, 1)
            entry["response"] = {
                "status": resp.status_code,
                "headers": {str(k): str(v) for k, v in resp.headers.items()},
                "body_len": len(resp_decoded),
                "body_raw_len": len(resp_raw),
                "content_encoding": resp.headers.get("Content-Encoding", ""),
                "body_sha256_16": _sha16(resp_decoded),
                "body_raw_sha256_16": _sha16(resp_raw),
                "body": resp_body,
                "body_truncated": resp_trunc,
                "duration_ms": duration,
            }
        if error:
            entry["error"] = error

        # Windows 的代理栈在遇到 loopback 目标时会先发一条 http://0.0.0.20/ 探测
        # （实测落在证据里是 502），这不是目标端点。标注出来，免得 L2 把它当真实面。
        if req.pretty_host == "0.0.0.20":
            entry["note"] = "windows_loopback_proxy_probe"

        self._fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        # 逐行 flush：容器被 kill 时，最后一秒的流量也不该丢
        self._fh.flush()


addons = [Observe()]
