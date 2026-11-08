# web_reverse_lab —— 网站逆向 / 漏洞筛查 / 模拟攻击 的容器化架构

> 一句话：这不是"一个更大的扫描器"，而是一条把**黑盒目标收敛成接口契约
> （`contract.json`）**的流水线；漏洞筛查与模拟攻击全部引用那份契约，
> 没有契约引用的漏洞一律不入库。

本工程与同盘的三套既有工程是**互补**关系，不是替代：

| 既有工程 | 它解决什么 | 它不覆盖什么（本工程的入口） |
| --- | --- | --- |
| `D:\web_logic_reverse_lab` | 在**已声明**的 15 条路由上做纵向深挖（测绘→fuzz→统计→报告） | 那 15 条是人工硬编码的；没有爬虫、没有 JS 解析、没有签名还原 |
| `D:\net_attack_defense_lab` | 业务逻辑剧本的跨容器攻防与观测 | 外部攻击面（OWASP 路径）、前端代码层 |
| `D:\逆向工具网络安全汇总` | `.exe`/App 的静态与动态逆向（IDA/Ghidra/Frida/unidbg） | 服务端拿不到二进制，整条链对网站不成立 |
| **本工程** | 未声明表面的**横向发现** + 前端**算法还原** + 模板化筛查 | 见文末「明确不回答的问题」 |

---

## 1. 为什么 `.exe` 的工具链在网站上会失效

不是工具不够多，是**可观测面不同**：

| 维度 | 软件 / .exe 逆向 | 网站逆向 |
| --- | --- | --- |
| 被测单元 | 进程内完整程序，可 dump、断点、改字节 | 四方耦合：浏览器运行时 + 前端资产 + 传输协议 + 服务端黑盒 |
| 真值来源 | 反汇编/反编译的伪代码 | 抓到的报文 + 前端 JS 里的算法 + 观测到的状态变化 |
| 最小可逆单元 | 一个函数 | 一次请求 + 一组前端不变量（sign / nonce / token） |
| 能否单点拦截 | 能（debugger） | 不能（只能代理、CDP、注入 hook） |
| 失败模式 | 加壳、混淆、反调试 | 签名风控、TLS/JA3 指纹、HTTP2 指纹、**没有 JS 运行时算不出参数** |

结论：**换锚点**。`.exe` 锚在「二进制/符号/控制流」，网站锚在「流量 / 前端算法 / 契约」。

---

## 2. 分层架构（L0–L7）

```
L0 基座     镜像供应链 · 网络边界 · 证据与 run_id · 资源上限
L1 表面     资产与存活发现（httpx / nmap / 被动 URL）
L2 契约 ★   接口面还原：爬虫 + JS 提取 + sourcemap + HAR→OpenAPI
L3 算法 ★   前端算法还原：sign/加密/指纹 → 可重放的纯函数 + golden vectors
L4 授权     鉴权矩阵：角色 × 端点 × 对象ID 的差分重放
L5 筛查     模板化与专项：nuclei / ZAP / sqlmap / 请求走私
L6 模拟攻击 finding → 利用链（仅 lab 内靶场），逐步落证据
L7 证据报告 统一 finding schema，每条结论回链到 evidence 的具体行
```

★ = 现有工程完全空白、也是"网站逆向"区别于"网站扫描"的全部所在。

**`contract.json` 是架构的关节**（L2 产出，L3–L6 全部引用）。
当前版本 **schema v2**：把"应当"（声明）/ "实际"（观测）/ "结论"分三层，层与层不互相覆盖，
完整字段表与融合规则见 **[CONTRACT_SCHEMA.md](CONTRACT_SCHEMA.md)**（实现真源：
`collectors/contract_schema.py`，51 条自检断言）。

```jsonc
{
  "schema_version": 2,
  "run_id": "20261107T142100",
  "target": {"base_url": "http://127.0.0.1:3000", "profile": "juice_shop"},
  "endpoints": [{
    "id": "ep_0007",
    "method": "POST",
    "path": "/rest/user/login",
    // 声明层（OpenAPI）：应当怎样
    "parameters": [{"name": "email", "in": "body", "required": true,
                    "schema": {"type": "string", "format": "email"},
                    "source": "OPENAPI", "observed_values": ["admin@juice-sh.op"]}],
    "security": {"declared": [], "required": false, "source": "OPENAPI"},
    "responses": {"200": {"description": "OK", "schema": {"type": "object"},
                          "source": "OPENAPI", "declared": true, "observed_hits": 3}},
    // 观测层（HAR + flows）：实际上怎样
    "observed_statuses": [200],
    "observed_security": {"schemes": [], "statuses_without_credentials": [], "required": null},
    // 结论层：由前两层按固定规则推出
    "status": "active",              // active|deprecated|unverified|hidden|unknown
    "spa_shell": false,              // 200 不等于存在（catch-all 壳）
    "provenance": ["OPENAPI", "HAR_SEQ_17"],   // ★ 审计基石，空则不入库
    "contradictions": [],            // 声明 vs 实测冲突，必须人工复核
    "client_algo": ["signer.js:signLogin"],
    "evidence_ref": ["flows/20261107T142100.jsonl#seq-17",
                     "artifacts/js/main.js#L4821"]
  }]
}
```

**融合优先级（不是覆盖，是分层）**：OpenAPI 定 `parameters`/`security`/`responses.schema`
的"应当"，HAR 定 `observed_*` 的"实际"；两者冲突**只进 `contradictions`，不选边**。

**硬性纪律**：L5 报出的任何漏洞，若 `endpoint_ref` 不在 `contract.json` 里，一律不入库。
这与 `net_attack_defense_lab` 里"判定只用账本事实"是同一条原则——没有契约引用的
漏洞只是扫描器噪音。

---

## 3. 容器拓扑与边界

```
宿主机 Chrome + DevTools（人工探索：唯一"真人指纹"）
        │  127.0.0.1:8080
        ▼
┌──────────────── web-reverse-lab (bridge) ────────────────┐
│  crawler(katana, 仅 --profile crawl)                      │
│      │  必须经代理出去：绕过代理的爬虫结果没有 evidence_ref │
│      ▼                                                    │
│  mitmproxy ── 逐条落盘 ──► evidence/flows/<run>.jsonl     │
│      │        └─ 退出时 ─► evidence/har/<run>.har         │
│      │  出口白名单 allow_hosts（见 .env）                  │
│      ▼                                                    │
│  host.docker.internal:3000 ──► 宿主机上的靶场             │
│                                                           │
│  range(可选, 127.0.0.1:3001) ── juice-shop                │
└───────────────────────────────────────────────────────────┘
```

三条纪律：

1. **端口一律绑 `127.0.0.1`**：宿主机浏览器能用，局域网看不见。
2. **出口靠代理白名单收紧**（`allow_hosts`），而不是 `network_mode: internal`。
   因为目标在宿主机上，容器必须能到 host-gateway，物理隔离在此不成立；
   用"代理拒绝连去哪"替代，且规则写在 `.env` 里可复核。
   ——这是本工程与 `net_attack_defense_lab` 在边界实现上的**刻意差异**，必须写清。
3. **代码只读挂载**：`collectors/` 是 `:ro`，唯一可写是 `evidence/` 与 `artifacts/`。

---

## 4. 六个必须提前拍板的设计决策

| # | 决策 | 结论 | 理由 |
| --- | --- | --- | --- |
| D1 | 浏览器在哪 | **双轨**：L2 人工探索用宿主机 Chrome；L3 自动化复现用容器内 Playwright + CDP | 宿主机指纹真实可装扩展；容器可复现可隔离 |
| D2 | 是否允许出网 | 按 compose profile 开，且 run manifest 留痕 | 否则扫不了任何真实站点 |
| D3 | TLS 指纹 | **双通道**：mitmproxy 只做观测；参数复现走 `curl_cffi`/uTLS | 代理终止 TLS 后 JA3/JA4 已变，不能假装抓到的是目标看到的 |
| D4 | 镜像从哪来 | 本地规范名 + `images.lock` + 镜像站降级重试 | 见 §5 |
| D5 | 重的工具是否常驻 | 不常驻，用 `profiles:` 按需 | 引擎只给了 ~7.7 GiB 内存 |
| D6 | 证据格式 | JSONL（一行一条）+ 原始产物并存 | 崩溃前的行仍是有效证据 |

---

## 5. 镜像供应链（本机实测约束）

| 现象 | 实测证据 | 对策 |
| --- | --- | --- |
| 官方 registry 不可用 | `registry-1.docker.io` → `2a03:2880:f11a:83:face:b00c:0:25de:443`（Facebook 段） | 一律经镜像站前缀拉取后 retag |
| 镜像站大 blob 偶发被重置 | `read tcp ...->[2606:4700:3010::f753:1c2f]:443: wsarecv: ... forcibly closed`、`TLS handshake timeout` | 重试 + 线性退避；必要时提高 IPv4 优先级 |
| CLI 不在 PATH | `exec: "docker-credential-desktop": executable file not found in %PATH%` | `scripts/fix_env.ps1` 写用户 PATH |
| 引擎起不来 | `Wsl/Service/CreateInstance/MountDisk/HCS/E_ACCESSDENIED` + `com.docker.service` Stopped | 管理员启动该服务，或管理员身份运行 Docker Desktop |


---

## 6. 目录骨架

```
D:\web_reverse_lab\
├── ARCHITECTURE.md          本文件：分层、边界、决策
├── CONTRACT_SCHEMA.md       contract.json schema v2 字段表 + 融合规则 R1-R9 + 验证步骤
├── README.md                怎么跑、怎么复核、已知坑
├── docker-compose.yml       observe / crawl / range 三个 profile
├── .env.example             运行期变量（含出口白名单、目标别名、爬虫参数）
├── images.lock              规范名 | 镜像站仓库 | tag | digest
├── scripts\
│   ├── fix_env.ps1          P0：PATH / IPv4 / 引擎可达性体检
│   ├── pull_through.ps1     经镜像站拉取 + retag（带退避重试）
│   ├── up_observe.ps1       起观测网并打印浏览器代理配置
│   ├── verify_p1.ps1        P1 验收：走一次代理并断言证据落盘
│   ├── extract_baseline.py  P2 Step1：RouteProbe -> baseline/*.json（带源指纹）
│   ├── replay_baseline.ps1  P2 Step2：15 条已知路由经代理回放（对照组）
│   ├── p2_baseline.ps1      P2 编排：爬虫→回放→停代理→捞 HAR→契约→校验
│   ├── verify_p2_baseline.py P2 Step4：契约 vs 基线，量化 + 差异分析
│   ├── selftest_har_to_contract.py  转换脚本冒烟测试（纯离线，28 断言）
│   └── selftest_contract_schema.py  schema v2 融合规则自检（纯离线，51 断言）
├── collectors\
│   ├── mitm_observe.py      addon：逐条落盘 + 目标重写 + 算法线索 + HAR 导出
│   ├── har_to_contract.py   HAR + flows -> contract.json（观测轨）
│   └── contract_schema.py   ★ schema v2 真源：归一化 / v1→v2 升级 / 融合 / 校验
├── baseline\                Ground Truth：baseline_15_routes.json
├── contracts\               L2 产物：contract_<run_id>.json
├── evidence\                运行产物（可写）：flows\<run_id>.jsonl、har\<run_id>.har
├── artifacts\               证书、crawl\、replay\、p2\manifest_<run_id>.json
└── reports\                 p2_baseline_report.md 与同名 JSON
```

**为什么 P2 又补了一个 `collectors/contract_schema.py`**：P3 是**多源**契约
（OpenAPI 声明 + HAR 观测 + 未来的 JS 静态提取），如果每个脚本各自拼一遍 JSON，
"同名端点合并成什么形状"就会有三份实现、三套口径。schema 必须先是**代码**，
再是文档，最后才是产物。

**为什么 `contracts/` 是独立的一级目录、而不是塞进 `evidence/`**：
它是 L2 的**产物**，L3–L6 全部只读引用它；而 `evidence/` 是原始观测、一次一删。
把"结论"和"原料"放同一层，迟早会有人拿原料当结论用。

---

## 7. 落地路线与验收标准（P0–P4）

| 阶段 | 目标 | 验收标准（可复核，不靠感觉） |
| --- | --- | --- |
| **P0 环境** | PATH / 镜像站前缀 / IPv4 优先 / 引擎可达 | `docker version` 返回 server 版本；`pull_through.ps1` 连跑 3 次全绿 |
| **P1 观测网** | mitmproxy 起在 `127.0.0.1:8080`，宿主机浏览器可用 | 经代理访问靶场 `/rest/user/login`，`evidence/flows/<run>.jsonl` 出现该请求且 `client_algo_hints` 非空 |
| **P2 契约闭环** | katana + JS 提取 + HAR→OpenAPI 产出 `contract.json` | 见下方「P2 的两条验收线」 |
| **P2.5 schema v2** | 多源契约的公共形状：声明/观测/结论三层 + `provenance` | `selftest_contract_schema.py` 51 断言全过；P2 契约升 v2 后 `verify_p2_baseline.py` 数字**一字不变**（15/15、2/15、15/15） |
| **P3 契约双轨** | 轨道 A 吃 `/api-docs` 的 OpenAPI；轨道 B headless 真跑 JS 触发鉴权流 | 15 条 Ground Truth 全覆盖（≥P2 的 2/15 自动发现力）+ OpenAPI 未声明的端点单列 `status: hidden` 供人工复核 |
| **P4 算法还原** | sign/加密参数 → 可重放纯函数 + golden vectors | 同参数下复算结果与观测值逐字节一致（不断言"绕过"） |

### P2 的两条验收线（实测口径，已落地）

原先只写"端点集合 ⊇ 手写的 15 条"，跑完发现这句话**太容易自我满足**：
只要把这些路由回放一遍，覆盖就必然是 15/15，而"爬虫到底能自动发现什么"一个字没测到。
所以拆成两条，性质不同，**不能合并成一个数**：

| 线 | 指标 | 性质 | 本机实测（juice-shop） |
| --- | --- | --- | --- |
| 控制组 | 契约覆盖基线 15/15 + 每条带 `flows/*.jsonl#seq-N` 回链 | **硬断言**：不满足就是管线有缺陷 | 15/15、回链 15/15 |
| 无监督发现力 | 只在爬虫时间窗内发现的条数 | **度量**：衡量 L1/L2 的自动发现能力，不是及格线 | 2/15（`/`、`/ftp`） |

2/15 不是失败，而是**P3 的需求单**：Angular 的接口地址是运行时拼出来的
（`` `${host}/rest/...` ``），静态 JS 解析（`-jc/-jsluice`）还原不出来 →
要么真跑 JS（`-headless`/Playwright），要么直接吃 `/api-docs` 的 OpenAPI
把 `source: OPENAPI` 并进契约。

**若它多出你没写过的端点，那才是真正的情报。** 实测多出 35 个（已剔除 19 个
SPA catch-all 壳）：`/ftp/*`（403 的一批 + `/ftp/quarantine` 200 + 一个可下载的
`/ftp/incident-support.kdbx`）与 `/redirect`(406)。

两条纪律由这次实测补上：

1. **期望不是断言**。`expected_*` 只在原文表述是断言式时才填；实测不一致记成
   Ground Truth 侧 finding（手写清单随版本过期），不让管线判负。
   实测一例：`/rest/user/whoami` 手写 401，该实例真实返回 200 `{"user":{}}`。
2. **200 不等于存在**。SPA 对未知路径普遍回同一份 index.html，必须用响应体哈希
   识别 catch-all（`spa_shell`），否则 `/juice-shop/build/lib/insecurity.js → 200`
   会被误读成"服务端源码可读"。

---

## 8. 这套架构明确**不**回答的问题

- **不解决风控**：设备指纹、行为、验证码、IP 信誉等对抗性防护不在范围内。
  L3 只做"协议可复现"，不做"绕过"。
- **不覆盖服务端**：服务端拿不到二进制，关于其内部逻辑的结论只能是黑盒推断（最高 HYP）。
- **不代表生产强度**：`allow_hosts` 是代理层面的白名单，不是网络层隔离；
  Docker Desktop 的 NAT 也与 Linux 主机不同。
- **TLS 指纹已变**：经 mitmproxy 的流量，JA3/JA4 是 mitmproxy 的，不是浏览器的。
  任何"目标没拦我"的结论都要先扣掉这一条。
- **不自动判定漏洞真伪**：L5 产出的是 finding，不是结论；L6 的成功判据必须来自靶场账本/状态。

---

## 9. 与既有工程的一致性约定（刻意沿用的部分）

| 约定 | 来源 | 本工程落地位置 |
| --- | --- | --- |
| 证据只进 `evidence/`，代码只读挂载 | `web_logic_reverse_lab` compose | `docker-compose.yml` 的 `:ro` 与 `./evidence:/evidence` |
| 观测点只记录、不改写 | `net_attack_defense_lab/sensor/proxy.py` | `collectors/mitm_observe.py` |
| 边界要可复核（写进配置、可打印） | 两者都有 | `.env` 的 `ALLOW_HOSTS` + addon 启动日志打印别名表 |
| 主机白名单是闭集，不是网段规则 | `labkit/targets/base.py` | `ALLOW_HOSTS` 用显式枚举而非 `.*` |
| 报告每条结论可回链到原始行 | `web_logic_reverse_lab` 报告 | JSONL 的 `seq` 编号即回链锚点 |
