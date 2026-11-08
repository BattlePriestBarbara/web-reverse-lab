# web_reverse_lab 项目总结

> 一句话定位：这不是"一个更大的扫描器"，而是一条把**黑盒目标收敛成接口契约**
> （`contract.json`）的流水线；漏洞筛查与模拟攻击全部引用那份契约，
> 没有契约引用的漏洞一律不入库。
>
> 文档性质：阶段性工程总结（面向归档、答辩与交接）。
> 所有数字均可在同目录产物中回查，未做四舍五入外的修饰。
> 生成日期：2026-11-08　对应工程状态：P2.5 完成、P3 Step 1/2.1 完成。

---

## 0. 一页速览

| 阶段 | 目标 | 状态 | 关键实测数字 |
| --- | --- | --- | --- |
| **P0 环境** | PATH / 镜像站前缀 / IPv4 优先 / 引擎可达 | 已完成 | `docker version` 返回 server 版本；`pull_through.ps1` 连跑 3 次全绿 |
| **P1 观测网** | mitmproxy 起在 `127.0.0.1:8080` | 已完成 | 经代理访问靶场，`evidence/flows/<run>.jsonl` 落盘且 `client_algo_hints` 非空 |
| **P2 契约闭环** | 爬虫 + 回放 + HAR → `contract.json` + 对照基线量化 | 已完成（对照组验证通过） | 控制组 **15/15**、爬虫发现力 **2/15**、断言式状态吻合 **7/8**、证据回链 **15/15**；76 条 HAR 交换 → **68 端点**；新增端点 35（其中 **19 个 SPA 壳已剔除**） |
| **P2.5 契约 schema v2** | 声明 / 观测 / 结论三层 + `provenance` 审计链 + 多源融合 | 已完成 | 自检 **51 断言**全过；真实契约升级后结构零错误（`active=49`、`unknown=19`），且 `unknown` 集合与 `spa_shell` 集合**完全相等**；喂回 P2 校验脚本数字一字不变 |
| **P3 契约双轨** | 轨道 A：吃靶场 `/api-docs` 的 OpenAPI；轨道 B：headless 真跑 JS | **未开始**（Step 2.2 待放行） | — |
| **P4 算法还原** | sign / 加密参数 → 可重放纯函数 + golden vectors | 未开始 | — |

---

## 1. 项目定位

同盘另有三套既有工程，本工程与它们**互补而非替代**：

| 既有工程 | 它解决什么 | 本工程的入口 |
| --- | --- | --- |
| `web_logic_reverse_lab` | 在**已声明**的 15 条路由上纵向深挖（测绘 → fuzz → 统计 → 报告） | 那 15 条是人工硬编码的；本工程负责**自动发现**未声明表面 |
| `net_attack_defense_lab` | 业务逻辑剧本的跨容器攻防与观测 | 本工程补外部攻击面（OWASP 路径）与前端代码层 |
| `逆向工具网络安全汇总` | `.exe`/App 静态与动态逆向（IDA/Ghidra/Frida/unidbg） | 服务端拿不到二进制，那条链对网站不成立 |

**为什么 `.exe` 工具链在网站上失效**：不是工具不够多，是**可观测面不同**。
软件逆向锚在「二进制 / 符号 / 控制流」，网站逆向必须锚在「流量 / 前端算法 / 契约」——
前端可以只代理、只能 CDP/注入 hook，无法单点断点拦截。

---

## 2. 目录与代码构成

```
D:\web_reverse_lab\
├── ARCHITECTURE.md          分层（L0–L7）、边界、六个设计决策、镜像供应链
├── CONTRACT_SCHEMA.md       契约 schema v2 字段表 + 融合规则 R1–R9 + status 判定表
├── README.md                怎么跑、怎么复核、已知坑
├── docs\PROJECT_SUMMARY.md  本文件
├── docker-compose.yml       observe / crawl / range 三个 profile
├── .env.example             出口白名单、目标别名、端口、爬虫参数
├── images.lock              规范名 → 镜像站仓库映射
├── scripts\                 编排与验收（PowerShell + Python）
├── collectors\              mitmproxy addon、HAR→契约、schema v2 真源
├── baseline\                Ground Truth（带源文件 sha256 指纹）
├── contracts\               L2 正式产物（L3–L6 只读引用）
├── evidence\                运行产物：flows/*.jsonl、har/*.har（不入库）
├── artifacts\               证书、crawl、replay、运行清单（不入库）
└── reports\                 验收报告（不入库，见 §8 注）
```

代码规模（`Get-Content | Measure-Object -Line`，不含 evidence/artifacts）：

| 文件 | 行数 | 职责 |
| --- | ---: | --- |
| `collectors/contract_schema.py` | **755** | schema v2 唯一真源：路径签名匹配 / v1→v2 升级 / 多源融合 / 结构校验 / CLI |
| `collectors/har_to_contract.py` | 404 | HAR + flows → 契约（join / 模板化 / 认证推断 / SPA 壳剔除） |
| `scripts/verify_p2_baseline.py` | 362 | 契约对基线做量化评估与差异分析（同时认 v1/v2） |
| `scripts/p2_baseline.ps1` | 247 | P2 编排：爬虫 → 回放 → 停代理 → 捞 HAR → 契约 → 校验 |
| `collectors/mitm_observe.py` | 228 | mitmproxy addon：逐条落盘 / 目标重写 / 算法线索 / HAR 导出 |
| `scripts/selftest_contract_schema.py` | 219 | schema v2 融合规则自检（51 断言，纯离线） |
| `scripts/extract_baseline.py` | 181 | 从既有工程抽 15 条 RouteProbe → `baseline/*.json` |
| `scripts/verify_p1.ps1` / `selftest_har_to_contract.py` | 155 / 155 | P1 验收断言 / 转换脚本冒烟测试（28 断言） |
| `scripts/replay_baseline.ps1` / `pull_through.ps1` | 101 / 103 | 对照组回放 / 镜像站拉取与 retag |
| `scripts/fix_env.ps1` / `up_observe.ps1` | 67 / 63 | 环境体检 / 起观测网 |
| **Python 合计** | **2304** | |
| **PowerShell 合计** | **736** | |

---

## 3. 已完成阶段与验收口径

### 3.1 P0 环境（镜像供应链）

本机实测约束：官方 registry 不可用（`registry-1.docker.io` 解析到 Facebook 段）、
镜像站大 blob 偶发被重置、`docker-credential-desktop` 不在 PATH。
对策是 **`images.lock` + 镜像站前缀 + 线性退避重试**，`fix_env.ps1` 负责写用户 PATH（不需要管理员）。
验收：`docker version` 能拿到 server 版本，`pull_through.ps1` 连跑 3 次全绿。

### 3.2 P1 观测网

三条边界纪律：

1. 端口一律绑 `127.0.0.1`（宿主机浏览器可用，局域网看不见）。
2. 出口靠**代理层白名单**（`ALLOW_HOSTS`）收紧，而非 `network_mode: internal`——
   目标在宿主机上，容器必须能到 host-gateway，物理隔离在此不成立；
   规则写在 `.env` 里可复核。
3. `collectors/` **只读挂载**，唯一可写是 `evidence/` 与 `artifacts/`。

证据格式为 **JSONL（一行一条）**：崩溃前的行仍是有效证据。
`body` / `body_sha256_16` 记的是**解码后**内容（raw 是 gzip 流，直接 sha 会让"同一页面"在不同客户端下算出不同哈希）。

### 3.3 P2 契约闭环

一轮 `p2_baseline.ps1` 依次产出：证据 JSONL、HAR、爬虫发现清单、回放结果、
契约 `contracts/contract_<run_id>.json`、报告、运行清单——**共用同一个 `run_id`，这是"同一轮"的唯一凭据**。

**两条覆盖率必须分开看**（这是本项目最重要的度量设计）：

| 指标 | 值 | 性质 | 含义 |
| --- | --- | --- | --- |
| 控制组覆盖 | **15/15** | **断言** | 手写清单每条路由都能在契约里找到：验证"捕获 → 契约 → 回链"没丢东西 |
| 爬虫发现力 | **2/15** | 度量 | 只有"爬虫时间窗内"发现的才算：L2 的真实自动发现能力 |
| 断言式状态吻合 | **7/8** | **断言** | 仅统计原文给了明确状态码的条目 |
| 证据回链 | **15/15** | **断言** | 每条都带 `flows/<run_id>.jsonl#seq-N` |
| 新增端点 | 35 | 情报 | document=11 / other=4 / static=20 |
| 其中 SPA 壳 | 19 | 已剔除 | 响应体与首页同哈希：这类 200 不代表资源存在 |

把两者合成一个数是最容易犯的错：回放会把分母填满，报告就显得"爬虫很棒"，
而真实情况是"爬虫只会跟着 `<a href>` 走"。本机实测 juice-shop：爬虫能找到 `/` 与 `/ftp`，
但 `/api/*`、`/rest/*` 一个都找不到——Angular 的接口地址是运行时拼的（`` `${host}/rest/...` ``），
静态 JS 解析还原不出来。这就是 P3 双轨的输入。

### 3.4 P2.5 契约 schema v2

v1 的每个字段都是"观测事实"（`statuses` / `content_types` / `params[].observed_values` / `auth.schemes`），
它能回答"发生过什么"，但回答不了下游要问的三件事：参数必填吗、要 Bearer 还是 Cookie、
spec 里有但本次没调用的端点算废弃还是没人碰。v2 因此把信息拆进**三个互不覆盖的层**：

| 层 | 内容 | 来源 |
| --- | --- | --- |
| declared 声明层 | `parameters` / `security` / `responses.schema` —— "应当怎样" | OpenAPI、基线、profile |
| observed 观测层 | `observed_statuses` / `observed_security` / `observed_values` —— "实际怎样" | HAR、爬虫、回放、JS 静态 |
| verdict 结论层 | `status`（active/deprecated/unverified/hidden/unknown）+ `contradictions` | 由前两层按固定规则推出 |

四条关键融合规则：

- **R1 占位符互通**：`{int}` ≡ `{id}` ≡ 任意单段，路径按**段签名**匹配。
  按字符串精确匹配会让多源重合度恒为 0，融合整个失效。
- **R3 观测永不反推 `required`**："这次没传 `q`" ≠ "`q` 非必填"；声明没给就留 `null`。
- **R5/R6 冲突不选边**：声明要鉴权而实测免认证放行、声明没写 401 而实测返回 401，
  一律进 `contradictions` 单列——**这些不一致本身就是最值钱的情报**。
- **R7 活性单点判定**：`spa_shell` 一律 `unknown`（200 ≠ 存在）；无声明轨时不产出 `hidden`。

验收（全部实跑过）：

```powershell
python scripts\selftest_contract_schema.py                                  # 51 断言全过
python scripts\selftest_har_to_contract.py                                   # 28 断言全过（未回归）
python collectors\contract_schema.py --validate contracts\contract_p2_final.json --stats
#   -> 端点 68；status: active=49, unknown=19；provenance: HAR_SEQ_*=68；[ok] 结构校验通过
```

两条硬交叉验证：① `unknown` 的 19 个端点集合与 `spa_shell=true` 集合**完全相等**，49 个真实端点全 `active`，
状态机在真实数据上闭环；② 把 P2 契约升级成 v2 后喂回 `verify_p2_baseline.py`，输出**一字不变**
（15/15、2/15、15/15）——说明换 schema 不破坏既有验收。

实现过程中自检抓出并修掉的两个真 bug（正是"静默合错"那一类）：
① 首个创建端点的记录绕过 `_merge_responses`，导致 `declared` / `observed_hits: 0` 标记丢失，
"声明了但没观测到"与"从没声明过"分不清；② `path` 参数按名字匹配使 `{int}` 与 `id` 永不相等，
一个端点冒出两个路径参数——改为按**段下标**配对，观测侧写法进 `name_aliases`。

---

## 4. 三个必须提前拍板的设计决策

| # | 决策 | 结论 | 理由 |
| --- | --- | --- | --- |
| D1 | 浏览器在哪 | **双轨**：人工探索用宿主机 Chrome；自动化复现用容器内 Playwright + CDP | 宿主机指纹真实、可装扩展；容器可复现、可隔离 |
| D2 | 是否允许出网 | 按 compose profile 开，且 run manifest 留痕 | 否则扫不了任何真实站点 |
| D3 | TLS 指纹 | **双通道**：mitmproxy 只做观测；参数复现走 `curl_cffi` / uTLS | 代理终止 TLS 后 JA3/JA4 已变，不能假装抓到的是目标看到的 |
| D4 | 镜像从哪来 | 本地规范名 + `images.lock` + 镜像站降级重试 | 官方 registry 本机不可用 |
| D5 | 重工具是否常驻 | 不常驻，用 `profiles:` 按需 | 引擎只给了约 7.7 GiB 内存 |
| D6 | 证据格式 | JSONL + 原始产物并存 | 崩溃前的行仍是有效证据 |

**契约是架构的关节**：`contract.json` 由 L2 产出，L3–L6 全部只读引用。
**硬性纪律**：L5 报出的任何漏洞，若 `endpoint_ref` 不在 `contract.json` 里，一律不入库——
没有契约引用的漏洞只是扫描器噪音。

**为什么 `contracts/` 是独立一级目录而不是塞进 `evidence/`**：它是 L2 的**产物**，
下游只读引用；而 `evidence/` 是原始观测、一次一删。把"结论"和"原料"放同一层，
迟早有人拿原料当结论用。

---

## 5. 证据纪律（本项目最核心的工程约束）

1. **断言与度量分开**：`15/15` 是断言（管线完整性），`2/15` 是度量（自动发现能力）。
   两者合计会把"回放填满分母"伪装成"爬虫很强"。
2. **Ground Truth 侧的不一致不判负**：`/rest/user/whoami` 手写期望 401，这台实例真实返回 200 `{"user":{}}`。
   记为 **finding（手写清单过期）**，不让管线判负——否则为了变绿，下一步就是去改断言。
3. **期望值只在原文是断言式表述时才填**（"200"、"401 未带令牌"）；写"未知""A 或 B"的一律 `undetermined`，只展示不断言。
4. **SPA 壳单独标**：响应体哈希与首页相同的 200 不是"存在的资源"，用 `spa_shell` 标记、
   不进存活统计、不进召回分子（实测 68 端点里 19 个是壳）。
5. **`provenance` 为空的端点不入库**：这是 `validate_contract()` 里唯一的硬错误，
   其余问题只出 warning——校验永不因数据难看而抛异常。
6. **冲突入账不静默**：声明与实测不一致只进 `contradictions`，不选边、不覆盖。

---

## 6. 踩过的坑（精选，完整版见 README「已知坑」）

| 现象 | 根因 | 对策 |
| --- | --- | --- |
| 容器里看到 `flows/*.jsonl` 是旧的 | Windows bind mount 元数据缓存滞后数十秒 | 以容器内为准：`docker exec ... wc -l` |
| `Invoke-WebRequest -Proxy` 返回 200，代理里什么都没有 | .NET 对 loopback 目标会**连上代理再绕过它** | 改用 `curl.exe --noproxy ""` |
| 每轮回放多出 `GET /0.1` + `Name or service not known` | PS 5.1 **静默丢弃**空字符串参数，`--noproxy ""` 把后面的 `-A` 吃掉，UA 变成第二个 URL | 用带等号的单 token：`--noproxy=`、`--user-agent=...` |
| `katana` 跑着但零输出、180 秒超时 | `docker compose run` 保留永不关闭的 stdin，katana 阻塞在 `read(0)` | entrypoint 包一层 `exec katana "$@" < /dev/null`；并给 `working_dir` 可写挂载点 |
| HAR 与 flows 同一轮却有若干条 join 不上 | `str.splitlines()` 还认 U+2028/U+0085，JS 大文件被劈成几段 | JSONL 只按 `"\n"` 切行 |
| 同页面两条证据 `body_sha256_16` 不同、`body` 乱码 | `raw_content` 是**未解压**字节，客户端发了 `Accept-Encoding: gzip` | addon 改用解码后的 `content`，raw 长度另记 `body_raw_len` |
| `python xxx.py` 抛 `UnicodeEncodeError: 'gbk' ...` | Windows 控制台按 ANSI 代码页编码 stdout | 脚本内 `sys.stdout.reconfigure(encoding="utf-8")`；PS 侧设 `PYTHONIOENCODING=utf-8` |
| 改完 `.ps1` 报"字符串缺少终止符" | PS 5.1 对无 BOM 的 UTF-8 脚本按 GBK 解析，中文字节吞掉 `"` `}` | 存成 **UTF-8 with BOM** |

---

## 7. 复现方式

```powershell
cd D:\web_reverse_lab

# 0) 纯离线自检（不碰 docker、不碰靶场）
python scripts\selftest_har_to_contract.py          # 28 断言
python scripts\selftest_contract_schema.py          # 51 断言

# 1) 环境体检 + 修 PATH（不需要管理员）
.\scripts\fix_env.ps1

# 2) 经镜像站拉镜像并 retag（带退避重试）
.\scripts\pull_through.ps1 -Only mitmproxy

# 3) 起观测网（按屏幕提示配浏览器代理 127.0.0.1:8080，bypass 必须含 <-loopback>）
.\scripts\up_observe.ps1

# 4) P1 验收：证明"请求 → 代理 → 证据落盘"这条链真的通了
.\scripts\verify_p1.ps1

# 5) P2：爬虫 → 回放 → HAR → contract.json → 对照基线校验（一条命令）
.\scripts\p2_baseline.ps1
.\scripts\p2_baseline.ps1 -SkipCrawl       # 只验回放链路（调转换脚本时用，约 1 分钟）
.\scripts\p2_baseline.ps1 -KeepUp          # 跑完不关观测网

# 6) 契约结构校验 / 现场升级 v1 → v2
python collectors\contract_schema.py --validate contracts\contract_p2_final.json --stats
```

靶场用的是宿主机上已在跑的 juice-shop（`127.0.0.1:3000`），容器侧通过
`host.docker.internal:3000` 访问，两者差异由 `TARGET_HOST_ALIAS` 在 addon 里抹平（`Host` 头保持原样）。

---

## 8. 当前状态与下一步

**已完成**：P0 / P1 / P2（含对照组验证）/ P2.5（schema v2 + 融合 + 自检）。

**进行中的队列**（每步需确认后执行）：

| Step | 内容 | 状态 |
| --- | --- | --- |
| P3 Step 1 | `contract_schema.py` + `CONTRACT_SCHEMA.md` + 51 断言自检 | ✅ 完成 |
| P3 Step 2.1 | 清理上一轮残留中间产物 | ✅ 完成 |
| P3 Step 2.2 | `scripts/parse_openapi.py`：靶场 `/api-docs/swagger.json` → `contract_openapi.json`（`$ref` 循环内联、`deprecated` 标 `status`、容错 skip+warning），再算 15 条 Ground Truth 覆盖率 | ⏸ **待放行** |
| P3 Step 3 | Headless HAR（起容器、登录流程、HAR 路径） | ⏸ 需先列计划并确认 |
| P3 Step 4 | `scripts/merge_contracts.py`：薄封装 `merge_contracts()` | ⏸ |
| P3 Step 5 | `scripts/verify_p3_baseline.py`：召回率 / 元数据覆盖率 / 多源重合度 / 隐藏接口 | ⏸ |

**给 git 提交前必须知道的一件事**：`.gitignore` 当前排除 `reports/`、`evidence/`、`artifacts/`、`.env`。
这意味着 `reports/p2_baseline_report.md`（P2 验收报告，唯一可复核的量化结论）**不会入库**。
若要把该报告归档，需把规则从"排除目录"改成"排除目录内容、再放行 md"：

```gitignore
reports/*
!reports/*.md
```

（`reports/` 这种"排除整个目录"的写法会使 `!` 放行失效，必须先排除目录内容再放行文件。）

---

## 9. 合规与边界

- 端口只绑 `127.0.0.1`，局域网看不见；出网由代理层 `ALLOW_HOSTS` 白名单收紧。
- 目标是**本机授权靶场**（juice-shop），未对任何生产系统发起请求。
- 经 mitmproxy 的流量，TLS 指纹（JA3/JA4）是 mitmproxy 的，不是浏览器的——
  因此参数复现走 `curl_cffi`/uTLS 另一条通道，观测与复现不共用指纹。
- 只在你拥有或明确授权测试的目标上使用。

---

## 10. 产物索引

| 产物 | 路径 | 性质 |
| --- | --- | --- |
| L2 契约（正式） | `contracts/contract_p2_final.json`（68 端点 / v1，可现场升 v2） | 入库 |
| 验收报告 | `reports/p2_baseline_report.md` + `reports/p2_baseline_p2_final.json` | 当前被 `.gitignore` 排除 |
| 证据 | `evidence/flows/p2_final.jsonl`、`evidence/har/p2_final.har` | 不入库（一次一删） |
| Ground Truth | `baseline/baseline_15_routes.json`（含源文件 sha256 指纹） | 入库 |
| 运行清单 | `artifacts/p2/manifest_<run_id>.json` | 不入库 |

> 本文件由工程现状（代码行数、自检输出、`--stats` 输出、P2 报告）逐项核对后写成，
> 与 `ARCHITECTURE.md`（设计）、`CONTRACT_SCHEMA.md`（契约规范）、`README.md`（操作手册）互为补充。

---

## 11. 版本控制状态

- 本目录已于 2026-11-08 执行 `git init`，默认分支 `master`，**尚未产生首个提交**。
- 首次提交将纳入 23 个文件（可用 `git add -A -n` 复核清单）；
  `.env`、`evidence/`、`artifacts/`、`reports/` 已按 `.gitignore` 排除（原因见 §8 末段）。
- 若需与远端约定一致的分支名：`git branch -m main`。
- 提交动作留给维护者执行，避免把"清理中间产物 / 调整 ignore 规则"这类决定混进首个提交。

