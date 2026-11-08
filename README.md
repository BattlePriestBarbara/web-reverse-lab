# web_reverse_lab

网站逆向 / 漏洞筛查 / 模拟攻击的容器化基座。设计依据见 **[ARCHITECTURE.md](ARCHITECTURE.md)**。

当前实现状态：**P0 环境 + P1 观测网 + P2 契约闭环（含对照组验证）+ P2.5 契约 schema v2**。
L2 的 `contract.json` 由真实 HAR 生成，每条端点带可点回的证据行；
`web_logic_reverse_lab` 手写的 15 条路由已被自动管线全部复原（15/15），
并在此过程中抓出 1 条过期期望与 19 个 SPA 假端点。

契约结构已升到 **schema v2**（声明/观测/结论三层 + `provenance` 审计链），
为 P3 的 OpenAPI × HAR 双轨融合做准备 —— 字段表与融合规则见
**[CONTRACT_SCHEMA.md](CONTRACT_SCHEMA.md)**。v1 契约无需重跑，会被现场升级。

---

## 快速开始（三步）

```powershell
cd D:\web_reverse_lab

# 1) 环境体检 + 修 PATH（不需要管理员）
.\scripts\fix_env.ps1

# 2) 从镜像站拉镜像并 retag 成规范名（带退避重试）
.\scripts\pull_through.ps1 -Only mitmproxy

# 3) 起观测网，并按屏幕提示配浏览器代理
.\scripts\up_observe.ps1

# 4) 验收：证明"请求 -> 代理 -> 证据落盘"这条链真的通了
.\scripts\verify_p1.ps1

# 5) P2：爬虫 -> 回放 -> HAR -> contract.json -> 对照基线量化校验（一条命令）
.\scripts\p2_baseline.ps1
```

浏览器代理填 `127.0.0.1:8080`，**bypass 必须含 `<-loopback>`**，
否则浏览器会绕过代理直连 `127.0.0.1`，代理里什么都没有。

靶场用的是你宿主机上已在跑的 juice-shop（`127.0.0.1:3000`），
容器侧通过 `host.docker.internal:3000` 访问，二者的差异由
`TARGET_HOST_ALIAS` 在 addon 里显式抹平（`Host` 头保持原样）。

---

## 看证据

```powershell
# 实时盯
Get-Content .\evidence\flows\<run_id>.jsonl -Wait -Tail 5

# 只看命中了算法线索的请求（L3 的工作队列）
Select-String -Path .\evidence\flows\*.jsonl -Pattern '"client_algo_hints":\["' | Select-Object -First 20

# 看某一条的完整内容
(Get-Content .\evidence\flows\<run_id>.jsonl -Tail 1) | ConvertFrom-Json | Format-List
```

一行一条 JSONL，每行都带 `seq`（回链锚点）、`client_authority`（客户端认为打的是谁）、
`redirected_to`（实际打到哪）、`client_algo_hints`（算法线索词）。

`body` / `body_sha256_16` 记的是**解码后**的内容（不是 `raw_content`）：
客户端一旦发 `Accept-Encoding: gzip`，raw 就是 gzip 流，直接 sha 它会让
"同一个页面"在不同客户端下算出不同哈希（实测 index.html：解码 9984 B、gzip 3242 B）。
传输量另记在 `body_raw_len` / `content_encoding` 里。

---

## P2：契约闭环与对照组验证

```powershell
.\scripts\p2_baseline.ps1                       # 完整一轮（爬虫 + 回放 + 校验）
.\scripts\p2_baseline.ps1 -SkipCrawl            # 只验回放链路（调转换脚本时用，~1 分钟）
.\scripts\p2_baseline.ps1 -KeepUp               # 跑完不关观测网（自己接着抓浏览器流量）
.\scripts\p2_baseline.ps1 -RunId p2_0815 -CrawlTimeoutSec 300
```

一轮会依次产出（文件名共用同一个 `run_id`，这是"同一轮"的唯一凭据）：

| 产物 | 路径 | 说明 |
| --- | --- | --- |
| 证据 | `evidence/flows/<run_id>.jsonl` | 逐条、崩溃安全；`seq` 是回链锚点 |
| HAR | `evidence/har/<run_id>.har` | mitmproxy 内置 save addon 在**退出时**写；不停进程就没有 |
| 爬虫发现 | `artifacts/crawl/katana_<run_id>.txt` | 一行一个 URL（只当诊断用，证据以 HAR 为准） |
| 回放结果 | `artifacts/replay/replay_<run_id>.json` | 15 条路由的真实状态码与字节数 |
| 契约 | `contracts/contract_<run_id>.json` | L2 的正式产物，L3–L6 只读引用 |
| 报告 | `reports/p2_baseline_report.md` | 逐条对比 + 差异分析 + 新端点清单 |
| 运行清单 | `artifacts/p2/manifest_<run_id>.json` | 这一轮按什么参数、什么时间窗跑的 |

### 两个覆盖率必须分开看

| 指标 | 含义 | 性质 |
| --- | --- | --- |
| **控制组覆盖 15/15** | 手写清单里的每条路由都能在契约里找到对应端点 | **断言**（管线完整性） |
| **爬虫发现力 2/15** | 只有"爬虫时间窗内"发现的才算 | 度量（L2 的自动发现能力） |
| **证据回链 15/15** | 每条都带 `flows/<run_id>.jsonl#seq-N` | **断言** |

把两者合成一个数是最容易犯的错：回放会把分母填满，报告就显得"爬虫很棒"，
而真实情况是"爬虫只会跟着 `<a href>` 走"。
本机实测 juice-shop：爬虫能自动找到 `/` 与 `/ftp`，但 `/api/*`、`/rest/*`
一个都找不到——Angular 的接口地址是拼出来的（`` `${host}/rest/...` ``），
静态 JS 解析还原不出来，必须真跑 JS（`-headless`/Playwright）或直接吃
`/api-docs` 的 OpenAPI。这就是 P3 的输入。

### 期望与实测不一致时怎么处理

`expected_*` 只在原文是**断言式**表述时才填值（"200 + …"、"401 未带令牌"）；
写"未知""A 或 B"的一律 `undetermined`，只展示不断言。
实测已出现：`/rest/user/whoami` 手写期望 401，这台实例真实返回 200 `{"user":{}}`。
这类不一致记为 **Ground Truth 侧 finding**（手写清单过期），**不让管线判负**——
否则为了让它变绿，下一步就是去改断言。

### 判定外的两条硬骨头

- **SPA catch-all**：很多 SPA 对任何未知路径都返回同一份 index.html，
  于是"200"不代表资源存在。契约里用响应体哈希标 `spa_shell`（实测 68 个端点里
  19 个是壳）。不标的话，`/juice-shop/build/lib/insecurity.js → 200` 会被当成
  "服务端源码可读"——那是个假情报。
- **`/ftp` 的 502**：目标真实返回 200 但 `Content-Length 11329` 只发了 11317，
  mitmproxy 记协议错误（响应体置 0），curl 侧表现为 502。这是**目标行为**，不是管线缺陷。

---

## 已知坑（都是本机实测出来的，不是通用清单）

| 症状 | 真实原因 | 处置 |
| --- | --- | --- |
| `docker: 无法将"docker"项识别为...` | CLI 不在 PATH | `.\scripts\fix_env.ps1` |
| `error getting credentials - err: exec: "docker-credential-desktop"...` | 同上（凭据助手也在那个目录） | 同上 |
| `registry-1.docker.io` 解析到 `2a03:2880:...:face:b00c` | DNS 被污染到 Facebook 段 | 只用 `pull_through.ps1`，别直接 pull 官方名 |
| `wsarecv: An existing connection was forcibly closed` / TLS handshake timeout | 镜像站大 blob 走 IPv6 到 Cloudflare 不稳 | 脚本已内置退避重试；仍失败则提高 IPv4 优先级（见下） |
| `E_ACCESSDENIED ... 无法将磁盘 D:\Docker\wsl\main\ext4.vhdx 附加到 WSL2: 拒绝访问` | **`com.docker.service` 没在跑**（Manual 启动类型），不是 vhdx 损坏 | 管理员 PowerShell：`Start-Service com.docker.service`，或以管理员身份运行 Docker Desktop |
| `port is already allocated` | 你在跑的靶场已占 `127.0.0.1:3000` | 本工程把内置 range 挪到 `3001` |
| 证据文件在宿主机上"一直是 0 字节"，但容器里明明有内容 | Docker Desktop(Windows) 的 bind mount 元数据缓存滞后（实测数十秒） | 以容器内为准：`docker exec web-reverse-lab-mitmproxy-1 wc -l /evidence/flows/*.jsonl`；`verify_p1.ps1` 就是在容器内断言的 |
| `Invoke-WebRequest -Proxy` 返回 200，代理里却什么都没有 | .NET 对 loopback 目标会**连上代理再绕过它**（mitmproxy 日志只有 connect/disconnect） | 用 `curl.exe --noproxy ""`；`verify_p1.ps1` 已改用 curl |
| 证据里出现 `GET http://0.0.0.20/` 与 502 | Windows 代理栈的 loopback 探测，不是目标端点 | addon 已标 `note: windows_loopback_proxy_probe`，L2 过滤掉即可 |
| 自己改完 `.ps1` 后报"字符串缺少终止符 / 缺少右 `}`" | Windows PowerShell 5.1 对**无 BOM 的 UTF-8** 脚本按 GBK 解析，中文字节吞掉了 `"` `}` | 存成 **UTF-8 with BOM**：`[IO.File]::WriteAllText($f, $t, (New-Object Text.UTF8Encoding $true))` |
| 每轮回放都多出 15 条 `GET /0.1` + `Name or service not known` | PS 5.1 会**静默丢弃**传给原生 exe 的空字符串参数：`--noproxy ""` 只剩 `--noproxy`，把紧跟其后的 `-A` 吃掉，UA 字符串变成**第二个 URL**（`web-reverse-lab-baseline-replay/0.1`） | 用带等号的单 token：`--noproxy=`、`--user-agent=...` |
| `katana` 在容器里"跑着但零输出"，180 秒才超时，代理侧只有 1 条流量 | katana 支持 `cat urls.txt \| katana`，**stdin 是活管道时它会去读输入**；`docker compose run`（含 `-d`/`-T`）会保留一个永不关闭的 stdin → 阻塞在 `read(0)`（`/proc/1/wchan=futex_do_wait`）。`docker run` 默认 stdin=`/dev/null`，所以手工测永远复现不出来 | compose 里把 entrypoint 包一层：`["sh","-c","exec katana \"$$@\" < /dev/null","--"]`（`$$` 是 compose 的转义） |
| 同上症状，但改完 stdin 依旧 | `read_only: true` 时 CWD 是 `/`，而 katana 的 JS 抽取（`-jc/-jsl`）要往**当前目录**写临时文件 → 就地卡死 | 加 `working_dir: /crawl`（可写挂载点），并给 `/root` `/tmp` 挂 tmpfs |
| HAR 与 flows 明明同一轮，却有若干条 "join 不上" | 用 `str.splitlines()` 读 JSONL：它还认 U+2028/U+0085/换页符等 Unicode 行界，JS 大文件与二进制响应体里就有这类字符，一行被劈成几段 | JSONL 只按 `"\n"` 切行（`text.split("\n")`） |
| 同一页面在两条证据里 `body_sha256_16` 不同、`body` 是乱码 | `raw_content` 是**未解压**的上游字节；katana/浏览器会发 `Accept-Encoding: gzip`（9984 B → 3242 B） | addon 已改用解码后的 `content`，raw 长度另记 `body_raw_len` |
| `python xxx.py` 抛 `UnicodeEncodeError: 'gbk' codec can't encode '⊇'` | Windows 控制台按 ANSI 代码页编码 Python 的 stdout | 脚本内 `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`；PS 侧再设 `$env:PYTHONIOENCODING=utf-8` |
| mitmproxy 莫名 `Exited (137)`，`ps -q` 返回空 | 上一轮没退干净的脚本实例跑到了自己的 `compose stop`——compose 是按**项目**操作的，会命中新一轮的容器 | 一次只跑一轮；脚本已改为轮询容器 id、`stop -t 30`（给 HAR 写盘留时间） |
| 多源契约合并时"重合度"恒为 0 | HAR 模板化出 `/rest/products/{int}/reviews`，OpenAPI 写 `/rest/products/{id}/reviews`；按字符串精确匹配**永不相等** | 路径按**段签名**匹配、占位符互通（`contract_schema.paths_match`）；path 参数按段下标配对，合并后保留声明侧名字，观测侧写法进 `name_aliases` |
| 融合后参数 `required` 从 `true` 变成 `false` | 拿"本次请求没带这个参数"反推必填性 | 观测**永不反推** `required`/`schema`：声明没给就留 `null`，不猜 |

提高 IPv4 优先级（需管理员，可回退）：

```powershell
netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 100           # 应用
netsh interface ipv6 reset prefixpolicy                            # 回退
```

---

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `docker-compose.yml` | `observe`（mitmproxy）/ `crawl`（katana）/ `range`（juice-shop）三个 profile |
| `.env`（由 `.env.example` 生成） | 出口白名单 `ALLOW_HOSTS`、目标别名 `TARGET_HOST_ALIAS`、端口、爬虫参数 |
| `images.lock` | 规范名 → 镜像站仓库的映射（换源只改这里） |
| `collectors/mitm_observe.py` | mitmproxy addon：逐条落盘 / 目标重写 / 算法线索 / HAR 导出 |
| `collectors/har_to_contract.py` | HAR + flows → `contract.json`（join / 模板化 / 认证推断 / SPA 壳剔除） |
| `collectors/contract_schema.py` | **schema v2 真源**：归一化 / v1→v2 升级 / 多源融合 / 结构校验（可当 CLI 用） |
| `CONTRACT_SCHEMA.md` | schema v2 字段表、融合规则 R1–R9、`status` 判定表、验证步骤 |
| `scripts/p2_baseline.ps1` | P2 编排：爬虫 → 回放 → 停代理 → 捞 HAR → 契约 → 校验 |
| `scripts/replay_baseline.ps1` | 对照组回放：15 条已知路由经代理逐条打一遍 |
| `scripts/extract_baseline.py` | 从 `web_logic_reverse_lab` 抽出 15 条 RouteProbe → `baseline/*.json` |
| `scripts/verify_p2_baseline.py` | 契约对基线做量化评估与差异分析，出报告（同时认 v1/v2 契约） |
| `scripts/selftest_har_to_contract.py` | 转换脚本的冒烟测试（28 断言，无需 docker） |
| `scripts/selftest_contract_schema.py` | schema v2 融合规则自检（51 断言，无需 docker、不碰靶场） |
| `baseline/` | Ground Truth（带源文件 sha256 指纹，源一变就该重抽） |
| `contracts/` | L2 产物 `contract.json`，L3–L6 只读引用 |
| `scripts/*.ps1` | 体检、拉取、启动、P1 验收 |
| `evidence/` | 运行产物：`flows/<run_id>.jsonl`、`har/<run_id>.har`（容器可写，代码不在此） |
| `artifacts/` | mitmproxy CA 证书、`crawl/`、`replay/`、`p2/` 运行清单 |
| `reports/` | `p2_baseline_report.md` 与同名 JSON |

---

## 边界（必须知道）

- 端口只绑 `127.0.0.1`，局域网看不见。
- 出网由 `ALLOW_HOSTS` 白名单收紧（写在 `.env` 里，启动日志会打印实际生效的别名表）。
  这是**代理层**白名单，不是网络层隔离——原因见 ARCHITECTURE.md §3。
- 经 mitmproxy 的流量，TLS 指纹（JA3/JA4）是 mitmproxy 的，不是浏览器的。
- 只在你拥有或明确授权测试的目标上使用。
