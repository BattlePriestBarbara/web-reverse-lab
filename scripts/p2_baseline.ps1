# =============================================================================
# p2_baseline.ps1 —— P2 对照组验证：一轮跑完"爬虫 → 回放 → HAR → 契约 → 校验"
# -----------------------------------------------------------------------------
# 顺序是刻意的，且每一步都为下一步留下可复核的产物：
#
#   1. 起观测网（mitmproxy），RUN_ID 由本脚本钉死 —— 一轮一个 id，证据、HAR、
#      契约、报告四处文件名必须一致，否则"同一轮"只是一句口头承诺；
#   2. **先爬虫后回放**，并在两者之间留 2 秒静默期。阶段归属靠这条时间窗判定，
#      不靠猜 User-Agent：爬虫的 UA 可以随便改，时间线改不了；
#   3. 回放 15 条已知路由（对照组）；
#   4. 停 mitmdump —— HAR 是在 save addon 的 done() 里写的，不停进程就没有 HAR；
#   5. 用 docker cp 把 HAR/JSONL **从容器里捞出来**，而不是读 bind mount：
#      Docker Desktop 的挂载有秒级延迟，P1 已经实测过"容器刚写完、宿主读到空"；
#   6. HAR → contract.json → 对照基线量化评估。
#
# 用法：
#   .\scripts\p2_baseline.ps1                    # 完整一轮
#   .\scripts\p2_baseline.ps1 -SkipCrawl         # 只验回放（调契约转换时用）
#   .\scripts\p2_baseline.ps1 -KeepUp            # 跑完不关观测网（自己接着抓浏览器流量）
# 退出码：0 = P2 通过；1 = 不通过或链路故障。任何一步失败都会立刻停并说清原因。
# =============================================================================
[CmdletBinding()]
param(
    [string]$RunId   = "",
    [string]$Baseline = "",
    [string]$BaseUrl  = "http://127.0.0.1:3000",
    [switch]$SkipCrawl,
    [switch]$SkipReplay,
    [switch]$KeepUp,
    [int]$CrawlTimeoutSec = 180
)

$ErrorActionPreference = "Continue"   # 主体是外部命令 + $LASTEXITCODE，Stop 会把正常分支当异常
$root = Split-Path -Parent $PSScriptRoot
$dockerBin = "D:\Docker\DockerDesktop\resources\bin"
if (Test-Path (Join-Path $dockerBin "docker.exe")) { $env:PATH = "$dockerBin;$env:PATH" }
# Python 在 Windows 上默认按 ANSI 代码页编码 stdout，中文会乱码、罕见符号会直接抛
# UnicodeEncodeError。脚本内部也各自 reconfigure 了一遍，这里是双保险。
$env:PYTHONIOENCODING = "utf-8"
Set-Location $root

if (-not $RunId)   { $RunId = "p2_" + (Get-Date -Format "yyyyMMddTHHmmss") }
if (-not $Baseline) { $Baseline = Join-Path $root "baseline\baseline_15_routes.json" }

function Fail([string]$msg) {
    Write-Host "[fail] $msg" -ForegroundColor Red
    exit 1
}

# --- 0. 前置 ----------------------------------------------------------------
$ver = & docker version --format "{{.Server.Version}}" 2>$null
if (-not $ver) { Fail "引擎不可达（先跑 .\scripts\fix_env.ps1；多半是 com.docker.service 没起）" }
Write-Host "[ok] 引擎 server=$ver" -ForegroundColor Green

foreach ($img in @("web-reverse-lab/mitmproxy:11.1.0", "web-reverse-lab/katana:latest")) {
    & docker image inspect $img *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[init] 缺镜像 $img，走镜像站拉取" -ForegroundColor Cyan
        $only = if ($img -like "*katana*") { "katana" } else { "mitmproxy" }
        & "$PSScriptRoot\pull_through.ps1" -Only $only
        if ($LASTEXITCODE -ne 0) { Fail "镜像拉取失败：$img" }
    }
}

# Ground Truth 必须现抽现用：它带源文件指纹，源文件一改就该重抽。
& python "$root\scripts\extract_baseline.py" --out $Baseline
if ($LASTEXITCODE -ne 0) { Fail "Ground Truth 抽取失败" }

# --- 1. 起观测网 -------------------------------------------------------------
# 进程环境变量优先于 .env，所以这里赋值就能覆盖 .env 里的 RUN_ID=。
$env:RUN_ID = $RunId
Write-Host "[run] RUN_ID=$RunId" -ForegroundColor Cyan
# 2>&1 + ForEach-Object：docker compose 把进度写在 stderr 上，PS 5.1 会把它包成
# NativeCommandError 记录，于是报错块在控制台上跟正文顺序错乱（看着像失败了，
# 其实命令成功了）。转成普通字符串输出，顺序就正常，也不会再触发 $ErrorActionPreference。
& docker compose --profile observe up -d --force-recreate 2>&1 |
    ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
if ($LASTEXITCODE -ne 0) { Fail "compose up 失败" }

# 等 addon 把 hardump 指向本轮 HAR —— 这一行日志同时证明两件事：
# addon 起来了、HAR 导出已就位。等不到就别往下跑，否则最后拿不到 HAR。
$ready = $false
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    $logs = (& docker compose --profile observe logs --no-color --tail 60 mitmproxy 2>&1 | Out-String)
    if ($logs -match "hardump=") { $ready = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $ready) {
    & docker compose --profile observe logs --no-color --tail 40 mitmproxy
    Fail "60 秒内没等到 hardump 就绪日志（见上面容器日志）"
}
Write-Host "[ok] 观测网就绪，HAR 已指向 /evidence/har/$RunId.har" -ForegroundColor Green

$cid = ""
for ($i = 0; $i -lt 20; $i++) {
    $cid = (& docker compose --profile observe ps -q mitmproxy 2>$null | Select-Object -First 1)
    if ($cid) { break }
    Start-Sleep -Milliseconds 500
}
if (-not $cid) {
    & docker compose --profile observe logs --no-color --tail 20 mitmproxy
    Fail "拿不到 mitmproxy 容器 id（容器可能已退出——见上面日志；Exited(137) 通常是并发实例把它停掉了）"
}
$cid = $cid.Trim()

# --- 2. 爬虫阶段 -------------------------------------------------------------
$crawlStart = [double]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000)
$crawlOut = Join-Path $root "artifacts\crawl\katana_$RunId.txt"
if (-not $SkipCrawl) {
    Write-Host "[crawl] katana 经 mitmproxy 抓取 $BaseUrl（深度3 + JS解析 + jsluice + known-files）" -ForegroundColor Cyan
    $crawlDir = Split-Path -Parent $crawlOut
    if (-not (Test-Path $crawlDir)) { New-Item -ItemType Directory -Path $crawlDir -Force | Out-Null }

    # 为什么用 `run -d` 而不是前台 `run`：
    # compose 前台 run 会把**自己那条永不关闭的 stdin 管道**交给容器；katana 支持
    # `cat urls.txt | katana`，见到非 TTY 的 stdin 就去读 URL，于是永久阻塞在 read(0)。
    # 实测：/proc/1/wchan=anon_pipe_read、fd0=pipe、CPU 0.03%、5 分钟零输出、
    # 代理侧只有 1 条流量 —— 症状看着像"站点没链接"，其实是爬虫在等输入。
    # 同一组参数用 `docker run`（stdin=/dev/null）秒过，这是判断依据。
    # 用 -d 启动后容器 stdin 不再是活管道，katana 立刻拿到 EOF 正常跑完；
    # 顺带还能给爬虫阶段加上真正的墙钟上限（前台 run 只能靠外部 kill）。
    $crawlName = "wr-crawler-$RunId"
    & docker rm -f $crawlName *> $null
    & docker compose --profile observe --profile crawl run -d --name $crawlName crawler 2>&1 |
        ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    if ($LASTEXITCODE -ne 0) { Fail "爬虫容器启动失败" }

    $deadline = (Get-Date).AddSeconds($CrawlTimeoutSec)
    while ($true) {
        $state = (& docker inspect -f "{{.State.Status}}" $crawlName 2>$null)
        if (-not $state -or $state.Trim() -ne "running") { break }
        if ((Get-Date) -gt $deadline) {
            Write-Host "[warn] 爬虫超过 $CrawlTimeoutSec 秒未结束，强制停止（按已抓到的算）" -ForegroundColor Yellow
            break
        }
        Start-Sleep -Milliseconds 500
    }

    $rawLog = @(& docker logs $crawlName 2>&1)
    # 只保留 URL 行：-f url 的产物就是一行一个 URL，别的都是容器噪音。
    $lines = @($rawLog | Where-Object { $_ -match '^https?://' })
    & docker rm -f $crawlName *> $null
    # 不带 BOM 写：BOM 会让下游按行解析的第一行带着 U+FEFF，且这种错只在"读的人"那边炸。
    [System.IO.File]::WriteAllLines($crawlOut, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
    Start-Sleep -Seconds 2      # 静默期：让在途请求落完，窗口边界才干净
    $crawlEnd = [double]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000)
    Write-Host ("[ok] 爬虫完成：{0} 条 URL -> {1}（窗口 {2:N1}s，丢弃非 URL 行 {3}）" -f `
        $lines.Count, $crawlOut, ($crawlEnd - $crawlStart), ($rawLog.Count - $lines.Count)) -ForegroundColor Green
    if ($lines.Count -eq 0) {
        Write-Host "[warn] 爬虫 0 行发现。常见原因不是'站点没链接'，而是容器环境问题：" -ForegroundColor Yellow
        Write-Host "       1) read_only 且无 working_dir → katana 的 JS 抽取无可写 CWD，就地卡死" -ForegroundColor Yellow
        Write-Host "       2) 前台 compose run → 阻塞在 read(stdin)" -ForegroundColor Yellow
        Write-Host "       手工复核：docker compose --profile observe --profile crawl run -d --name dbg crawler;" -ForegroundColor Yellow
        Write-Host "                 docker logs dbg" -ForegroundColor Yellow
    }
} else {
    $crawlEnd = $crawlStart + 0.001
    New-Item -ItemType Directory -Path (Split-Path -Parent $crawlOut) -Force | Out-Null
    [System.IO.File]::WriteAllLines($crawlOut, [string[]]@(), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[skip] 跳过爬虫阶段（所有端点都会归到 replay）" -ForegroundColor Yellow
}


# --- 3. 回放阶段（对照组） ----------------------------------------------------
if (-not $SkipReplay) {
    Write-Host "[replay] 逐条回放基线路由（经 127.0.0.1:8080）" -ForegroundColor Cyan
    $replayOut = Join-Path $root "artifacts\replay\replay_$RunId.json"
    & "$PSScriptRoot\replay_baseline.ps1" -Baseline $Baseline -ProxyPort 8080 `
        -BaseUrl $BaseUrl -OutJson $replayOut
    if ($LASTEXITCODE -ne 0) { Fail "回放失败：有路由连不上代理或目标" }
} else {
    Write-Host "[skip] 跳过回放阶段" -ForegroundColor Yellow
}

Start-Sleep -Seconds 1

if ($KeepUp) {
    Write-Host "[keep] -KeepUp：观测网保持运行。HAR 只在 mitmdump 退出时写，故本轮不产出契约。" -ForegroundColor Yellow
    Write-Host "       收尾：docker compose --profile observe stop mitmproxy，再手工跑转换与校验。" -ForegroundColor Yellow
    exit 0
}

# --- 4. 停观测网（HAR 只在正常退出时落盘） ------------------------------------
Write-Host "[stop] 停止 mitmdump，触发 save addon 写 HAR" -ForegroundColor Cyan
# -t 30：HAR 是在退出钩子里整体序列化写盘的，默认 10 秒宽限在慢盘上可能不够，
# 不够就会变成 SIGKILL(137)——HAR 全丢，而报错只说"缺 HAR"，看不出是超时被杀。
& docker compose --profile observe stop -t 30 mitmproxy 2>&1 |
    ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
Start-Sleep -Seconds 1

# --- 5. 从容器里把产物捞出来（不信 bind mount 的即时性） ----------------------
$harDir = Join-Path $root "evidence\har"
$flowDir = Join-Path $root "evidence\flows"
New-Item -ItemType Directory -Path $harDir -Force | Out-Null
New-Item -ItemType Directory -Path $flowDir -Force | Out-Null
$harHost = Join-Path $harDir "$RunId.har"
$flowHost = Join-Path $flowDir "$RunId.jsonl"

& docker cp "${cid}:/evidence/flows/$RunId.jsonl" $flowDir 2>&1 | Out-Null
if (-not (Test-Path $flowHost)) { Fail "证据 JSONL 没捞出来（容器 $cid）" }

& docker cp "${cid}:/evidence/har/$RunId.har" $harDir 2>&1 | Out-Null
if (-not (Test-Path $harHost)) {
    Write-Host "[hint] 容器 /evidence/har 下没有本轮 HAR：多半是 mitmdump 被 kill 而非 stop，" -ForegroundColor Yellow
    Write-Host "       或 save addon 的 hardump 未生效。重跑本脚本即可（默认走 stop）。" -ForegroundColor Yellow
    Fail "缺少 HAR，HAR->OpenAPI 这一段无法成立"
}
Write-Host ("[ok] 产物已捞到宿主：{0} ({1:N0} B) + {2}" -f `
    (Split-Path -Leaf $harHost), (Get-Item $harHost).Length, (Split-Path -Leaf $flowHost)) -ForegroundColor Green

# --- 6. HAR + JSONL -> contract.json -----------------------------------------
$contractDir = Join-Path $root "contracts"
New-Item -ItemType Directory -Path $contractDir -Force | Out-Null
$contract = Join-Path $contractDir "contract_$RunId.json"
$window = "{0:F3},{1:F3}" -f $crawlStart, $crawlEnd

Write-Host "[contract] HAR + flows -> contract.json（爬虫窗口 $window）" -ForegroundColor Cyan
& python "$root\collectors\har_to_contract.py" --har $harHost --flows $flowHost `
    --out $contract --run-id $RunId --base-url $BaseUrl --crawl-window $window
if ($LASTEXITCODE -ne 0) { Fail "契约生成失败" }

# --- 7. 对照基线做量化评估 ----------------------------------------------------
$report = Join-Path $root "reports\p2_baseline_report.md"
$jsonOut = Join-Path $root "reports\p2_baseline_$RunId.json"
Write-Host "[verify] contract 对 baseline 做差异分析" -ForegroundColor Cyan
& python "$root\scripts\verify_p2_baseline.py" --contract $contract --baseline $Baseline `
    --report $report --json-out $jsonOut
$verifyExit = $LASTEXITCODE

# --- 8. 运行清单（这一轮按什么规则跑的，事后可复核） --------------------------
$p2Dir = Join-Path $root "artifacts\p2"
New-Item -ItemType Directory -Path $p2Dir -Force | Out-Null
$manifest = [pscustomobject]@{
    run_id       = $RunId
    target       = $BaseUrl
    proxy        = "127.0.0.1:8080"
    container_id = $cid
    crawl        = [pscustomobject]@{
        skipped     = [bool]$SkipCrawl
        start_epoch = $crawlStart
        end_epoch   = $crawlEnd
        duration_s  = [math]::Round($crawlEnd - $crawlStart, 3)
        output      = $crawlOut
    }
    replay       = [pscustomobject]@{ skipped = [bool]$SkipReplay }
    artifacts    = [pscustomobject]@{
        har         = $harHost
        flows       = $flowHost
        contract    = $contract
        report      = $report
        verify_json = $jsonOut
    }
    verdict      = $(if ($verifyExit -eq 0) { "pass" } else { "fail" })
}
$manifestPath = Join-Path $p2Dir "manifest_$RunId.json"
[System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 6),
    (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "=== 本轮产物 ===" -ForegroundColor Cyan
Write-Host "  HAR       : $harHost"
Write-Host "  flows     : $flowHost"
Write-Host "  contract  : $contract"
Write-Host "  报告      : $report"
Write-Host "  清单      : $manifestPath"
Write-Host ""
if ($verifyExit -eq 0) {
    Write-Host "P2 对照组验证通过（退出码 0）" -ForegroundColor Green
    exit 0
}
Write-Host "P2 未通过（见上面的逐条差异表；报告已落盘）" -ForegroundColor Red
exit 1
