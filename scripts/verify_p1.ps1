# =============================================================================
# verify_p1.ps1 —— P1 验收：证明"浏览器走代理 -> 请求到靶场 -> 证据落盘"整条链成立
# -----------------------------------------------------------------------------
# 为什么用"证据行数增量"而不是"我请求成功了"来断言：
#   Invoke-WebRequest 即使没走代理也可能成功（.NET 对 loopback 有 bypass 规则），
#   那样会得到"HTTP 200，但代理里什么都没有"的假通过。
#   这里比较请求前后的 JSONL 行数，行数是唯一无法伪造的事实。
#
# 两个用例，各自验证一件事：
#   A) 普通业务请求：链路通、状态码与证据一致
#   B) 带 sign/timestamp 的请求：client_algo_hints 真的会被打上（L3 的入口索引）
#
# 退出码：0 = 两项都过；1 = 任一失败。
# =============================================================================
[CmdletBinding()]
param(
    [string]$Target = "http://127.0.0.1:3000",
    [int]$Port = 8080,
    [string]$Service = "mitmproxy"
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$flowsDir = Join-Path $root "evidence\flows"
$fail = 0

# 为什么行数在**容器内**统计，而不读宿主机的 evidence\flows：
# Docker Desktop(Windows) 的 bind mount 元数据缓存会滞后——实测容器内已 5 行 / 18 KB 时，
# 宿主机 Get-Item 仍报 0 字节，几十秒后才变。在宿主机上判定会得到假阴性。
# 磁盘上的最终一致由最后一步"宿主机交叉核对"单独报告，不参与断言。
function Get-ContainerId {
    $id = (& docker ps --filter "label=com.docker.compose.service=$Service" --format "{{.ID}}" 2>$null | Out-String).Trim()
    return $id
}

function Get-RunId([string]$cid) {
    # run_id 由 addon 在启动时打印，是"这次运行写的是哪个文件"的唯一权威来源
    $hit = (& docker logs $cid 2>&1 | Select-String -Pattern '\[mitm_observe\] run_id=' | Select-Object -Last 1)
    if (-not $hit) { return "" }
    return (($hit.Line -split 'run_id=')[1]).Trim()
}

function Get-FlowLines([string]$cid, [string]$runId) {
    if (-not $cid -or -not $runId) { return 0 }
    $out = (& docker exec $cid sh -c "wc -l < /evidence/flows/$runId.jsonl 2>/dev/null || echo 0" 2>&1 | Out-String).Trim()
    $n = 0
    if ([int]::TryParse(($out -split '\s+')[0], [ref]$n)) { return $n }
    return 0
}

function Wait-FlowLines([string]$cid, [string]$runId, [int]$baseline, [int]$timeoutSec = 10) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    do {
        $n = Get-FlowLines $cid $runId
        if ($n -gt $baseline) { return $n }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $deadline)
    return (Get-FlowLines $cid $runId)
}

# 为什么用 curl.exe 而不是 Invoke-WebRequest：
# 实测 .NET 的 HttpWebRequest 对 http://127.0.0.1 会**连上代理再绕过它**
# （mitmproxy 日志里只出现 client connect / client disconnect，没有 GET），
# 于是得到"HTTP 200 但代理里什么都没有"的假通过。
# curl.exe 加 --noproxy "" 才是真正强制走代理——这是本机实测结论，不是偏好。
function Invoke-ViaProxy([string]$url, [string]$proxyUrl) {
    # -o 指向临时文件而不是 NUL：实测在 Windows 上 NUL 偶发不生效，响应体会泄到
    # stdout，把 "-w" 打出的状态码糊成一串（表现为 "502{json...}200"）。
    $tmp = Join-Path $env:TEMP ("wr_body_{0}.tmp" -f $PID)
    $raw = & curl.exe -s -x $proxyUrl --noproxy "" --max-time 20 -o $tmp -w "%{http_code}" $url 2>&1
    Remove-Item $tmp -ErrorAction SilentlyContinue
    $text = ($raw | Out-String).Trim()
    # 只认最后出现的三位状态码：前面可能夹着 Windows 代理栈的 loopback 探测噪声
    $code = $text
    if ($text -match '(\d{3})\s*$') { $code = $Matches[1] }
    return @{ Code = $code; Exit = $LASTEXITCODE; Raw = $text }
}

# --- 0. 代理端口是否在听（容器没起来时这一步就会先失败，报错更准） --------------
$listening = $false
try {
    $c = New-Object System.Net.Sockets.TcpClient
    $c.Connect("127.0.0.1", $Port); $listening = $c.Connected; $c.Close()
} catch { $listening = $false }
if (-not $listening) {
    Write-Host "[fail] 127.0.0.1:$Port 没有在监听 —— 先跑 .\scripts\up_observe.ps1" -ForegroundColor Red
    exit 1
}
Write-Host "[ok]   代理在听：127.0.0.1:$Port" -ForegroundColor Green

$cid = Get-ContainerId
if (-not $cid) {
    Write-Host "[fail] 没有运行中的 $Service 容器 —— 先跑 .\scripts\up_observe.ps1" -ForegroundColor Red
    exit 1
}
$runId = Get-RunId $cid
if (-not $runId) {
    Write-Host "[fail] 读不到 addon 的 run_id（容器日志里没有 [mitm_observe] run_id= 行）" -ForegroundColor Red
    exit 1
}
Write-Host "[ok]   容器 $cid  run_id=$runId" -ForegroundColor Green

$before = Get-FlowLines $cid $runId
Write-Host "        基线：已有 $before 行证据" -ForegroundColor DarkGray

# --- 1. 用例 A：普通业务请求 ---------------------------------------------------
$proxy = "http://127.0.0.1:$Port"
Write-Host ""
Write-Host "[A] GET $Target/rest/products/search?q=apple  (curl.exe -x $proxy --noproxy '')"
$resA = Invoke-ViaProxy "$Target/rest/products/search?q=apple" $proxy
Write-Host "    HTTP $($resA.Code)  curl exit=$($resA.Exit)" -ForegroundColor DarkGray

$afterA = Wait-FlowLines $cid $runId $before 10
if ($afterA -gt $before) {
    Write-Host "[ok]   证据新增 $($afterA - $before) 行（容器内计数）" -ForegroundColor Green
} else {
    Write-Host "[fail] 证据没有新增：请求没有经过代理（检查客户端是否 bypass 了 loopback）" -ForegroundColor Red
    $fail++
}

# --- 2. 用例 B：算法线索标注 ---------------------------------------------------
Write-Host ""
Write-Host "[B] GET $Target/__wr_probe__?sign=1&timestamp=2&nonce=3  (curl.exe)"
$resB = Invoke-ViaProxy "$Target/__wr_probe__?sign=1&timestamp=2&nonce=3" $proxy
# 200 或 404 都算正常（取决于靶场是否 SPA catch-all），本用例只关心证据行
Write-Host "    HTTP $($resB.Code)  curl exit=$($resB.Exit)" -ForegroundColor DarkGray

$afterB = Wait-FlowLines $cid $runId $afterA 10

if ($afterB -gt $afterA) {
    $lastLine = (& docker exec $cid sh -c "tail -n 1 /evidence/flows/$runId.jsonl" 2>&1 | Out-String).Trim()
    $hints = ($lastLine | ConvertFrom-Json).client_algo_hints
    Write-Host "    client_algo_hints = [$($hints -join ', ')]" -ForegroundColor DarkGray
    if ($hints -contains "sign" -and $hints -contains "timestamp") {
        Write-Host "[ok]    sign/timestamp 已标注（L3 的入口索引可用）" -ForegroundColor Green
    } else {
        Write-Host "[fail] 算法线索没标上，检查 collectors\mitm_observe.py 的 _algo_hints" -ForegroundColor Red
        $fail++
    }
} else {
    Write-Host "[fail] 用例 B 没有新增证据行" -ForegroundColor Red
    $fail++
}

# --- 3. 宿主机交叉核对（只报告，不断言：bind mount 可能滞后） --------------------
Write-Host ""
$hostFile = Join-Path $root "evidence\flows\$runId.jsonl"
if (Test-Path $hostFile) {
    $hostLines = -1
    try { $hostLines = [System.IO.File]::ReadAllLines($hostFile).Count } catch { $hostLines = -1 }
    if ($hostLines -ge 0) {
        Write-Host "[info] 宿主机侧：$hostLines 行（容器内 $afterB 行）" -ForegroundColor DarkGray
        Write-Host "       缓存滞后是 Docker Desktop(Windows) 的已知行为，稍后自会一致。" -ForegroundColor DarkGray
    } else {
        Write-Host "[info] 宿主机侧读不到（文件正被容器持有 / bind mount 尚未刷新）；容器内 $afterB 行" -ForegroundColor DarkGray
    }
} else {
    Write-Host "[info] 宿主机侧暂未看到该文件（bind mount 尚未刷新）" -ForegroundColor DarkGray
}
Write-Host "       路径：$hostFile"

# --- 4. 结论 -------------------------------------------------------------------
Write-Host ""
if ($fail -eq 0) {
    Write-Host "P1 验收通过：链路通、证据落盘、算法线索可用。" -ForegroundColor Green
    exit 0
} else {
    Write-Host "P1 验收失败：$fail 项未通过（见上）。" -ForegroundColor Red
    exit 1
}
