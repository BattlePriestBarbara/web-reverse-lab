# =============================================================================
# replay_baseline.ps1 —— 对照组回放：把 baseline 里的路由逐条经代理打一遍
# -----------------------------------------------------------------------------
# 它不是"扫描"，是**校准**：用已知答案把"捕获 → 契约 → 回链"这条管线走通一次。
# 因此这里刻意只做一件事——发请求、记下真实状态码，不做任何判定；判定在
# scripts\verify_p2_baseline.py 里，且只对原文断言过的状态码下结论。
#
# 三个必须照抄的细节（P1 用血换来的）：
#   1. 用 curl.exe 而不是 Invoke-WebRequest：后者对 127.0.0.1 目标会绕过 -Proxy
#      直连，代理上看不到任何东西，而你会以为"抓到了"；
#   2. 必须带 --noproxy ""：Windows 的代理绕过表里含 loopback，不清空就白设 -x；
#   3. 响应体写临时文件（-o），不要写 NUL：某些组合下 curl 会把 -w 的输出和
#      错误信息混在一起，正文里出现 '502{json}200' 这种粘连串，最后一个三位数
#      才是真正的状态码。这里干脆只从 -w 取，并用正则取最后一个。
#
# 用法：
#   .\scripts\replay_baseline.ps1
#   .\scripts\replay_baseline.ps1 -ProxyPort 8080 -BaseUrl http://127.0.0.1:3000
# 退出码：0 = 全部路由都拿到了状态码；1 = 有路由连不上（说明观测网或靶场有问题）。
# =============================================================================
[CmdletBinding()]
param(
    [string]$Baseline = "",
    [int]$ProxyPort   = 8080,
    [string]$BaseUrl  = "",
    [string]$OutJson  = ""
)

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
if (-not $Baseline) { $Baseline = Join-Path $root "baseline\baseline_15_routes.json" }
if (-not $OutJson)  { $OutJson  = Join-Path $root ("artifacts\replay\replay_" + (Get-Date -Format "yyyyMMddTHHmmss") + ".json") }

if (-not (Test-Path $Baseline)) {
    Write-Host "[fail] 找不到基线：$Baseline" -ForegroundColor Red
    Write-Host "       先跑：python scripts\extract_baseline.py" -ForegroundColor Yellow
    exit 1
}

$doc = Get-Content $Baseline -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $BaseUrl) { $BaseUrl = $doc.target.base_url }
$BaseUrl = $BaseUrl.TrimEnd("/")

$curl = "curl.exe"
if (-not (Get-Command $curl -ErrorAction SilentlyContinue)) {
    Write-Host "[fail] 找不到 curl.exe（Win10 1803+ 自带）" -ForegroundColor Red
    exit 1
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wr_replay_" + [guid]::NewGuid().ToString("N") + ".body")
$results = @()
$n = 0

foreach ($route in $doc.routes) {
    $n++
    $path = $route.path_sample
    if ($route.query) { $path = "$path`?$($route.query)" }
    $url = "$BaseUrl$path"

    # --noproxy "" 与 -x 必须同时出现；顺序无关，但缺一个都会静默地抓到空气。
    # --noproxy= 必须写成带等号的单 token：PowerShell 5.1 会把原生命令的**空字符串
    # 参数静默丢弃**，于是 `--noproxy ""` 变成 `--noproxy` 后面紧跟 `-A`，curl 把
    # `-A` 当作 no_proxy 的值，UA 字符串成了第二个 URL（主机解析失败、路径 /0.1），
    # 每轮凭空多出一条假流量。实测踩过：15 次回放产生 15 条 DNS 失败记录。
    # --user-agent= 同理用等号形式，避免任何参数被拆开。
    $ua = "web-reverse-lab-baseline-replay/0.1"
    $raw = & $curl -s -o $tmp -w "%{http_code}" --max-time 25 -x "http://127.0.0.1:$ProxyPort" --noproxy= "--user-agent=$ua" $url 2>&1
    $exit = $LASTEXITCODE
    $code = ""
    foreach ($m in [regex]::Matches([string]$raw, "\d{3}")) { $code = $m.Value }
    $size = if (Test-Path $tmp) { (Get-Item $tmp).Length } else { 0 }

    $results += [pscustomobject]@{
        seq    = $n
        label  = $route.label
        method = $route.method
        url    = $url
        status = $code
        bytes  = $size
        curl_exit = $exit
        expect = $route.expected_status
    }

    $mark = if ($code) { "OK " } else { "ERR" }
    $color = if ($code) { "DarkGray" } else { "Red" }
    $shown = if ($code) { $code } else { "----" }
    Write-Host ("[{0}] {1,2}/{2} {3,-22} {4} -> {5} ({6} B)" -f `
        $mark, $n, $doc.routes.Count, $route.label, $path, $shown, $size) -ForegroundColor $color
}

Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue

$dir = Split-Path -Parent $OutJson
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

$payload = [pscustomobject]@{
    generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    proxy        = "http://127.0.0.1:$ProxyPort"
    base_url     = $BaseUrl
    baseline     = $Baseline
    total        = $results.Count
    with_status  = @($results | Where-Object { $_.status }).Count
    results      = $results
}
$payload | ConvertTo-Json -Depth 6 | Set-Content -Path $OutJson -Encoding UTF8

Write-Host ""
Write-Host ("回放完成：{0}/{1} 条拿到状态码 -> {2}" -f $payload.with_status, $payload.total, $OutJson) -ForegroundColor Cyan
if ($payload.with_status -ne $payload.total) {
    Write-Host "[warn] 有路由没拿到状态码：检查观测网是否在跑（docker compose --profile observe ps）" -ForegroundColor Yellow
    Write-Host "       以及靶场是否还是你预期的那个（curl.exe -x http://127.0.0.1:$ProxyPort --noproxy `"`" $BaseUrl/）" -ForegroundColor Yellow
    exit 1
}
exit 0
