# =============================================================================
# up_observe.ps1 —— 起观测网（P1）
# -----------------------------------------------------------------------------
# 做的事只有三件：前置体检 -> 起 mitmproxy -> 打印浏览器该怎么配。
# 刻意不自动修改系统代理：系统代理是全局状态，改坏了会影响你其它所有联网行为，
# 而"在浏览器里填一个代理地址"是可逆的、也更符合"我自己知道我在抓什么"。
# =============================================================================
[CmdletBinding()]
param(
    [switch]$Recreate
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dockerBin = "D:\Docker\DockerDesktop\resources\bin"
if (Test-Path (Join-Path $dockerBin "docker.exe")) { $env:PATH = "$dockerBin;$env:PATH" }

Set-Location $root

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[init] 已由 .env.example 生成 .env" -ForegroundColor Cyan
}

# --- 前置：引擎可达 -----------------------------------------------------------
$ver = & docker version --format "{{.Server.Version}}" 2>$null
if (-not $ver) {
    Write-Host "[fail] 引擎不可达。先跑 .\scripts\fix_env.ps1 看提示。" -ForegroundColor Red
    Write-Host "       最常见原因：com.docker.service 没起（需管理员）：Start-Service com.docker.service" -ForegroundColor Yellow
    exit 1
}
Write-Host "[ok]   引擎 server=$ver" -ForegroundColor Green

# --- 前置：镜像就位（经镜像站） -----------------------------------------------
& docker image inspect "web-reverse-lab/mitmproxy:11.1.0" *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[init] 镜像不在本地，走镜像站拉取（可能要多试几次，IPv6 链路会抖）" -ForegroundColor Cyan
    & "$PSScriptRoot\pull_through.ps1" -Only mitmproxy
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[fail] 镜像拉取失败，见上面的重试日志。" -ForegroundColor Red
        exit 1
    }
}

# --- 起服务 -------------------------------------------------------------------
# 注意：变量名不能用 $args —— 那是 PowerShell 的自动变量（脚本参数数组），
# 赋值会静默失败并导致 splatting 展开成脚本自身的参数。
$composeArgs = @("compose", "--profile", "observe", "up", "-d")
if ($Recreate) { $composeArgs += "--force-recreate" }
& docker @composeArgs
if ($LASTEXITCODE -ne 0) { Write-Host "[fail] compose up 失败" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "=== 观测网已就绪 ===" -ForegroundColor Green
& docker compose --profile observe ps

Write-Host ""
Write-Host "宿主机浏览器代理配置（Chrome 建议用独立 profile，别污染日常浏览器）：" -ForegroundColor Cyan
Write-Host "  HTTP  proxy : 127.0.0.1:8080"
Write-Host "  HTTPS proxy : 127.0.0.1:8080"
Write-Host "  例外/bypass : <-loopback>   （不填这一项，浏览器会绕过代理直连 127.0.0.1，抓不到靶场）"
Write-Host ""
Write-Host "证书（首次必须装，否则 https 目标会报证书错误）：" -ForegroundColor Cyan
Write-Host "  mitmproxy-CA-cert.cer 在 .\artifacts\mitmproxy\ 下，双击导入『受信任的根证书颁发机构』"
Write-Host "  只抓明文 http 靶场（如 juice-shop:3000）时不需要装证书。"
Write-Host ""
Write-Host "验证一次并断言证据落盘：" -ForegroundColor Cyan
Write-Host "  .\scripts\verify_p1.ps1"
Write-Host ""
Write-Host "盯实时流量：" -ForegroundColor Cyan
Write-Host "  Get-Content .\evidence\flows\<run_id>.jsonl -Wait -Tail 5"
