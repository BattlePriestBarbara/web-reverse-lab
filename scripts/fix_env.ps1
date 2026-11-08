# =============================================================================
# fix_env.ps1 —— 修 P0 的三个环境问题（本机实测出来的，不是通用建议）
# -----------------------------------------------------------------------------
# 三项分别对应：
#   1. docker.exe 不在 PATH      -> 所有 docker 命令报"无法将 docker 项识别为 ..."
#   2. docker-credential-desktop 不在 PATH -> docker pull 报
#      'error getting credentials - err: exec: "docker-credential-desktop":
#       executable file not found in %PATH%'
#   3. IPv6 到 Cloudflare 的链路不稳 -> 镜像站大 blob 报 wsarecv 被重置
#
# 1/2 只改**用户级** PATH（不需要管理员，不改系统 PATH，随时可回退）。
# 3 需要管理员，所以做成"只打印命令、不擅自执行"。
# =============================================================================
[CmdletBinding()]
param(
    [switch]$ApplyIpv4Priority
)

$ErrorActionPreference = "Continue"
$dockerBin = "D:\Docker\DockerDesktop\resources\bin"

Write-Host "=== 一次性体检 ===" -ForegroundColor Cyan

# --- 1/2: PATH ---------------------------------------------------------------
if (Test-Path (Join-Path $dockerBin "docker.exe")) {
    Write-Host "[ok]    docker.exe 存在：$dockerBin\docker.exe"
} else {
    Write-Host "[fail]  找不到 docker.exe，请确认 Docker Desktop 装在 D:\Docker\DockerDesktop" -ForegroundColor Red
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -split ";" -contains $dockerBin) {
    Write-Host "[ok]    用户 PATH 已包含 $dockerBin"
} else {
    Write-Host "[fix]   写入用户 PATH：$dockerBin"
    [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $dockerBin), "User")
    Write-Host "[ok]    已写入（新开的终端生效；当前终端请重开或用 `$env:PATH 临时追加）" -ForegroundColor Green
}

# --- 3: IPv4 优先级 -----------------------------------------------------------
$policy = netsh interface ipv6 show prefixpolicy 2>$null | Out-String
if ($policy -match "::ffff:0:0/96") {
    $line = ($policy -split "`n" | Where-Object { $_ -match "::ffff:0:0/96" } | Select-Object -First 1).Trim()
    Write-Host "[info]  当前 IPv4 映射前缀策略：$line"
    Write-Host "        若镜像拉取仍报 wsarecv/TLS handshake timeout，提高到 100 可让 IPv4 优先："
    Write-Host "        netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 100" -ForegroundColor DarkGray
}

if ($ApplyIpv4Priority) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        Write-Host "[fail]  -ApplyIpv4Priority 需要管理员权限，本终端不是管理员。" -ForegroundColor Red
    } else {
        netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 100 | Out-Null
        Write-Host "[ok]    已把 IPv4 映射前缀优先级设为 100（回退：netsh interface ipv6 reset prefixpolicy）" -ForegroundColor Green
    }
}

# --- 4: 引擎可达性（最常见的一个"看起来是别的问题"的问题） -------------------
Write-Host ""
Write-Host "=== 引擎可达性 ===" -ForegroundColor Cyan
$env:PATH = "$dockerBin;$env:PATH"
$ver = & docker version --format "{{.Server.Version}}" 2>$null
if ($ver) {
    Write-Host "[ok]    引擎可达：server=$ver" -ForegroundColor Green
} else {
    Write-Host "[fail]  引擎不可达。若报 " -ForegroundColor Red -NoNewline
    Write-Host "E_ACCESSDENIED ... 无法将磁盘 D:\Docker\wsl\main\ext4.vhdx 附加到 WSL2: 拒绝访问" -ForegroundColor Red
    Write-Host "        那是 com.docker.service（Docker Desktop Service）没在跑，而启动它需要管理员：" -ForegroundColor Yellow
    Write-Host "        以管理员身份运行 PowerShell，然后执行：" -ForegroundColor Yellow
    Write-Host "            Start-Service com.docker.service" -ForegroundColor Yellow
    Write-Host "        或者：右键 Docker Desktop -> 以管理员身份运行。" -ForegroundColor Yellow
}
