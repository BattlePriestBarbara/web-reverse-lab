# =============================================================================
# pull_through.ps1 —— 经镜像站拉取并 retag 成规范名
# -----------------------------------------------------------------------------
# 存在的唯一理由（实测，不是听说）：
#   * registry-1.docker.io 在本机被解析到 Facebook 段
#     （2a03:2880:f11a:83:face:b00c:0:25de:443），官方名 pull 必失败；
#   * 镜像站 docker.1ms.run 可用，但它的大 blob 走 Cloudflare IPv6，会偶发
#     "wsarecv: An existing connection was forcibly closed" / TLS handshake timeout。
# 所以：站点可换、必须重试、规范名不变。compose 里永远不出现站点域名。
#
# 用法：
#   .\scripts\pull_through.ps1                     # 按 images.lock 拉全部
#   .\scripts\pull_through.ps1 -Only mitmproxy     # 只拉名字含 mitmproxy 的
#   .\scripts\pull_through.ps1 -Force              # 已存在也重拉
#   .\scripts\pull_through.ps1 -Mirror docker.1ms.run -Retries 6
#
# 退出码：0 = 全部就绪；1 = 有镜像拉不下来（会逐条打印失败原因）。
# =============================================================================
[CmdletBinding()]
param(
    [string]$Mirror  = "docker.1ms.run",
    [int]$Retries    = 5,
    [string]$Only    = "",
    [switch]$Force
)

# 刻意用 Continue：本脚本的主体是"调用外部 docker 命令并按 $LASTEXITCODE 判定"。
# 若设成 Stop，`docker image inspect` 对不存在的镜像往 stderr 写一行错误，
# PowerShell 会把它当成 NativeCommandError 抛出，脚本在第 1 个镜像就崩，
# 而它其实是"镜像不在本地"这个正常分支。
$ErrorActionPreference = "Continue"

# docker.exe 不在系统 PATH 是这台机器的既成事实（见 scripts/fix_env.ps1），
# 这里自带兜底路径，避免"脚本要用 docker 但 docker 不在 PATH"这种循环。
$dockerBin = "D:\Docker\DockerDesktop\resources\bin"
if (Test-Path (Join-Path $dockerBin "docker.exe")) {
    $env:PATH = "$dockerBin;$env:PATH"
}
$docker = "docker"

$lockFile = Join-Path (Split-Path -Parent $PSScriptRoot) "images.lock"
if (-not (Test-Path $lockFile)) { Write-Error "找不到 images.lock：$lockFile"; exit 1 }

function Test-ImagePresent([string]$name) {
    # docker image inspect 成功 = 本地已有该 tag。
    # 2>&1 | Out-Null 把 stderr 一并吞掉：镜像不存在时 docker 会往 stderr 写
    # "Error response from daemon: No such image"，那不是异常，是"还没有"。
    & $docker image inspect $name 2>&1 | Out-Null
    return ($LASTEXITCODE -eq 0)
}

$ok = 0; $fail = 0
foreach ($line in Get-Content $lockFile -Encoding UTF8) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }

    $cols = $trimmed.Split("|")
    if ($cols.Count -lt 3) { Write-Warning "行格式不对，跳过：$trimmed"; continue }

    $canonical = $cols[0].Trim()   # 例：web-reverse-lab/mitmproxy:11.1.0
    $repo      = $cols[1].Trim()   # 例：mitmproxy/mitmproxy
    $tag       = $cols[2].Trim()   # 例：11.1.0
    $digest    = if ($cols.Count -ge 4) { $cols[3].Trim() } else { "" }

    if ($Only -and ($canonical -notlike "*$Only*")) { continue }

    if (-not $Force -and (Test-ImagePresent $canonical)) {
        Write-Host "[skip] $canonical 已在本地" -ForegroundColor DarkGray
        $ok++; continue
    }

    if (-not $repo) {
        Write-Warning "[skip] $canonical 第二列为空（表示不需要拉取）"
        continue
    }

    $ref = if ($digest) { "$Mirror/$repo@$digest" } else { "$Mirror/$repo`:$tag" }
    $done = $false
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        Write-Host "[pull] $ref (第 $attempt/$Retries 次)" -ForegroundColor Cyan
        $out = (& $docker pull $ref 2>&1 | Out-String).Trim()
        if ($out) { Write-Host $out -ForegroundColor DarkGray }

        if ($LASTEXITCODE -eq 0) {
            & $docker tag $ref $canonical 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[ ok ] $canonical  <-  $ref" -ForegroundColor Green
                $done = $true
            } else {
                Write-Host "[fail] retag 失败：$ref -> $canonical" -ForegroundColor Red
            }
            break
        }

        # 这三类错误重试 100 次也不会变：tag 不存在 / 仓库不存在 / 该仓库不公开。
        # 快速失败并提示改 images.lock，比刷 5 遍同样的报错有用。
        if ($out -match 'manifest unknown|not found|pull access denied|denied: requested access') {
            Write-Host "[fail] 该 tag 在镜像站上不存在或不可匿名拉取，重试无意义。" -ForegroundColor Red
            Write-Host "       请改 images.lock 第二/三列（可先试 $repo`:latest）。" -ForegroundColor Yellow
            break
        }

        # 大 blob 被 IPv6 链路重置时退避重试；1ms 站偶发整段超时，
        # 3s/6s/9s 的线性退避比固定间隔更有效（实测第二次常能过）。
        Start-Sleep -Seconds ([Math]::Min(3 * $attempt, 15))
    }

    if ($done) { $ok++ } else { $fail++; Write-Host "[fail] $ref 重试 $Retries 次仍未成功" -ForegroundColor Red }
}

Write-Host ""
Write-Host "就绪 $ok 个，失败 $fail 个" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Yellow" })
if ($fail -gt 0) {
    Write-Host "提示：若报 wsarecv / TLS handshake timeout，是 IPv6 到 Cloudflare 的链路问题，" -ForegroundColor Yellow
    Write-Host "     不是镜像不存在。可提高 IPv4 优先级（需管理员）：" -ForegroundColor Yellow
    Write-Host "     netsh interface ipv6 set prefixpolicy ::ffff:0:0/96 100" -ForegroundColor Yellow
    exit 1
}
exit 0
