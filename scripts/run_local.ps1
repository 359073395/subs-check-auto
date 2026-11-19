$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  subs-check-pro 本地真实网络检测 & 同步云端订阅" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. 确保二进制程序存在
$ExePath = Join-Path $RepoRoot "bin\subs-check-pro.exe"
if (-not (Test-Path $ExePath)) {
    Write-Host "[1/4] 正在下载 Windows 版 subs-check-pro.exe ..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "bin") | Out-Null
    $ZipPath = Join-Path $RepoRoot "bin\subs-check-pro_Windows_x86_64.zip"
    $ReleaseUrl = "https://github.com/sinspired/subs-check-pro/releases/latest/download/subs-check-pro_Windows_x86_64.zip"
    curl.exe -fsSL -L "https://gh-proxy.com/$ReleaseUrl" -o $ZipPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ZipPath) -or (Get-Item $ZipPath).Length -lt 1000000) {
        curl.exe -fsSL -L $ReleaseUrl -o $ZipPath
    }
    Expand-Archive -Path $ZipPath -DestinationPath (Join-Path $RepoRoot "bin") -Force
    Remove-Item $ZipPath -Force
}

# 2. 确保 pyyaml 可用
python -c "import yaml" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[准备] 正在安装 pyyaml ..." -ForegroundColor Yellow
    python -m pip install --quiet pyyaml
}

# 3. 清理旧信号并启动本地检测
$FlagPath = Join-Path $env:TEMP "subs_check_done.flag"
if (Test-Path $FlagPath) { Remove-Item $FlagPath -Force }

Write-Host "[2/4] 正在从本机网络采集并实测公益节点（通常需 1~3 分钟，请勿关闭窗口）..." -ForegroundColor Green
$Proc = Start-Process -FilePath $ExePath -ArgumentList "-f", "config\config.local.yaml" -WorkingDirectory $RepoRoot -PassThru

$MaxWaitSec = 900
$Elapsed = 0
while ($true) {
    if (Test-Path $FlagPath) {
        Write-Host "`n检测与订阅保存完成，正在优雅退出检测程序..." -ForegroundColor Green
        Start-Sleep -Seconds 2
        if (-not $Proc.HasExited) {
            Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
        }
        break
    }
    if ($Proc.HasExited) {
        Write-Host "`nsubs-check-pro 已退出 (ExitCode=$($Proc.ExitCode))。" -ForegroundColor Yellow
        break
    }
    if ($Elapsed -ge $MaxWaitSec) {
        Write-Host "`n达到最大等待时间 (${MaxWaitSec}s)，正在结束检测进程..." -ForegroundColor Yellow
        Stop-Process -Id $Proc.Id -Force -ErrorAction SilentlyContinue
        break
    }
    Start-Sleep -Seconds 2
    $Elapsed += 2
}

# 4. 精选 Top 20 并简化节点名称
Write-Host "[3/4] 正在按 IP 纯净度与本机测速精选 Top 20 并简化命名..." -ForegroundColor Green
python scripts\select_top20.py --local --top 20
if ($LASTEXITCODE -ne 0) {
    throw "select_top20.py 执行失败"
}

# 5. 推送最新 subs/ 到 GitHub（自动检测本机系统代理是否可用）
Write-Host "[4/4] 正在同步最新 20 个可用节点到 GitHub 与你的域名订阅..." -ForegroundColor Green

$ProxyArgs = @()
try {
    $reg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($reg.ProxyEnable -eq 1 -and $reg.ProxyServer) {
        $parts = $reg.ProxyServer -split ":"
        $pHost = $parts[0]
        $pPort = [int]$parts[1]
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($pHost, $pPort, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne(800, $false) -and $tcp.Connected) {
            $ProxyArgs = @("-c", "http.proxy=http://$($reg.ProxyServer)", "-c", "https.proxy=http://$($reg.ProxyServer)")
        }
        $tcp.Close()
    }
} catch {}

$ErrorActionPreference = "Continue"
git add subs/
git diff --cached --quiet
if ($LASTEXITCODE -ne 0) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm"
    git commit -m "chore: 本地真实网络实测更新可用订阅 [$ts]"
    & git @ProxyArgs pull --rebase origin main
    & git @ProxyArgs push origin main
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n全部完成！你的域名订阅与 GitHub 订阅均已更新为最新本机实测可用节点。" -ForegroundColor Cyan
    } else {
        Write-Host "`n警告：本地 subs/ 文件已生成，但推送到 GitHub 失败，请确认网络/代理后重试。" -ForegroundColor Red
    }
} else {
    Write-Host "`n订阅内容无变化。" -ForegroundColor Yellow
}
