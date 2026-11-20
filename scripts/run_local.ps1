param([switch]$NoPush)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

# Prefer a real interpreter; the Windows Store python alias is not an interpreter.
$PythonCandidates = @((Join-Path $RepoRoot ".venv\Scripts\python.exe"))
foreach ($commandName in @("python.exe", "python3.exe")) {
    $command = Get-Command $commandName -ErrorAction SilentlyContinue
    if ($command) { $PythonCandidates += $command.Source }
}
$nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
if ($nodeCommand) {
    $dependencyDir = Split-Path (Split-Path (Split-Path $nodeCommand.Source))
    $PythonCandidates += Join-Path $dependencyDir "python\python.exe"
}
$PythonExe = $null
foreach ($candidate in $PythonCandidates) {
    if (Test-Path -LiteralPath $candidate) {
        try {
            & $candidate -c "import sys; assert sys.version_info >= (3, 10)" 2>$null
            if ($LASTEXITCODE -eq 0) { $PythonExe = $candidate; break }
        } catch { continue }
    }
}
if (-not $PythonExe) { throw "Python 3.10+ is required. Install Python, then run this file again." }

# A fetch proxy is only used for downloads and Git, never for node verification.
$FetchProxy = $null
try {
    $reg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if ($reg.ProxyServer -match "^([^:;=]+):(\d+)$") {
        $proxyHost = $Matches[1]
        $proxyPort = [int]$Matches[2]
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $connection = $tcp.BeginConnect($proxyHost, $proxyPort, $null, $null)
            if ($connection.AsyncWaitHandle.WaitOne(800) -and $tcp.Connected) {
                $FetchProxy = "http://$($reg.ProxyServer)"
            }
        } finally { $tcp.Dispose() }
    }
} catch {}
$CurlArgs = @("-fsSL", "--connect-timeout", "15", "--max-time", "180")
if ($FetchProxy) { $CurlArgs += @("--proxy", $FetchProxy) }

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if ($PythonExe -ne $VenvPython) {
    & $PythonExe -m venv (Join-Path $RepoRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Could not create project Python environment" }
    $PythonExe = $VenvPython
}
$HasYaml = $false
try { & $PythonExe -c "import yaml" 2>$null; $HasYaml = $LASTEXITCODE -eq 0 } catch {}
if (-not $HasYaml) {
    $PipArgs = @("-m", "pip", "install", "PyYAML>=6,<7")
    if ($FetchProxy) { $PipArgs += @("--proxy", $FetchProxy) }
    & $PythonExe @PipArgs
    if ($LASTEXITCODE -ne 0) { throw "Could not install PyYAML" }
}
New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "bin") | Out-Null

$Collector = Join-Path $RepoRoot "bin\subs-check-pro.exe"
if (-not (Test-Path -LiteralPath $Collector)) {
    $archive = Join-Path $RepoRoot "bin\collector.zip"
    & curl.exe @CurlArgs "https://github.com/sinspired/subs-check-pro/releases/download/v3.6.1/subs-check-pro_Windows_x86_64.zip" -o $archive
    if ($LASTEXITCODE -ne 0) { throw "Collector download failed" }
    Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $RepoRoot "bin") -Force
    Remove-Item -LiteralPath $archive
}
$Core = Join-Path $RepoRoot "bin\sing-box.exe"
if (-not (Test-Path -LiteralPath $Core)) {
    $archive = Join-Path $RepoRoot "bin\sing-box.zip"
    & curl.exe @CurlArgs "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-windows-amd64.zip" -o $archive
    if ($LASTEXITCODE -ne 0) { throw "sing-box download failed" }
    Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $RepoRoot "bin") -Force
    Copy-Item -LiteralPath (Join-Path $RepoRoot "bin\sing-box-1.14.2-windows-amd64\sing-box.exe") -Destination $Core
    Remove-Item -LiteralPath $archive
}
if (-not (Test-Path -LiteralPath $Core) -or -not (Test-Path -LiteralPath $Collector)) {
    throw "Required executables are missing"
}

Write-Host "Collecting fresh nodes, then verifying exported links on this machine."
Write-Host "This may take up to 20 minutes. The collector log path will be printed."
$PreviousHttpProxy = $env:HTTP_PROXY
$PreviousHttpsProxy = $env:HTTPS_PROXY
try {
    if ($FetchProxy) { $env:HTTP_PROXY = $FetchProxy; $env:HTTPS_PROXY = $FetchProxy }
    $RunArgs = @("scripts\run_check.py", "--collector", $Collector, "--core", $Core)
    if (-not $NoPush) { $RunArgs += "--push" }
    & $PythonExe @RunArgs
    if ($LASTEXITCODE -ne 0) { throw "Update failed. Old subscriptions were not reported as newly verified; inspect output/runs." }
} finally {
    $env:HTTP_PROXY = $PreviousHttpProxy
    $env:HTTPS_PROXY = $PreviousHttpsProxy
}
