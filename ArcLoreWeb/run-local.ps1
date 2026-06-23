<#
.SYNOPSIS
    Build and run ArcLoreWeb locally against an already-running Lore server,
    then open the browser. Defaults to AUTH mode (native in-app UCS login).

.DESCRIPTION
    Wraps the end-to-end local-test flow into one command:
      1. sanity-check the Lore HTTP endpoint is reachable (/health_check),
      2. regenerate templ components if the `templ` CLI is on PATH,
      3. `go run` the web app.

    By default the app runs WITH auth: open the URL, click Login, and complete
    the UCS sign-in in your browser — ArcLoreWeb exchanges a per-repo authz
    token automatically on each repo page. Pass -AuthDisabled for a Lore server
    running without a [server.auth] block (no login, no Bearer header).

    The Lore server address is auto-discovered from the repo's
    .lore/config.toml (remote_url) unless you pass -GrpcAddr / -HttpAddr.
    The HTTP blob endpoint is assumed on :41339 of the same host. If no
    .lore config is found, falls back to localhost:41337 / :41339.

.EXAMPLE
    .\run-local.ps1
    # auth mode against the discovered Lore server, serves on :41380

.EXAMPLE
    .\run-local.ps1 -AuthDisabled
    # for a local auth-disabled Lore server (no login)

.EXAMPLE
    .\run-local.ps1 -GrpcAddr lore.box:41337 -HttpAddr http://lore.box:41339 -Listen :9000
#>
[CmdletBinding()]
param(
    [string]$GrpcAddr      = "",
    [string]$HttpAddr      = "",
    [string]$Listen        = ":41380",
    [string]$SessionSecret = "devsecretdevsecretdevsecret00000",
    [string]$AuthUrl       = "",
    [string]$MgmtAddr      = "",      # arc-lore-auth HTTP/JSON mgmt API; default = http://{lore-host}:8080
    [switch]$AuthDisabled,
    [switch]$AuthDebug,
    [switch]$SkipHealthCheck,
    [switch]$SkipTemplGen
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# Auto-discover the Lore server from the repo's .lore/config.toml unless the
# caller passed -GrpcAddr / -HttpAddr explicitly. The web client speaks plain
# gRPC, so we strip the "lore://" (or "urc://") scheme. The .lore config only
# records the gRPC remote; the HTTP blob endpoint is assumed on :41339 on the
# same host (override with -HttpAddr if your server differs).
if ([string]::IsNullOrWhiteSpace($GrpcAddr) -or [string]::IsNullOrWhiteSpace($HttpAddr)) {
    $loreConfig = Join-Path $PSScriptRoot "..\..\.lore\config.toml"
    if (Test-Path $loreConfig) {
        $remoteLine = Select-String -Path $loreConfig -Pattern '^\s*remote_url\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($null -ne $remoteLine) {
            $remoteUrl = $remoteLine.Matches[0].Groups[1].Value          # e.g. lore://159.69.137.186:41337
            $hostPort  = $remoteUrl -replace '^[a-zA-Z]+://', ''          # strip scheme -> host:port
            $hostOnly  = ($hostPort -split ':')[0]
            if ([string]::IsNullOrWhiteSpace($GrpcAddr)) { $GrpcAddr = $hostPort }
            if ([string]::IsNullOrWhiteSpace($HttpAddr)) { $HttpAddr = "http://${hostOnly}:41339" }
            if ([string]::IsNullOrWhiteSpace($MgmtAddr)) { $MgmtAddr = "http://${hostOnly}:8080" }
            Write-Host "Discovered Lore server from $loreConfig : $remoteUrl" -ForegroundColor DarkGray
        }
    }
}

# Fall back to localhost if discovery found nothing and nothing was passed.
if ([string]::IsNullOrWhiteSpace($GrpcAddr)) { $GrpcAddr = "localhost:41337" }
if ([string]::IsNullOrWhiteSpace($HttpAddr)) { $HttpAddr = "http://localhost:41339" }
if ([string]::IsNullOrWhiteSpace($MgmtAddr)) { $MgmtAddr = "http://localhost:8080" }

$authMode = if ($AuthDisabled) { "auth-disabled (no login)" } else { "auth (native in-app login — username/password form)" }

Write-Host "ArcLoreWeb local runner" -ForegroundColor Cyan
Write-Host "  gRPC : $GrpcAddr"
Write-Host "  HTTP : $HttpAddr"
Write-Host "  mgmt : $MgmtAddr  (arc-lore-auth /api)"
Write-Host "  serve: http://localhost$Listen"
Write-Host "  mode : $authMode"
Write-Host ""

# 1. Reachability check against the Lore HTTP health endpoint (unauthenticated).
if (-not $SkipHealthCheck) {
    $healthUrl = "$($HttpAddr.TrimEnd('/'))/health_check"
    Write-Host "Checking Lore HTTP health: $healthUrl" -ForegroundColor DarkGray
    try {
        $resp = Invoke-WebRequest -Uri $healthUrl -Method Get -TimeoutSec 5 -UseBasicParsing
        Write-Host "  Lore HTTP OK (HTTP $($resp.StatusCode))" -ForegroundColor Green
    } catch {
        Write-Warning "Lore HTTP health check failed: $($_.Exception.Message)"
        Write-Warning "The web app will still start, but repo data will not load until the Lore server is reachable."
        Write-Warning "Re-run with -SkipHealthCheck to silence this, or fix -HttpAddr."
    }
    Write-Host ""
}

# 2. Regenerate templ components if the CLI is available (generated files are
#    committed, so this is only needed after editing .templ sources).
if (-not $SkipTemplGen) {
    $templ = Get-Command templ -ErrorAction SilentlyContinue
    if ($null -ne $templ) {
        Write-Host "templ generate..." -ForegroundColor DarkGray
        templ generate
        if ($LASTEXITCODE -ne 0) { throw "templ generate failed (exit $LASTEXITCODE)" }
    } else {
        Write-Host "templ CLI not found on PATH; using committed *_templ.go as-is." -ForegroundColor DarkGray
    }
    Write-Host ""
}

# 3. Run the web app. Default: auth mode (in-app UCS login + per-repo token
#    exchange). -AuthDisabled flips LORE_AUTH_DISABLED for auth-disabled servers.
if ($AuthDisabled) {
    $env:LORE_AUTH_DISABLED = "true"
} else {
    $env:LORE_AUTH_DISABLED = "false"
}
$env:LORE_GRPC_ADDR = $GrpcAddr
$env:LORE_HTTP_ADDR = $HttpAddr
$env:LISTEN_ADDR    = $Listen
$env:SESSION_SECRET = $SessionSecret
$env:MGMT_API_ADDR  = $MgmtAddr
if (-not [string]::IsNullOrWhiteSpace($AuthUrl)) {
    $env:LORE_AUTH_URL = $AuthUrl
}
if ($AuthDebug) {
    $env:LORE_AUTH_DEBUG = "1"
    Write-Host "  Auth-debug: token kid/iss/aud summaries will print to the console." -ForegroundColor DarkGray
}

Write-Host "Starting ArcLoreWeb (Ctrl+C to stop)..." -ForegroundColor Cyan
Write-Host "  Browse: http://localhost$Listen" -ForegroundColor Cyan
if ($AuthDisabled) {
    Write-Host "  Auth-disabled: no login needed; the repo list loads directly." -ForegroundColor Cyan
} else {
    Write-Host "  Open the URL and sign in with your username and password (native login — no browser redirect)." -ForegroundColor Cyan
    Write-Host "  First run? Visit /setup to create the first admin account." -ForegroundColor Cyan
}
$logFile = Join-Path $PSScriptRoot "tmp\arcloreweb.log"
New-Item -ItemType Directory -Force -Path (Split-Path $logFile) | Out-Null
Write-Host "  Logging to: $logFile" -ForegroundColor DarkGray
Write-Host ""

# Tee stdout+stderr to a log file (tmp/ is gitignored) so the run output —
# including LORE_AUTH_DEBUG token summaries — can be inspected after the fact.
go run ./cmd/arcloreweb 2>&1 | Tee-Object -FilePath $logFile
