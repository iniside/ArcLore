<#
.SYNOPSIS
    Install (or remove) the arc-lore-auth self-signed TLS certificate into the
    Windows machine Trusted Root store, so the UE Lore plugin / lore CLI can
    verify the gRPC TLS connection to arc-lore-auth :8443.

.DESCRIPTION
    The editor verifies the :8443 gRPC certificate against the Windows trust
    store (LocalMachine\Root). There is NO skip-verify, so the self-signed cert
    arc-lore-auth generates must be trusted on every editor host.

    By default this script FETCHES the cert directly from the auth server's TLS
    handshake on <Server>:<Port> - the exact cert you need to trust is the one
    the server presents - so no SSH/scp, no file copy, and no credentials are
    needed (scp won't work anyway: the server's SFTP subsystem is disabled).
    It always grabs the CURRENT cert, so re-running after a cert rotation just
    works. This is trust-on-first-use over the LAN, the same trust model as the
    rest of the self-host setup.

    Use -CertPath to install from a local file instead. Idempotent: re-running
    is safe. Must run elevated (Administrator) - LocalMachine\Root is machine-wide.

.PARAMETER Server
    Hostname/IP of the auth server to fetch the cert from (its :8443 TLS handshake).
    MUST match the host in lore-server's auth_url. Required unless -CertPath is given.

.PARAMETER Port
    gRPC TLS port to fetch from. Default: 8443.

.PARAMETER CertPath
    Install from a local copy of arc-lore-auth-tls.crt instead of fetching.

.PARAMETER ExpectedThumbprint
    Optional SHA1 thumbprint to pin against (case-insensitive, spaces/colons ignored).
    When provided, the fetched or loaded cert's SHA1 thumbprint is compared against
    this value BEFORE installing it into the trust store; a mismatch aborts with
    exit code 1. When omitted (the default), trust-on-first-use (TOFU) applies and
    the cert is installed without thumbprint verification.

.PARAMETER Uninstall
    Remove the cert from LocalMachine\Root (by thumbprint if -CertPath given,
    else by subject CN containing 'arc-lore-auth').

.EXAMPLE
    .\install-windows.ps1 -Server <your-host>
    # fetch from the arc-lore-auth host and install (TOFU)

.EXAMPLE
    .\install-windows.ps1 -Server lore.lan
    # fetch from a named host (TOFU)

.EXAMPLE
    .\install-windows.ps1 -Server lore.lan -ExpectedThumbprint 'AB:CD:EF:...'
    # fetch and verify the thumbprint before installing (pinned)

.EXAMPLE
    .\install-windows.ps1 -CertPath .\arc-lore-auth-tls.crt
    # install from a local file

.EXAMPLE
    .\install-windows.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Server = '',
    [int]$Port = 8443,
    [string]$CertPath,
    [string]$ExpectedThumbprint = '',
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err  { param([string]$m) Write-Host "[x] $m" -ForegroundColor Red }

# Fetch the leaf certificate a TLS server presents during its handshake. We do
# NOT verify it (the whole point is to retrieve the self-signed cert so we can
# trust it) - this is trust-on-first-use over the LAN.
function Get-RemoteCert {
    param([string]$HostName, [int]$Port)
    $tcp = [System.Net.Sockets.TcpClient]::new()
    $tcp.Connect($HostName, $Port)
    try {
        $accept = [System.Net.Security.RemoteCertificateValidationCallback]{ param($s, $c, $ch, $e) $true }
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $accept)
        try {
            $ssl.AuthenticateAsClient($HostName)
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        } finally { $ssl.Dispose() }
    } finally { $tcp.Dispose() }
}

# -- Elevation check -----------------------------------------------------------
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This script must run as Administrator (it writes LocalMachine\Root)."
    Write-Warn "Right-click PowerShell -> 'Run as administrator', then re-run."
    exit 1
}

$storeLocation = 'Cert:\LocalMachine\Root'

# -- Uninstall path ------------------------------------------------------------
if ($Uninstall) {
    Write-Info "Uninstalling arc-lore-auth cert from $storeLocation"

    $thumbprint = $null
    $subject    = $null
    if ($CertPath) {
        if (-not (Test-Path $CertPath)) { Write-Err "CertPath not found: $CertPath"; exit 1 }
        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (Resolve-Path $CertPath).Path
        $thumbprint = $c.Thumbprint
        $subject    = $c.Subject
    }

    $matches = @()
    if ($thumbprint) {
        $matches = Get-ChildItem $storeLocation | Where-Object { $_.Thumbprint -eq $thumbprint }
    }
    if (-not $matches -and $subject) {
        $matches = Get-ChildItem $storeLocation | Where-Object { $_.Subject -eq $subject }
    }
    if (-not $matches) {
        # Fall back to the well-known issuer name arc-lore-auth uses.
        $matches = Get-ChildItem $storeLocation | Where-Object { $_.Subject -match 'arc-lore-auth' }
    }

    if (-not $matches) {
        Write-Warn "No matching cert found in store - nothing to remove."
        exit 0
    }
    foreach ($m in $matches) {
        Write-Info "Removing $($m.Subject)  [$($m.Thumbprint)]"
        Remove-Item -Path $m.PSPath -Force
    }
    Write-Ok "Removed $($matches.Count) certificate(s)."
    exit 0
}

# -- Validate required params ---------------------------------------------------
if (-not $CertPath -and -not $Server) {
    Write-Err "-Server is required (the IP/hostname of your arc-lore-auth host) unless -CertPath is given."
    exit 1
}

# -- Obtain the cert (fetch from :8443 TLS, or a local -CertPath) ---------------
$tempFetched = $null
if (-not $CertPath) {
    Write-Info "Fetching cert from ${Server}:${Port} (TLS handshake - no creds needed)..."
    try {
        $fetched = Get-RemoteCert -HostName $Server -Port $Port
    } catch {
        Write-Err "Could not fetch the cert from ${Server}:${Port}: $($_.Exception.Message)"
        Write-Warn "Check the host/port and that arc-lore-auth is running, or pass -CertPath <file>."
        exit 1
    }
    $tempFetched = Join-Path $env:TEMP 'arc-lore-auth-tls.crt'
    [System.IO.File]::WriteAllBytes(
        $tempFetched,
        $fetched.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    $CertPath = $tempFetched
    Write-Ok "Fetched the cert presented by ${Server}:${Port}."
}
if (-not (Test-Path $CertPath)) {
    Write-Err "Cert file not found: $CertPath"
    exit 1
}
$CertPath = (Resolve-Path $CertPath).Path

# -- Inspect before import -----------------------------------------------------
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CertPath
$thumb = $cert.Thumbprint
Write-Info "Cert subject : $($cert.Subject)"
Write-Info "Cert SHA1    : $thumb"

# Surface the SAN so the operator can confirm it matches the dialed host.
$sanText = ''
foreach ($ext in $cert.Extensions) {
    if ($ext.Oid.Value -eq '2.5.29.17') {   # Subject Alternative Name
        $sanText = $ext.Format($false)
    }
}
if ($sanText) { Write-Info "Cert SAN     : $sanText" }
else { Write-Warn "Cert has no SAN extension - the gRPC client requires a matching SAN." }

# -- Optional thumbprint pin (TOFU when ExpectedThumbprint is absent) ----------
if ($ExpectedThumbprint -ne '') {
    $normalizeThumb = { param([string]$t) ($t -replace '[\s:]', '').ToUpperInvariant() }
    $fetchedNorm   = & $normalizeThumb $thumb
    $expectedNorm  = & $normalizeThumb $ExpectedThumbprint
    if ($fetchedNorm -ne $expectedNorm) {
        Write-Err "Thumbprint mismatch — aborting before trust-store import."
        Write-Err "  Expected : $ExpectedThumbprint"
        Write-Err "  Got      : $thumb"
        Write-Warn "Re-run install.sh on the server to confirm the cert has not been rotated."
        exit 1
    }
    Write-Ok "Thumbprint verified: $thumb"
}

# -- Import (idempotent) -------------------------------------------------------
$existing = Get-ChildItem $storeLocation | Where-Object { $_.Thumbprint -eq $thumb }
if ($existing) {
    Write-Ok "Cert already present in $storeLocation (thumbprint match) - nothing to do."
} else {
    Write-Info "Importing into $storeLocation ..."
    Import-Certificate -FilePath $CertPath -CertStoreLocation $storeLocation | Out-Null
    Write-Ok "Imported."
}

# -- Verify by reading back ----------------------------------------------------
$inStore = Get-ChildItem $storeLocation | Where-Object { $_.Thumbprint -eq $thumb }
if (-not $inStore) {
    Write-Err "Verification FAILED - cert not found in store after import."
    exit 1
}
Write-Ok "Verified in store:"
Write-Host "    Subject    : $($inStore.Subject)"
Write-Host "    Thumbprint : $($inStore.Thumbprint)"
Write-Host "    NotAfter   : $($inStore.NotAfter)"
if ($sanText) { Write-Host "    SAN        : $sanText" }

Write-Host ''
Write-Warn "REMINDER: the SAN above must match the host the editor dials in auth_url"
Write-Warn "(lore-server [environment.endpoint] auth_url = https://<host>:8443). An"
Write-Warn "IP-vs-hostname mismatch causes a TLS handshake failure - there is no skip-verify."

if ($tempFetched -and (Test-Path $tempFetched)) {
    Remove-Item $tempFetched -Force -ErrorAction SilentlyContinue
}
