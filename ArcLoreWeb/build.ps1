# build.ps1 — ArcLoreWeb full build sequence.
# Run from the ArcLoreWeb directory:  .\build.ps1
# Generated files (gen/ and web/templates/*_templ.go) are committed, so a plain
# "go build" works from a fresh clone.  Re-run this script when .proto files or
# .templ templates change.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "[1/3] buf generate  (regenerate gen/ from api/proto/*.proto)" -ForegroundColor Cyan
buf generate
if (-not $?) { exit 1 }

Write-Host "[2/3] templ generate  (regenerate web/templates/*_templ.go)" -ForegroundColor Cyan
templ generate
if (-not $?) { exit 1 }

Write-Host "[3/3] go build  (arcloreweb.exe)" -ForegroundColor Cyan
go build -o arcloreweb.exe ./cmd/arcloreweb
if (-not $?) { exit 1 }

Write-Host "Done. Binary: arcloreweb.exe" -ForegroundColor Green
