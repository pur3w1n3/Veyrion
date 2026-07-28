# Desktop Core jlink scaffolding (P2).
# Usage (repo root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/desktop-jlink.ps1 -DryRun
#
# Dry-run validates JAVA_HOME + jlink presence and prints the planned image layout.
# It does not build an installer and does not claim Sandbox Pack / VERIFIED readiness.

param(
    [switch]$DryRun,
    [string]$OutputDir = "dist/desktop-core"
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    Write-Host "FAIL: $Message" -ForegroundColor Red
    exit 1
}

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

if (-not $env:JAVA_HOME -or [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
    Fail "JAVA_HOME is not set"
}
if (-not (Test-Path $env:JAVA_HOME)) {
    Fail "JAVA_HOME does not exist: $env:JAVA_HOME"
}

$jlinkName = if ($IsWindows -or $env:OS -match "Windows") { "jlink.exe" } else { "jlink" }
$jlink = Join-Path $env:JAVA_HOME "bin\$jlinkName"
if (-not (Test-Path $jlink)) {
    # Some JetBrains JBR distributions omit jlink; dry-run must still fail closed on missing tool.
    Fail "jlink not found at $jlink (need a full JDK with jlink for Desktop Core packaging)"
}

$plannedModules = @(
    "java.base",
    "java.logging",
    "java.sql",
    "java.xml",
    "jdk.httpserver",
    "jdk.unsupported"
) -join ","

Write-Step "JAVA_HOME=$env:JAVA_HOME"
Write-Step "jlink=$jlink"
Write-Host "Planned modules: $plannedModules"
Write-Host "Planned output:  $(Join-Path $RepoRoot $OutputDir)"

if ($DryRun) {
    Write-Host "Would run: jlink --add-modules $plannedModules --output $OutputDir/runtime --strip-debug --no-header-files --no-man-pages"
    Write-Host "Would stage app jars + frontend dist under $OutputDir/app (not executed in DryRun)"
    Write-Host "DESKTOP_JLINK_DRY_RUN_OK"
    exit 0
}

Fail "Non-dry-run packaging is SCAFFOLDING only; re-run with -DryRun or implement full jlink/jpackage in a follow-up task"
