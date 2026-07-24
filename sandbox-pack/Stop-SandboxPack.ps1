[CmdletBinding()]
param(
    [switch]$RemoveRegistryData
)

$ErrorActionPreference = 'Stop'
$composeFile = Join-Path $PSScriptRoot 'compose.dev.yml'
$arguments = @('compose', '-f', $composeFile, 'down', '--remove-orphans')
if ($RemoveRegistryData) {
    $arguments += '--volumes'
}

& docker @arguments
if ($LASTEXITCODE -ne 0) {
    throw "docker compose down failed with exit code $LASTEXITCODE"
}

Write-Output 'Veyrion development Sandbox Pack stopped.'
