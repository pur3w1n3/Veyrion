[CmdletBinding()]
param(
    [string]$Artifacts = (Join-Path $PSScriptRoot 'samples'),
    [ValidateRange(1, 65535)]
    [int]$BackendPort = 8080,
    [ValidateRange(1, 65535)]
    [int]$FrontendPort = 5173
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if ($BackendPort -eq $FrontendPort) {
    throw 'BackendPort and FrontendPort must be different.'
}

$workspace = (Resolve-Path $PSScriptRoot).Path
$artifactPath = [System.IO.Path]::GetFullPath($Artifacts)
$workspacePrefix = $workspace.TrimEnd('\') + '\'
if (-not $artifactPath.Equals($workspace, [System.StringComparison]::OrdinalIgnoreCase) -and
    -not $artifactPath.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Artifacts must stay inside the Veyrion workspace.'
}

if (-not (Test-Path -LiteralPath $artifactPath)) {
    New-Item -ItemType Directory -Path $artifactPath | Out-Null
}

if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'frontend\node_modules\.bin\vite.cmd'))) {
    & npm ci --prefix frontend
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend dependency installation failed with exit code $LASTEXITCODE"
    }
}

& mvn -q '-Dmaven.repo.local=.m2' '-DskipTests' package
if ($LASTEXITCODE -ne 0) {
    throw "Maven build failed with exit code $LASTEXITCODE"
}

& java -cp 'target/classes' com.aq.jvmsentinel.dev.DevLauncherMain `
    --workspace $workspace `
    --artifacts $artifactPath `
    --backend-port $BackendPort `
    --frontend-port $FrontendPort
exit $LASTEXITCODE
