[CmdletBinding()]
param(
    [switch]$SkipRuntimeBuild
)

$ErrorActionPreference = 'Stop'
$packRoot = $PSScriptRoot
$repoRoot = (Resolve-Path (Join-Path $packRoot '..')).Path
$runtimeRoot = Join-Path $packRoot '.runtime'
$composeFile = Join-Path $packRoot 'compose.dev.yml'
$stateFile = Join-Path $runtimeRoot 'state.json'
$runtimeTag = '127.0.0.1:5000/veyrion/artifact-runtime:dev'
$requiredFeatures = @(
    'artifact-readonly-mount-v1',
    'network-deny-v1',
    'non-root-v1',
    'read-only-rootfs-v1',
    'resource-budget-v1',
    'trace-tmpfs-v1'
) | Sort-Object

function Invoke-Docker {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($Arguments[0]) failed with exit code $LASTEXITCODE"
    }
}

& docker info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop Linux engine is not available.'
}

New-Item -ItemType Directory -Force -Path $runtimeRoot | Out-Null
Invoke-Docker @('compose', '-f', $composeFile, 'up', '-d', 'registry')

if (-not $SkipRuntimeBuild) {
    Invoke-Docker @(
        'build',
        '--file', (Join-Path $packRoot 'artifact-runtime.Dockerfile'),
        '--tag', $runtimeTag,
        $repoRoot
    )
    Invoke-Docker @('push', $runtimeTag)
}

$runtimeUri = (& docker image inspect --format '{{index .RepoDigests 0}}' $runtimeTag | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'The artifact runtime image is not available. Run without -SkipRuntimeBuild first.'
}
if ($runtimeUri -notmatch '^127\.0\.0\.1:5000/veyrion/artifact-runtime@sha256:[0-9a-f]{64}$') {
    throw 'The local registry did not return a digest-pinned artifact runtime reference.'
}

$state = [ordered]@{
    schemaVersion = 2
    runtime = 'docker-desktop-runc'
    capability = 'TRUSTED_DOCKER'
    networkMode = 'none'
    features = $requiredFeatures
    artifactRuntimeImageUri = $runtimeUri
}
[System.IO.File]::WriteAllText(
    $stateFile,
    ($state | ConvertTo-Json -Depth 4),
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output "Trusted internal JAR runtime: $runtimeUri"
Write-Output "State file: $stateFile"
Write-Warning 'TRUSTED_DOCKER uses --network none: external network and external DNS are unavailable; the target probe uses container-internal loopback. Docker runc is not a hardened hostile-code boundary.'
