[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?/(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*$')]
    [string]$ImageRepository,

    [Parameter(Mandatory = $true)]
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$metadataFile = Join-Path ([System.IO.Path]::GetTempPath()) ("veyrion-fixture-{0}.json" -f [guid]::NewGuid())
$buildTag = '{0}:build-{1}' -f $ImageRepository, ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())

try {
    if (-not $Push) {
        throw 'A registry push must be explicitly authorized with -Push; a local image has no trustworthy repository digest.'
    }

    & docker buildx build `
        --file (Join-Path $PSScriptRoot 'Dockerfile') `
        --tag $buildTag `
        --push `
        --metadata-file $metadataFile `
        $repoRoot
    if ($LASTEXITCODE -ne 0) {
        throw "docker buildx failed with exit code $LASTEXITCODE"
    }

    $metadata = Get-Content -Raw -LiteralPath $metadataFile | ConvertFrom-Json
    $digest = $metadata.'containerimage.digest'
    if ($digest -notmatch '^sha256:[0-9a-f]{64}$') {
        throw 'The registry/build result did not return a valid sha256 repository digest.'
    }

    $digestPinnedUri = '{0}@{1}' -f $ImageRepository, $digest
    Write-Output $digestPinnedUri
    Write-Information ("Set {0}={1}" -f 'VEYRION_HTTP_ENTRY_SMOKE_V1_IMAGE_URI', $digestPinnedUri) -InformationAction Continue
}
finally {
    Remove-Item -LiteralPath $metadataFile -Force -ErrorAction SilentlyContinue
}
