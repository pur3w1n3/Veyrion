# Optional fetcher for P0-15 open-source practical recall samples.
# Does NOT vendor JARs into git. Requires network + Maven.
# Usage:
#   pwsh scripts/fetch-practical-samples.ps1
#   pwsh scripts/fetch-practical-samples.ps1 -SampleId spring-petclinic
param(
    [string]$SampleId = "",
    [string]$OutRoot = "samples/practical-oss"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$catalogPath = Join-Path $repoRoot "src/test/resources/baselines/p0-15-practical-oss-samples.json"
if (-not (Test-Path $catalogPath)) {
    throw "Missing catalog $catalogPath"
}

$catalog = Get-Content -Raw -Path $catalogPath | ConvertFrom-Json
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

function Fetch-Sample($sample) {
    $id = $sample.sampleId
    $dest = Join-Path $OutRoot $id
    Write-Host "==> $id from $($sample.repositoryUrl)@$($sample.ref)"
    if (Test-Path $dest) {
        Write-Host "    already present: $dest"
    } else {
        git clone --depth 1 --branch $sample.ref $sample.repositoryUrl $dest
    }
    Push-Location $dest
    try {
        Write-Host "    build: $($sample.buildHint)"
        Invoke-Expression $sample.buildHint
    } finally {
        Pop-Location
    }
    $jars = Get-ChildItem -Path $dest -Recurse -Filter *.jar |
        Where-Object { $_.Name -notmatch '(-sources|-javadoc)\.jar$' }
    if (-not $jars) {
        Write-Warning "No runnable jar found for $id — check buildHint/module selection."
    } else {
        Write-Host "    jars:"
        $jars | Select-Object -First 8 | ForEach-Object { Write-Host "      $($_.FullName)" }
    }
}

foreach ($sample in $catalog.samples) {
    if ($SampleId -and $sample.sampleId -ne $SampleId) { continue }
    Fetch-Sample $sample
}

Write-Host "Done. Artifacts stay under $OutRoot and must not be committed."
Write-Host "Recall remains NOT_EVALUABLE until PracticalRecallBaselineAcceptanceTest observes local digests."
