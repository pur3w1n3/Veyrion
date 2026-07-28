# P0-14 local CI gates (deterministic, fail-closed).
# Usage (from repo root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/ci-gates.ps1
#
# Allowed paths mode (DEFAULT ENABLED):
#   Compares git working-tree changes against an Allowed paths file
#   (default: contracts/task-allowed-paths.example.txt).
#   - If there is no git diff / untracked change: SKIP OK
#   - If AllowedPathsFile is set/default and a changed path is outside the list: FAIL
#   Opt out:  -SkipAllowedPaths
#   Override: -AllowedPathsFile <path>
#
# Other optional switches:
#   -SkipCompile   reuse existing target/test-classes

param(
    [switch]$SkipCompile,
    [switch]$SkipAllowedPaths,
    [string]$AllowedPathsFile = ""
)

$ErrorActionPreference = "Stop"
$env:JAVA_HOME = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { "C:\Program Files\JetBrains\IntelliJ IDEA 2025.3.2\jbr" }
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Fail([string]$Message) {
    Write-Host "FAIL: $Message" -ForegroundColor Red
    exit 1
}

function Test-PathAllowed([string]$Path, [string[]]$AllowedPatterns) {
    $normalized = $Path.Replace('\', '/')
    foreach ($pattern in $AllowedPatterns) {
        $glob = $pattern.Replace('\', '/')
        if ($glob.EndsWith("/**")) {
            $prefix = $glob.Substring(0, $glob.Length - 2)
            if ($normalized.StartsWith($prefix)) { return $true }
        } elseif ($normalized -eq $glob -or $normalized.StartsWith($glob.TrimEnd('*'))) {
            return $true
        }
    }
    return $false
}

Write-Step "Repo root: $RepoRoot"
Write-Host "JAVA_HOME=$env:JAVA_HOME"

# --- 1) Compile + AcceptanceTestRunner (non-zero assertions) ---
if (-not $SkipCompile) {
    Write-Step "mvn -q test-compile"
    & mvn -q test-compile
    if ($LASTEXITCODE -ne 0) { Fail "mvn test-compile failed ($LASTEXITCODE)" }
}

Write-Step "AcceptanceTestRunner (curated non-zero gate)"
$cp = @(
    (Join-Path $RepoRoot "target\test-classes"),
    (Join-Path $RepoRoot "target\classes")
) -join ";"
$deps = Get-ChildItem (Join-Path $RepoRoot "target\dependency") -Filter "*.jar" -ErrorAction SilentlyContinue
if (-not $deps) {
    Write-Step "Copy Maven runtime/test deps for classpath"
    & mvn -q dependency:build-classpath "-Dmdep.outputFile=target/classpath.txt" "-DincludeScope=test"
    if ($LASTEXITCODE -ne 0) { Fail "dependency:build-classpath failed" }
    $depCp = Get-Content (Join-Path $RepoRoot "target\classpath.txt") -Raw
} else {
    $depCp = ($deps | ForEach-Object { $_.FullName }) -join ";"
}
if (Test-Path (Join-Path $RepoRoot "target\classpath.txt")) {
    $depCp = (Get-Content (Join-Path $RepoRoot "target\classpath.txt") -Raw).Trim()
}
$fullCp = "$cp;$depCp"
$java = Join-Path $env:JAVA_HOME "bin\java.exe"
& $java -cp $fullCp com.aq.jvmsentinel.AcceptanceTestRunner
if ($LASTEXITCODE -ne 0) { Fail "AcceptanceTestRunner failed ($LASTEXITCODE)" }

# --- 2) Migration presence / V00x order (also covered in CiGateAcceptanceTest) ---
Write-Step "Migration files V00x contiguous"
$migDir = Join-Path $RepoRoot "src\main\resources\db\migration"
$migs = Get-ChildItem $migDir -Filter "V*.sql" | Sort-Object Name
if ($migs.Count -lt 1) { Fail "no migrations found" }
$expected = 1
foreach ($m in $migs) {
    if ($m.Name -notmatch '^V(\d{3})__.+\.sql$') { Fail "bad migration name: $($m.Name)" }
    $ver = [int]$Matches[1]
    if ($ver -ne $expected) { Fail "migration gap: expected V$('{0:D3}' -f $expected) saw $($m.Name)" }
    $expected++
}
Write-Host "OK: $($migs.Count) migrations contiguous"

# --- 3) Migration checksum table sampling ---
Write-Step "Migration checksum table consistency"
$checksumPath = Join-Path $RepoRoot "contracts\migration-checksums.txt"
if (-not (Test-Path $checksumPath)) { Fail "missing contracts/migration-checksums.txt" }
$pinned = @{}
Get-Content $checksumPath | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#")) { return }
    $parts = $line -split '\s+', 2
    if ($parts.Count -ne 2) { Fail "bad checksum line: $line" }
    $pinned[$parts[1]] = $parts[0].ToLowerInvariant()
}
foreach ($m in $migs) {
    if (-not $pinned.ContainsKey($m.Name)) { Fail "checksum missing for $($m.Name)" }
    $bytes = [System.IO.File]::ReadAllBytes($m.FullName)
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString("x2") }) -join ""
    if ($hash -ne $pinned[$m.Name]) { Fail "checksum mismatch for $($m.Name)" }
}
Write-Host "OK: $($pinned.Count) migration checksums match"

# --- 4) Markdown relative link check (docs/**/*.md) ---
Write-Step "Markdown relative links under docs/"
$mdFiles = Get-ChildItem (Join-Path $RepoRoot "docs") -Recurse -Filter "*.md"
$linkPattern = '\]\(([^)]+)\)'
$broken = New-Object System.Collections.Generic.List[string]
foreach ($md in $mdFiles) {
    $content = Get-Content $md.FullName -Raw
    [regex]::Matches($content, $linkPattern) | ForEach-Object {
        $target = $_.Groups[1].Value.Trim()
        if (-not $target) { return }
        if ($target -match '^(https?://|mailto:|#)') { return }
        if ($target.StartsWith("http:") -or $target.StartsWith("https:")) { return }
        $pathPart = ($target -split '#', 2)[0]
        if (-not $pathPart) { return }
        if ($pathPart -match '^[a-zA-Z][a-zA-Z0-9+.-]*:') { return }
        $resolved = [System.IO.Path]::GetFullPath((Join-Path $md.DirectoryName $pathPart))
        if (-not (Test-Path -LiteralPath $resolved)) {
            $broken.Add("$($md.FullName.Substring($RepoRoot.Path.Length + 1)) -> $target")
        }
    }
}
if ($broken.Count -gt 0) {
    $broken | Select-Object -First 20 | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Fail "broken markdown links: $($broken.Count)"
}
Write-Host "OK: docs relative links resolve"

# --- 5) git diff --check (skip success when clean / unavailable) ---
Write-Step "git diff --check"
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    Write-Host "SKIP: git not available"
} else {
    # git may emit CRLF warnings on stderr; do not treat those as terminating errors.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $diffOutput = & git -C $RepoRoot diff --check 2>&1
    $diffExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    $conflictLines = @($diffOutput | Where-Object {
        $_ -and ($_ -notmatch 'LF will be replaced by CRLF') -and ($_ -notmatch '^warning:')
    })
    if ($diffExit -eq 0) {
        Write-Host "OK: git diff --check clean (or empty)"
    } elseif ($conflictLines.Count -eq 0) {
        Write-Host "OK: git diff --check exit=$diffExit with only CRLF/warnings"
    } else {
        $conflictLines | ForEach-Object { Write-Host $_ }
        Fail "git diff --check reported issues ($diffExit)"
    }
}

# --- 6) Allowed paths vs git diff (DEFAULT ENABLED; skip when no changes) ---
if ($SkipAllowedPaths) {
    Write-Step "Allowed paths audit"
    Write-Host "SKIP: -SkipAllowedPaths"
} else {
    Write-Step "Allowed paths audit vs git diff (default enabled)"
    if (-not $AllowedPathsFile) {
        $AllowedPathsFile = Join-Path $RepoRoot "contracts\task-allowed-paths.example.txt"
    }
    if (-not (Test-Path $AllowedPathsFile)) {
        Fail "AllowedPathsFile missing: $AllowedPathsFile (create contracts/task-allowed-paths.example.txt or pass -AllowedPathsFile / -SkipAllowedPaths)"
    }
    if (-not $git) {
        Write-Host "SKIP: git not available for Allowed paths audit"
    } else {
        $allowed = @(Get-Content $AllowedPathsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") })
        if ($allowed.Count -lt 1) { Fail "AllowedPathsFile has no path patterns: $AllowedPathsFile" }
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $changed = @(& git -C $RepoRoot diff --name-only HEAD 2>$null)
        $untracked = @(& git -C $RepoRoot ls-files --others --exclude-standard 2>$null)
        $ErrorActionPreference = $prevEap
        $all = @($changed) + @($untracked) | Where-Object { $_ } | ForEach-Object { $_.Replace('\', '/') } | Sort-Object -Unique
        if ($all.Count -eq 0) {
            Write-Host "SKIP: no git diff / untracked changes (Allowed paths OK)"
        } else {
            $violations = @()
            foreach ($path in $all) {
                if (-not (Test-PathAllowed $path $allowed)) {
                    $violations += $path
                }
            }
            if ($violations.Count -gt 0) {
                $violations | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
                Fail "paths outside Allowed list: $($violations.Count) (file=$AllowedPathsFile). Use task-pack allowlist or -SkipAllowedPaths for dirty trees."
            }
            Write-Host "OK: $($all.Count) changed path(s) within Allowed list ($AllowedPathsFile)"
        }
    }
}

Write-Host ""
Write-Host "ci-gates.ps1: PASS" -ForegroundColor Green
exit 0
