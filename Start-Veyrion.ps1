[CmdletBinding()]
param(
    [string]$Artifacts = (Join-Path $PSScriptRoot 'samples'),
    [ValidateRange(1, 65535)]
    [int]$BackendPort = 8080,
    [ValidateRange(1, 65535)]
    [int]$FrontendPort = 5173,
    [string]$JavaHome = $env:JAVA_HOME
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not [string]::IsNullOrWhiteSpace($JavaHome)) {
    $resolvedJavaHome = (Resolve-Path -LiteralPath $JavaHome).Path
    $javaExecutable = Join-Path $resolvedJavaHome 'bin\java.exe'
    if (-not (Test-Path -LiteralPath $javaExecutable -PathType Leaf)) {
        throw "JavaHome does not contain bin\java.exe: $resolvedJavaHome"
    }
    $env:JAVA_HOME = $resolvedJavaHome
    $env:Path = (Join-Path $resolvedJavaHome 'bin') + ';' + $env:Path
}
else {
    $javaExecutable = (Get-Command java -ErrorAction Stop).Source
}

$previousErrorAction = $ErrorActionPreference
try {
    # java writes version and property information to stderr by design.
    $ErrorActionPreference = 'Continue'
    $javaOutput = & $javaExecutable -XshowSettings:properties -version 2>&1
    $javaExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $previousErrorAction
}
$javaProperties = ($javaOutput | Out-String)
if ($javaExitCode -ne 0 -or
    $javaProperties -notmatch 'java\.specification\.version\s*=\s*(?:1\.)?(\d+)') {
    throw 'Unable to determine the Java runtime version.'
}
$javaMajor = [int]$Matches[1]
if ($javaMajor -lt 17) {
    throw "Veyrion requires Java 17 or newer, but Java $javaMajor is active. Use: .\Start-Veyrion.ps1 -JavaHome 'E:\path\to\jdk-17'"
}

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
