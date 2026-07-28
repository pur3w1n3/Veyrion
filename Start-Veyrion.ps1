[CmdletBinding()]
param(
    [string]$Artifacts,
    [ValidateRange(1, 65535)]
    [int]$BackendPort = 18080,
    [ValidateRange(1, 65535)]
    [int]$FrontendPort = 5173,
    [string]$JavaHome = $env:JAVA_HOME,
    [switch]$WithDockerRuntime,
    [switch]$RebuildRuntimeImage
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Artifacts)) {
    $Artifacts = Join-Path $PSScriptRoot 'samples'
}

# Local Control Plane SQLite lives at <Artifacts>/.veyrion/control-plane.db
# (default Artifacts = samples). Migration checksum mismatches fail closed;
# see README for backup-and-recreate recovery on disposable dev databases.

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

function Assert-LoopbackPortAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    $listener = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
    }
    catch {
        throw "$Name port $Port is already in use. Stop the old Veyrion process or choose another port."
    }
    finally {
        $listener.Stop()
    }
}

# Fail before starting Docker or rebuilding the application when an old
# development instance is still listening.
Assert-LoopbackPortAvailable -Port $BackendPort -Name 'Backend'
Assert-LoopbackPortAvailable -Port $FrontendPort -Name 'Frontend'

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

if ($WithDockerRuntime) {
    $sandboxStateFile = Join-Path $PSScriptRoot 'sandbox-pack\.runtime\state.json'
    $skipRuntimeBuild = (Test-Path -LiteralPath $sandboxStateFile) -and -not $RebuildRuntimeImage
    if ($skipRuntimeBuild) {
        & (Join-Path $PSScriptRoot 'sandbox-pack\Start-SandboxPack.ps1') `
            -SkipRuntimeBuild
    }
    else {
        & (Join-Path $PSScriptRoot 'sandbox-pack\Start-SandboxPack.ps1')
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $sandboxStateFile -PathType Leaf)) {
        throw 'Sandbox Pack startup failed.'
    }
    $sandboxState = Get-Content -Raw -LiteralPath $sandboxStateFile | ConvertFrom-Json
    if ($sandboxState.capability -ne 'TRUSTED_DOCKER' -or
        $sandboxState.artifactRuntimeImageUri -notmatch '^[a-z0-9.-]+(?::[0-9]{1,5})?/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$') {
        throw 'Sandbox Pack returned an invalid trusted artifact runtime image.'
    }
    $env:VEYRION_ARTIFACT_RUNTIME_IMAGE_URI = $sandboxState.artifactRuntimeImageUri
}

if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'frontend\node_modules\.bin\vite.cmd'))) {
    & npm ci --prefix frontend
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend dependency installation failed with exit code $LASTEXITCODE"
    }
}
$nodeExecutable = (Get-Command node -ErrorAction Stop).Source

& mvn -q '-Dmaven.repo.local=.m2' '-DskipTests' package
if ($LASTEXITCODE -ne 0) {
    throw "Maven build failed with exit code $LASTEXITCODE"
}

& mvn -q '-Dmaven.repo.local=.m2' dependency:build-classpath '-Dmdep.outputFile=target/runtime-classpath.txt'
if ($LASTEXITCODE -ne 0) {
    throw "Runtime classpath resolution failed with exit code $LASTEXITCODE"
}
$runtimeDependencies = (Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'target\runtime-classpath.txt')).Trim()
$applicationClasses = Join-Path $PSScriptRoot 'target\classes'
$runtimeClasspath = $applicationClasses + [System.IO.Path]::PathSeparator + $runtimeDependencies

& $javaExecutable -cp $runtimeClasspath com.aq.jvmsentinel.dev.DevLauncherMain `
    --workspace $workspace `
    --artifacts $artifactPath `
    --backend-port $BackendPort `
    --frontend-port $FrontendPort `
    --node $nodeExecutable `
    --docker-artifact-worker $WithDockerRuntime.IsPresent
exit $LASTEXITCODE
