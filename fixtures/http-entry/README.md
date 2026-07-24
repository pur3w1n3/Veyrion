# HTTP entry controlled fixture

This is a real Java 17 / Spring Boot 4.1.0 fixture for the repository-owned
`http-entry-smoke-v1` path. It is intentionally not a service:

- Spring starts with `WebApplicationType.NONE`; no HTTP listener is opened.
- `ControlledProbeRunner` directly invokes the real `@RestController` /
  `@PostMapping` method once with a bounded synthetic marker.
- The application code does not open sockets, connect to a database, touch a
  file, or start a process. It reports synthetic HTTP/JDBC/FILE/PROCESS intents
  through `AgentRuntime`; every dependency intent says `executed=false`.
- The Spring context closes and the process exits after that single call.
- The JVM Agent is observation code, not a sandbox or security boundary.
  Runtime network denial, read-only root filesystems, capability removal, and
  resource budgets remain Worker/OpenSandbox responsibilities.

## Maven build and tests

Run from the repository root. Installing the agent only makes its API available
to this independent Maven module:

```powershell
mvn -f agent/pom.xml "-Dmaven.repo.local=.m2" install
mvn -f fixtures/http-entry/pom.xml "-Dmaven.repo.local=.m2" test
mvn -f fixtures/http-entry/pom.xml "-Dmaven.repo.local=.m2" package
```

The packaged artifact is `fixtures/http-entry/target/fixture.jar`. It is a
flattened shaded JAR because the current Worker invokes the fixed main class
with `java -cp`, rather than using Spring Boot's nested-JAR launcher.

## Container build and repository digest

The Dockerfile must use the repository root as its build context. It copies only
the agent and fixture Maven inputs into a multi-stage build; it does not copy
the host workspace, Maven settings, environment files, or credentials into the
runtime image. The Java 17 runtime uses fixed numeric user/group `65532:65532`
and an exec-form Java entrypoint.

A local image ID is not a repository digest. The PowerShell script therefore
requires an explicit `-Push`, pushes a temporary tag with BuildKit, reads the
digest returned by that build/push, validates it, and only then prints the real
digest-pinned URI:

```powershell
.\fixtures\http-entry\Build-Fixture.ps1 `
  -ImageRepository registry.example.com/veyrion/fixture-http-entry `
  -Push
```

This repository does not contain or claim a published image digest. Use the
script output as trusted operator configuration:

```powershell
$env:VEYRION_HTTP_ENTRY_SMOKE_V1_IMAGE_URI = `
  'registry.example.com/veyrion/fixture-http-entry@sha256:<actual-64-hex-digest>'
```

Do not type the placeholder as configuration. The Control Plane accepts only a
lowercase registry/repository URI with an exact `@sha256:` digest and derives
`fixtureDigest` from that URI. Fixture ID, main class, and target entry remain
code-owned. Public dynamic-task requests still accept only `authorized` and
`fixtureId`.

## Trace directory compatibility

The image and Worker both use `/tmp/veyrion-trace`. The deployment operator must
attest `writable-tmp-v1` in addition to the read-only-root capability; otherwise
the Worker rejects execution. This keeps the root filesystem immutable while
providing one bounded ephemeral output location for the Agent trace.
