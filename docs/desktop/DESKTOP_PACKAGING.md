# Desktop Core packaging (jlink + jpackage)

> Status: **SCAFFOLDING** (2026-07-28). This document and `scripts/desktop-jlink.ps1` describe the intended Desktop Core layout. They do **not** claim a production installer, auto-update channel, or Sandbox Pack attestation.

## Goal

Ship a personal-local **Desktop Core** image that contains:

- Java Control Plane + local CLI entrypoints
- React GUI static assets served by Control Plane (or adjacent static host)
- SQLite runtime native bits required by the JDBC driver

Optional later: a separate **Sandbox Pack** (Docker/gVisor/Kata Worker material) that is never bundled into Core without its own release evidence gate.

## Tooling

| Tool | Role |
|------|------|
| `jlink` | Produce a custom runtime image (`java.base`, `java.sql`, `jdk.httpserver`, …) |
| `jpackage` | Wrap the runtime image + application into a platform installer/app image |
| JDK 17+ | Project compiles with `--release 17`; packaging JDK should be a full JDK (not a JBR without `jlink`) |

## Dry-run

From the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/desktop-jlink.ps1 -DryRun
```

Dry-run checks:

1. `JAVA_HOME` is set and points at an existing directory
2. `jlink` exists under `$JAVA_HOME/bin`
3. Prints the planned module set and output directories without writing an image

Success prints `DESKTOP_JLINK_DRY_RUN_OK`.

## Planned layout (not yet produced)

```text
dist/desktop-core/
  runtime/          # jlink image
  app/              # jvm-security-verifier jars + frontend dist
  bin/veyrion.*     # launcher stubs
```

## Honesty boundaries

- Desktop Core packaging does **not** enable `VERIFIED`, gVisor/Kata, or host execution of WAR artifacts.
- Sandbox Pack remains a separate attested deliverable; Core must degrade to `STATIC_ONLY` / `TRUSTED_DOCKER` / `DYNAMIC_DISABLED` when Sandbox Pack is absent.
- Do not treat a successful dry-run as evidence that an installer was built or audited.
