# Trusted Boot multi-entry fixture

Built at test time by `TrustedBootJarFixture` for live `TRUSTED_DOCKER` multi-request acceptance.

- Executable `Main-Class` hosts JDK `HttpServer` on port `8080` with `/api/a` and `/api/b`
- Each route executes a distinct JDBC statement via `jdbc:veyrion-mock:` (Agent dependency mock)
- `BOOT-INF/classes` carries Spring annotation stubs so static analysis can discover both entries

Not a production sample. Do not treat results as malicious-artifact isolation evidence.
