package com.aq.jvmsentinel.fixture;

import java.net.URI;
import java.util.Map;
import java.util.Objects;

/**
 * Code-owned allowlist for fixtures that may use the development runc capability.
 * Public API input selects an identifier only; it cannot supply runtime material.
 */
public final class TrustedFixtureCatalog {
    public static final String HTTP_ENTRY_SMOKE_V1 = "http-entry-smoke-v1";
    public static final String HTTP_ENTRY_SMOKE_V2 = "http-entry-smoke-v2";
    private static final String HTTP_ENTRY_SMOKE_DIGEST =
            "7bb52f8ad62998aabb45d0f797cb93f22b3e8619f8737d2a65dfc750956f729d";
    private static final String HTTP_ENTRY_SMOKE_V2_DIGEST =
            "5d2b801c8fdb6b39fc6085bdf9aa78417f49c5cb24ca0a50b68170f3ea828ada";

    private static final Map<String, TrustedFixture> FIXTURES = Map.of(
            HTTP_ENTRY_SMOKE_V1,
            new TrustedFixture(
                    HTTP_ENTRY_SMOKE_V1,
                    "registry.invalid/veyrion/fixture-http-entry@sha256:" + HTTP_ENTRY_SMOKE_DIGEST,
                    "com.aq.jvmsentinel.fixture.HttpEntryFixture",
                    HTTP_ENTRY_SMOKE_DIGEST,
                    "entry-1"),
            HTTP_ENTRY_SMOKE_V2,
            new TrustedFixture(
                    HTTP_ENTRY_SMOKE_V2,
                    "registry.invalid/veyrion/fixture-http-entry-v2@sha256:" + HTTP_ENTRY_SMOKE_V2_DIGEST,
                    "com.aq.jvmsentinel.fixture.HttpEntryFixtureV2",
                    HTTP_ENTRY_SMOKE_V2_DIGEST,
                    "entry-1"));

    public TrustedFixture require(String fixtureId) {
        TrustedFixture fixture = fixtureId == null ? null : FIXTURES.get(fixtureId);
        if (fixture == null) throw new UnknownFixtureException("fixture is not in the trusted catalog");
        return fixture;
    }

    public record TrustedFixture(String fixtureId, String imageUri, String mainClass,
                                 String fixtureDigest, String targetEntryId) {
        public TrustedFixture {
            fixtureId = requireId(fixtureId, "fixtureId");
            targetEntryId = requireId(targetEntryId, "targetEntryId");
            mainClass = Objects.requireNonNull(mainClass, "mainClass");
            if (!mainClass.matches("[A-Za-z_$][A-Za-z0-9_$.]{0,254}")) {
                throw new IllegalArgumentException("mainClass is invalid");
            }
            fixtureDigest = Objects.requireNonNull(fixtureDigest, "fixtureDigest");
            if (!fixtureDigest.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("fixtureDigest must be a lowercase SHA-256");
            }
            URI image = URI.create(Objects.requireNonNull(imageUri, "imageUri"));
            if (image.getScheme() != null || image.getQuery() != null || image.getFragment() != null
                    || !imageUri.endsWith("@sha256:" + fixtureDigest)) {
                throw new IllegalArgumentException("imageUri must be an immutable registry reference");
            }
        }

        private static String requireId(String value, String name) {
            Objects.requireNonNull(value, name);
            if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
                throw new IllegalArgumentException(name + " is invalid");
            }
            return value;
        }
    }

    public static final class UnknownFixtureException extends IllegalArgumentException {
        public UnknownFixtureException(String message) {
            super(message);
        }
    }
}
