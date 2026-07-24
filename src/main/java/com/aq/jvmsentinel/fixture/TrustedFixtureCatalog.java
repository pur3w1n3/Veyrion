package com.aq.jvmsentinel.fixture;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Code-owned allowlist for fixtures that may use the development runc capability.
 * Public API input selects an identifier only; it cannot supply runtime material.
 */
public final class TrustedFixtureCatalog {
    public static final String HTTP_ENTRY_SMOKE_V1 = "http-entry-smoke-v1";
    public static final String HTTP_ENTRY_SMOKE_V2 = "http-entry-smoke-v2";
    public static final String HTTP_ENTRY_SMOKE_V1_IMAGE_ENV =
            "VEYRION_HTTP_ENTRY_SMOKE_V1_IMAGE_URI";
    private static final String HTTP_ENTRY_SMOKE_DIGEST =
            "7bb52f8ad62998aabb45d0f797cb93f22b3e8619f8737d2a65dfc750956f729d";
    private static final String HTTP_ENTRY_SMOKE_V2_DIGEST =
            "5d2b801c8fdb6b39fc6085bdf9aa78417f49c5cb24ca0a50b68170f3ea828ada";
    private static final String DEFAULT_HTTP_ENTRY_SMOKE_IMAGE =
            "registry.invalid/veyrion/fixture-http-entry@sha256:" + HTTP_ENTRY_SMOKE_DIGEST;
    private static final Pattern IMMUTABLE_IMAGE = Pattern.compile(
            "[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?/"
                    + "(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*"
                    + "[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:([0-9a-f]{64})");

    private final Map<String, TrustedFixture> fixtures;

    /** Fail-closed defaults: neither image resolves unless an operator explicitly configures it. */
    public TrustedFixtureCatalog() {
        this(DEFAULT_HTTP_ENTRY_SMOKE_IMAGE);
    }

    /** Explicit trusted-operator injection for the V1 image only. */
    public TrustedFixtureCatalog(String httpEntrySmokeV1ImageUri) {
        String v1Digest = digestFromImageUri(httpEntrySmokeV1ImageUri);
        this.fixtures = Map.of(
                HTTP_ENTRY_SMOKE_V1,
                new TrustedFixture(
                        HTTP_ENTRY_SMOKE_V1,
                        httpEntrySmokeV1ImageUri,
                        "com.aq.jvmsentinel.fixture.HttpEntryFixture",
                        v1Digest,
                        "entry-1"),
                HTTP_ENTRY_SMOKE_V2,
                new TrustedFixture(
                        HTTP_ENTRY_SMOKE_V2,
                        "registry.invalid/veyrion/fixture-http-entry-v2@sha256:" + HTTP_ENTRY_SMOKE_V2_DIGEST,
                        "com.aq.jvmsentinel.fixture.HttpEntryFixtureV2",
                        HTTP_ENTRY_SMOKE_V2_DIGEST,
                        "entry-1"));
    }

    public static TrustedFixtureCatalog fromEnvironment(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        String configured = environment.get(HTTP_ENTRY_SMOKE_V1_IMAGE_ENV);
        return configured == null || configured.isBlank()
                ? new TrustedFixtureCatalog()
                : new TrustedFixtureCatalog(configured);
    }

    public TrustedFixture require(String fixtureId) {
        TrustedFixture fixture = fixtureId == null ? null : fixtures.get(fixtureId);
        if (fixture == null) throw new UnknownFixtureException("fixture is not in the trusted catalog");
        return fixture;
    }

    private static String digestFromImageUri(String imageUri) {
        Objects.requireNonNull(imageUri, "imageUri");
        Matcher matcher = IMMUTABLE_IMAGE.matcher(imageUri);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                    "imageUri must be a lowercase registry/repository reference pinned by sha256");
        }
        URI image = URI.create(imageUri);
        if (image.getScheme() != null || image.getQuery() != null || image.getFragment() != null) {
            throw new IllegalArgumentException("imageUri must be an immutable registry reference");
        }
        return matcher.group(1);
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
            String extractedDigest = digestFromImageUri(imageUri);
            fixtureDigest = Objects.requireNonNull(fixtureDigest, "fixtureDigest");
            if (!extractedDigest.equals(fixtureDigest)) {
                throw new IllegalArgumentException("fixtureDigest must match the image URI digest");
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
