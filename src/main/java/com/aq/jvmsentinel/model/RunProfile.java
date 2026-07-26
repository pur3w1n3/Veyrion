package com.aq.jvmsentinel.model;

import java.util.Objects;

/**
 * Declares how an artifact may be executed dynamically. Without a complete
 * profile, WAR / non-Boot / CLASS stay static-only — never host-executed.
 */
public record RunProfile(
        ArtifactType artifactType,
        boolean executableBootJar,
        boolean profileProvided,
        String runtimeHint,
        String failureMode
) {
    public static final String MODE_OK = "OK";
    public static final String MODE_NO_RUN_PROFILE = "NO_RUN_PROFILE";
    public static final String MODE_WAR_DYNAMIC_DISABLED = "WAR_DYNAMIC_DISABLED";
    public static final String MODE_CLASS_STATIC_ONLY = "CLASS_STATIC_ONLY";
    public static final String MODE_NON_BOOT_JAR = "NON_BOOT_JAR_NEEDS_PROFILE";

    public RunProfile {
        Objects.requireNonNull(artifactType, "artifactType");
        runtimeHint = runtimeHint == null ? "" : runtimeHint;
        failureMode = failureMode == null || failureMode.isBlank() ? MODE_NO_RUN_PROFILE : failureMode;
    }

    public boolean allowsTrustedDockerDynamic() {
        return artifactType == ArtifactType.JAR && executableBootJar && profileProvided
                && MODE_OK.equals(failureMode);
    }

    public static RunProfile forArtifact(ArtifactType type, boolean hasMainClass, boolean profileProvided) {
        Objects.requireNonNull(type, "type");
        return switch (type) {
            case CLASS -> new RunProfile(type, false, false, "static-classfile", MODE_CLASS_STATIC_ONLY);
            case WAR -> new RunProfile(type, false, profileProvided,
                    profileProvided ? "embedded-container-profile" : "",
                    profileProvided ? MODE_WAR_DYNAMIC_DISABLED : MODE_NO_RUN_PROFILE);
            case JAR -> {
                if (!hasMainClass) {
                    yield new RunProfile(type, false, profileProvided, "library-jar",
                            MODE_NON_BOOT_JAR);
                }
                if (!profileProvided) {
                    // Boot JAR uses the default TRUSTED_DOCKER java -jar profile.
                    yield new RunProfile(type, true, true, "java -jar TRUSTED_DOCKER", MODE_OK);
                }
                yield new RunProfile(type, true, true, "java -jar TRUSTED_DOCKER", MODE_OK);
            }
        };
    }
}
