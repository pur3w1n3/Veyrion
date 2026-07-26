package com.aq.jvmsentinel.model;

/** P2-01: WAR/non-Boot dynamic paths stay fail-closed without host execution. */
public final class RunProfileAcceptanceTest {
    public static void main(String[] args) {
        RunProfile boot = RunProfile.forArtifact(ArtifactType.JAR, true, false);
        check(boot.allowsTrustedDockerDynamic(), "Boot JAR uses default TRUSTED_DOCKER profile");
        check(RunProfile.MODE_OK.equals(boot.failureMode()), "Boot JAR failureMode OK");

        RunProfile library = RunProfile.forArtifact(ArtifactType.JAR, false, false);
        check(!library.allowsTrustedDockerDynamic(), "library JAR blocked");
        check(RunProfile.MODE_NON_BOOT_JAR.equals(library.failureMode()), "library JAR needs profile");

        RunProfile warNoProfile = RunProfile.forArtifact(ArtifactType.WAR, false, false);
        check(!warNoProfile.allowsTrustedDockerDynamic(), "WAR without profile blocked");
        check(RunProfile.MODE_NO_RUN_PROFILE.equals(warNoProfile.failureMode()),
                "WAR without profile → NO_RUN_PROFILE");

        RunProfile warWithProfile = RunProfile.forArtifact(ArtifactType.WAR, false, true);
        check(!warWithProfile.allowsTrustedDockerDynamic(),
                "WAR with profile still not silently host-executed");
        check(RunProfile.MODE_WAR_DYNAMIC_DISABLED.equals(warWithProfile.failureMode()),
                "WAR dynamic remains disabled until embedded runtime exists");

        RunProfile classOnly = RunProfile.forArtifact(ArtifactType.CLASS, false, true);
        check(!classOnly.allowsTrustedDockerDynamic(), "CLASS stays static-only");
        check(RunProfile.MODE_CLASS_STATIC_ONLY.equals(classOnly.failureMode()), "CLASS_STATIC_ONLY");

        System.out.println("RunProfileAcceptanceTest: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
