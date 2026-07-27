package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.analysis.identity.AuthCodeQueryService;
import com.aq.jvmsentinel.control.service.ProbePlanService;
import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Collectors;

/** Acceptance checks for fair identity-track expansion under the 512 probe cap. */
public final class ControlPlaneProbeExpansionAcceptanceTest {
    public static void main(String[] args) throws Exception {
        withoutHarvestOnlyUnauthExpands();
        withHarvestMultiTrackExpansionRespectsCap();
        missingAuthMaterializesUnauthenticated();
        authAndBladeChannelsMaterializeIndependently();
        defaultSecretHs256DualWritesBladeAuth();

        System.out.println("ControlPlaneProbeExpansionAcceptanceTest: PASS");
    }

    /** No artifact harvest → no forged ADMIN JWT; only UNAUTH probes expand. */
    private static void withoutHarvestOnlyUnauthExpands() {
        List<ApiDtos.EntryDto> entries = new ArrayList<>();
        entries.add(entry(0, "/admin/token"));
        for (int i = 1; i < 40; i++) {
            entries.add(entry(i, "/api/route" + i));
        }
        List<ExternalArtifactTaskExecutor.ProbeTarget> base = entries.stream()
                .map(entry -> new ExternalArtifactTaskExecutor.ProbeTarget(
                        entry.method(), entry.route(), "", IdentityTrack.UNAUTH.name(), ""))
                .toList();
        List<ExternalArtifactTaskExecutor.ProbeTarget> expanded =
                ControlPlaneServer.expandProbesByIdentityTracks((Path) null, entries, base, 512);
        check(expanded.size() <= 512, "expanded plan must respect the hard cap");
        check(tracksFor(expanded, "/admin/token").equals(Set.of(IdentityTrack.UNAUTH.name())),
                "without harvest high-value route only expands UNAUTH");
        check(expanded.stream().noneMatch(p -> IdentityTrack.ADMIN.name().equals(p.track())),
                "without harvest ADMIN JWT tracks are not silently forged");
    }

    /** Harvested sign-key restores multi-track expansion under the 512 cap. */
    private static void withHarvestMultiTrackExpansionRespectsCap() throws Exception {
        Path jar = writeHarvestJar();
        try {
            List<ApiDtos.EntryDto> entries = new ArrayList<>();
            entries.add(entry(0, "/admin/token"));
            entries.add(entry(1, "/deploy/upload"));
            for (int i = 2; i < 250; i++) {
                entries.add(entry(i, "/api/route" + i));
            }
            List<ExternalArtifactTaskExecutor.ProbeTarget> base = entries.stream()
                    .map(entry -> new ExternalArtifactTaskExecutor.ProbeTarget(
                            entry.method(), entry.route(), "", IdentityTrack.UNAUTH.name(), ""))
                    .toList();

            List<ExternalArtifactTaskExecutor.ProbeTarget> expanded =
                    ControlPlaneServer.expandProbesByIdentityTracks(jar, entries, base, 512);

            check(expanded.size() <= 512, "expanded plan must respect the hard cap");
            check(tracksFor(expanded, "/admin/token").equals(Set.of(
                            IdentityTrack.UNAUTH.name(),
                            IdentityTrack.USER.name(),
                            IdentityTrack.ADMIN.name(),
                            IdentityTrack.BYPASS_CANDIDATE.name())),
                    "with harvest high-value route receives every available track");
            check(tracksFor(expanded, "/api/route249").containsAll(Set.of(
                            IdentityTrack.UNAUTH.name(), IdentityTrack.ADMIN.name())),
                    "later ordinary routes must not starve authenticated tracks");
            check(!tracksFor(expanded, "/api/route249").contains(IdentityTrack.BYPASS_CANDIDATE.name()),
                    "ordinary routes must not receive bypass track by default");

            List<ApiDtos.EntryDto> saturatedEntries = new ArrayList<>();
            for (int i = 0; i < 512; i++) {
                saturatedEntries.add(entry(i, "/bulk/route" + i));
            }
            List<ExternalArtifactTaskExecutor.ProbeTarget> saturatedBase = saturatedEntries.stream()
                    .map(entry -> new ExternalArtifactTaskExecutor.ProbeTarget(entry.method(), entry.route()))
                    .toList();
            List<ExternalArtifactTaskExecutor.ProbeTarget> saturated =
                    ControlPlaneServer.expandProbesByIdentityTracks(
                            jar, saturatedEntries, saturatedBase, 512);
            check(saturated.size() == 512, "saturated expansion must still fill the cap");
            check(saturated.stream().anyMatch(probe -> IdentityTrack.ADMIN.name().equals(probe.track())),
                    "saturated expansion must reserve space for authenticated tracks");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    /** MISSING_AUTH must probe without Authorization / secondary auth and without inventing a bearer. */
    private static void missingAuthMaterializesUnauthenticated() {
        ProbePlanService.AuthMaterialized omitted =
                ControlPlaneServer.materializeAiPocAuth("MISSING_AUTH", null, null);
        check(IdentityTrack.UNAUTH.name().equals(omitted.track().name()), "MISSING_AUTH track is UNAUTH");
        check(omitted.authToken().isEmpty(), "MISSING_AUTH omits auth token");
        check(omitted.secondaryAuthToken().isEmpty(), "MISSING_AUTH omits secondary auth token");
        check(omitted.identityAvailable(), "MISSING_AUTH remains probeable as UNAUTH");
        check("MISSING_AUTH".equals(omitted.provenance()), "MISSING_AUTH provenance");

        ProbePlanService.AuthMaterialized empty =
                ControlPlaneServer.materializeAiPocAuth("MISSING_AUTH", "", null);
        check(empty.authToken().isEmpty() && IdentityTrack.UNAUTH == empty.track(),
                "empty authorizationHeader still means unauthenticated");

        try {
            ControlPlaneServer.materializeAiPocAuth("MISSING_AUTH", "Bearer eyJhbGciOiJub25lIn0.e30.", null);
            throw new AssertionError("MISSING_AUTH must reject non-empty authorizationHeader");
        } catch (IllegalArgumentException expected) {
            check("MISSING_AUTH_MUST_OMIT_AUTHORIZATION".equals(expected.getMessage()),
                    "stable MISSING_AUTH_MUST_OMIT_AUTHORIZATION code");
        }

        try {
            ControlPlaneServer.materializeAiPocAuth("MISSING_AUTH", null, "secondary-token", null);
            throw new AssertionError("MISSING_AUTH must reject non-empty secondary auth header");
        } catch (IllegalArgumentException expected) {
            check("MISSING_AUTH_MUST_OMIT_AUTHORIZATION".equals(expected.getMessage()),
                    "MISSING_AUTH rejects secondary auth header with same code");
        }

        ProbePlanService.AuthMaterialized algNone =
                ControlPlaneServer.materializeAiPocAuth("ALG_NONE",
                        "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.", null);
        check(!algNone.authToken().isBlank(), "ALG_NONE still accepts AI JWT material");
        check(algNone.secondaryAuthToken().isEmpty(),
                "auth-only material does not invent secondary auth");
    }

    private static void authAndBladeChannelsMaterializeIndependently() {
        ProbePlanService.AuthMaterialized authOnly =
                ControlPlaneServer.materializeAiPocAuth("CUSTOM_POC", "tok-auth", null, null);
        check("tok-auth".equals(authOnly.authToken()) && authOnly.secondaryAuthToken().isEmpty(),
                "auth-only PoC leaves secondaryAuthToken empty");

        ProbePlanService.AuthMaterialized secondaryOnly =
                ControlPlaneServer.materializeAiPocAuth("CUSTOM_POC", null, "tok-secondary", null);
        check(secondaryOnly.authToken().isEmpty()
                        && "tok-secondary".equals(secondaryOnly.secondaryAuthToken()),
                "secondary-only PoC leaves authToken empty");

        ProbePlanService.AuthMaterialized both =
                ControlPlaneServer.materializeAiPocAuth("CUSTOM_POC", "tok-a", "tok-b", null);
        check("tok-a".equals(both.authToken()) && "tok-b".equals(both.secondaryAuthToken()),
                "both channels stay distinct");
    }

    /**
     * DEFAULT_SECRET_HS256 mints only after artifact harvest; without a key → IDENTITY_UNAVAILABLE.
     * With harvested key + multi-header surface → dual-write Authorization + secondary auth.
     */
    private static void defaultSecretHs256DualWritesBladeAuth() throws Exception {
        ProbePlanService.AuthMaterialized unavailable =
                ControlPlaneServer.materializeAiPocAuth("DEFAULT_SECRET_HS256", null, null, null);
        check(!unavailable.identityAvailable(),
                "DEFAULT_SECRET_HS256 without harvest is IDENTITY_UNAVAILABLE");
        check(unavailable.provenance() != null
                        && unavailable.provenance().contains("IDENTITY_UNAVAILABLE"),
                "provenance explains missing signing material");

        Path jar = writeHarvestJar();
        try {
            ProbePlanService.AuthMaterialized mat =
                    ControlPlaneServer.materializeAiPocAuth("DEFAULT_SECRET_HS256", null, null, jar);
            check(mat.identityAvailable(), "DEFAULT_SECRET_HS256 available after harvest");
            check(!mat.authToken().isBlank(), "DEFAULT_SECRET_HS256 sets Authorization token");
            check(mat.secondaryAuthToken() != null
                            && mat.secondaryAuthToken().toLowerCase().startsWith("bearer "),
                    "DEFAULT_SECRET_HS256 dual-writes secondary auth with bearer scheme");
        } finally {
            Files.deleteIfExists(jar);
        }
    }

    private static Path writeHarvestJar() throws Exception {
        Path jar = Files.createTempFile("probe-multi-header-key-", ".jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry(
                    "BOOT-INF/classes/org/springblade/core/jwt/props/JwtProperties.class"));
            byte[] key = AuthCodeQueryService.WELL_KNOWN_BLADE_COMMERCIAL_SIGN_KEY
                    .getBytes(StandardCharsets.UTF_8);
            byte[] bytes = new byte[4 + key.length];
            bytes[0] = (byte) 0xCA;
            bytes[1] = (byte) 0xFE;
            bytes[2] = (byte) 0xBA;
            bytes[3] = (byte) 0xBE;
            System.arraycopy(key, 0, bytes, 4, key.length);
            jos.write(bytes);
            jos.closeEntry();
        }
        return jar;
    }

    private static Set<String> tracksFor(List<ExternalArtifactTaskExecutor.ProbeTarget> probes, String route) {
        return probes.stream()
                .filter(probe -> route.equals(probe.route()))
                .map(ExternalArtifactTaskExecutor.ProbeTarget::track)
                .collect(Collectors.toSet());
    }

    private static ApiDtos.EntryDto entry(int index, String route) {
        return new ApiDtos.EntryDto(
                ApiDtos.SCHEMA_VERSION,
                "project-test",
                "a".repeat(64),
                "scan-test",
                "entry-" + index,
                "HTTP",
                "GET",
                route,
                "example.Controller" + index,
                "app",
                List.of(),
                List.of(),
                ApiDtos.STATIC_INFERRED,
                0.9,
                0,
                List.of());
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
