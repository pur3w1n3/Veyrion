package com.aq.jvmsentinel.control;

import com.aq.jvmsentinel.model.IdentityTrack;
import com.aq.jvmsentinel.worker.ExternalArtifactTaskExecutor;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** Acceptance checks for fair identity-track expansion under the 512 probe cap. */
public final class ControlPlaneProbeExpansionAcceptanceTest {
    public static void main(String[] args) {
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
                ControlPlaneServer.expandProbesByIdentityTracks((Path) null, entries, base, 512);

        check(expanded.size() <= 512, "expanded plan must respect the hard cap");
        check(tracksFor(expanded, "/admin/token").equals(Set.of(
                        IdentityTrack.UNAUTH.name(),
                        IdentityTrack.USER.name(),
                        IdentityTrack.ADMIN.name(),
                        IdentityTrack.BYPASS_CANDIDATE.name())),
                "high-value route must receive every available track");
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
                        (Path) null, saturatedEntries, saturatedBase, 512);
        check(saturated.size() == 512, "saturated expansion must still fill the cap");
        check(saturated.stream().anyMatch(probe -> IdentityTrack.ADMIN.name().equals(probe.track())),
                "saturated expansion must reserve space for authenticated tracks");

        missingAuthMaterializesUnauthenticated();
        authAndBladeChannelsMaterializeIndependently();
        defaultSecretHs256DualWritesBladeAuth();

        System.out.println("ControlPlaneProbeExpansionAcceptanceTest: PASS");
    }

    /** MISSING_AUTH must probe without Authorization / Blade-Auth and without inventing a bearer. */
    private static void missingAuthMaterializesUnauthenticated() {
        ControlPlaneServer.AuthMaterialized omitted =
                ControlPlaneServer.materializeAiPocAuth("MISSING_AUTH", null, null);
        check(IdentityTrack.UNAUTH.name().equals(omitted.track().name()), "MISSING_AUTH track is UNAUTH");
        check(omitted.authToken().isEmpty(), "MISSING_AUTH omits auth token");
        check(omitted.bladeAuthToken().isEmpty(), "MISSING_AUTH omits blade auth token");
        check(omitted.identityAvailable(), "MISSING_AUTH remains probeable as UNAUTH");
        check("MISSING_AUTH".equals(omitted.provenance()), "MISSING_AUTH provenance");

        ControlPlaneServer.AuthMaterialized empty =
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
            ControlPlaneServer.materializeAiPocAuth("MISSING_AUTH", null, "blade-token", null);
            throw new AssertionError("MISSING_AUTH must reject non-empty bladeAuthHeader");
        } catch (IllegalArgumentException expected) {
            check("MISSING_AUTH_MUST_OMIT_AUTHORIZATION".equals(expected.getMessage()),
                    "MISSING_AUTH rejects bladeAuthHeader with same code");
        }

        ControlPlaneServer.AuthMaterialized algNone =
                ControlPlaneServer.materializeAiPocAuth("ALG_NONE",
                        "Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.", null);
        check(!algNone.authToken().isBlank(), "ALG_NONE still accepts AI JWT material");
        check(algNone.bladeAuthToken().isEmpty(), "auth-only material does not invent Blade-Auth");
    }

    private static void authAndBladeChannelsMaterializeIndependently() {
        ControlPlaneServer.AuthMaterialized authOnly =
                ControlPlaneServer.materializeAiPocAuth("CUSTOM_POC", "tok-auth", null, null);
        check("tok-auth".equals(authOnly.authToken()) && authOnly.bladeAuthToken().isEmpty(),
                "auth-only PoC leaves bladeAuthToken empty");

        ControlPlaneServer.AuthMaterialized bladeOnly =
                ControlPlaneServer.materializeAiPocAuth("CUSTOM_POC", null, "tok-blade", null);
        check(bladeOnly.authToken().isEmpty() && "tok-blade".equals(bladeOnly.bladeAuthToken()),
                "blade-only PoC leaves authToken empty");

        ControlPlaneServer.AuthMaterialized both =
                ControlPlaneServer.materializeAiPocAuth("CUSTOM_POC", "tok-a", "tok-b", null);
        check("tok-a".equals(both.authToken()) && "tok-b".equals(both.bladeAuthToken()),
                "both channels stay distinct");
    }

    /** Blade DEFAULT_SECRET_HS256 synthesizer dual-writes Authorization + Blade-Auth. */
    private static void defaultSecretHs256DualWritesBladeAuth() {
        ControlPlaneServer.AuthMaterialized mat =
                ControlPlaneServer.materializeAiPocAuth("DEFAULT_SECRET_HS256", null, null, null);
        check(mat.identityAvailable(), "DEFAULT_SECRET_HS256 identity available");
        check(!mat.authToken().isBlank(), "DEFAULT_SECRET_HS256 sets Authorization token");
        check(mat.bladeAuthToken() != null
                        && mat.bladeAuthToken().toLowerCase().startsWith("bearer "),
                "DEFAULT_SECRET_HS256 dual-writes Blade-Auth with bearer scheme");
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
