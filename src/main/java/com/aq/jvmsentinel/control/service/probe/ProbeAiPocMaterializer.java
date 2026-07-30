package com.aq.jvmsentinel.control.service.probe;

import com.aq.jvmsentinel.analysis.identity.SyntheticIdentityService;
import com.aq.jvmsentinel.model.AuthBypassCandidate;
import com.aq.jvmsentinel.model.AuthBypassTechnique;
import com.aq.jvmsentinel.model.IdentityTrack;

import java.nio.file.Path;
import java.util.Optional;

/** AI PoC 授权 material 合成（MISSING_AUTH / technique synthesizer）。 */
public final class ProbeAiPocMaterializer {
    private ProbeAiPocMaterializer() {
    }

    /**
     * 供验收测试使用：MISSING_AUTH / AI PoC materialization。
     * {@code bladeAuthToken} 为 secondary auth 通道 token（已弃用 wire 名；语义为 {@code secondaryAuthToken}）。
     */
    public record AuthMaterialized(IdentityTrack track, String authToken, String bladeAuthToken,
                                   String provenance, boolean identityAvailable) {
        public AuthMaterialized(IdentityTrack track, String authToken, String provenance) {
            this(track, authToken, "", provenance, true);
        }

        /** secondary auth 通道 token 的通用别名。 */
        public String secondaryAuthToken() {
            return bladeAuthToken == null ? "" : bladeAuthToken;
        }
    }

    public static AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, Path artifactPath) {
        return materializeAiPocAuth(techniqueId, authorizationHeader, null, artifactPath);
    }

    public static AuthMaterialized materializeAiPocAuth(
            String techniqueId, String authorizationHeader, String bladeAuthHeader, Path artifactPath) {
        Optional<AuthBypassTechnique> technique = AuthBypassTechnique.tryParse(techniqueId);
        String secondaryToken = ProbeWireHelpers.normalizeProbeToken(bladeAuthHeader);
        if (!secondaryToken.isEmpty()) {
            AuthBypassCandidate.validateAuthMaterialOnly(bladeAuthHeader);
        }
        // MISSING_AUTH 为刻意未认证探针：绝不伪造 Bearer / secondary auth。
        if (technique.isPresent() && technique.get() == AuthBypassTechnique.MISSING_AUTH) {
            if ((authorizationHeader != null && !authorizationHeader.isBlank()) || !secondaryToken.isEmpty()) {
                throw new IllegalArgumentException("MISSING_AUTH_MUST_OMIT_AUTHORIZATION");
            }
            return new AuthMaterialized(IdentityTrack.UNAUTH, "", "", "MISSING_AUTH", true);
        }
        boolean hasAuth = authorizationHeader != null && !authorizationHeader.isBlank();
        if (hasAuth || !secondaryToken.isEmpty()) {
            String authToken = "";
            if (hasAuth) {
                AuthBypassCandidate.validateAuthMaterialOnly(authorizationHeader);
                authToken = ProbeWireHelpers.normalizeProbeToken(authorizationHeader);
            }
            // AI 编写的 DEFAULT_SECRET_HS256：harvest 指示时可双写 secondary 通道。
            if (secondaryToken.isEmpty()
                    && technique.isPresent()
                    && technique.get() == AuthBypassTechnique.DEFAULT_SECRET_HS256
                    && !authToken.isBlank()
                    && artifactPath != null) {
                SyntheticIdentityService.MaterialBundle harvested =
                        new SyntheticIdentityService().harvest(artifactPath);
                if (harvested.preferSecondaryAuthHeader() || harvested.multiHeaderAuthSurface()) {
                    secondaryToken = SyntheticIdentityService.secondaryAuthHeaderValue(authToken);
                }
            } else if (secondaryToken.isEmpty()
                    && technique.isPresent()
                    && technique.get() == AuthBypassTechnique.DEFAULT_SECRET_HS256
                    && !authToken.isBlank()) {
                // 无 artifact 上下文：仅保留 Authorization（通用默认）。
            }
            IdentityTrack track = technique
                    .map(AuthBypassTechnique::defaultTrack)
                    .orElse(IdentityTrack.BYPASS_CANDIDATE);
            return new AuthMaterialized(track, authToken, secondaryToken, "AI_POC", true);
        }
        if (technique.isEmpty() || technique.get() == AuthBypassTechnique.CUSTOM_POC) {
            return new AuthMaterialized(IdentityTrack.BYPASS_CANDIDATE, "", "", "AI_POC_NO_MATERIAL", true);
        }
        SyntheticIdentityService identity = new SyntheticIdentityService();
        SyntheticIdentityService.MaterialBundle materials = identity.harvest(artifactPath);
        SyntheticIdentityService.SyntheticIdentity synth =
                identity.synthesizeTechnique(technique.get(), materials);
        if (!synth.available()) {
            return new AuthMaterialized(technique.get().defaultTrack(), "", "",
                    synth.precondition(), false);
        }
        String token = ProbeWireHelpers.normalizeProbeToken(synth.authorizationHeader());
        String secondary = "";
        if (!token.isBlank() && (technique.get() == AuthBypassTechnique.DEFAULT_SECRET_HS256
                && (materials.preferSecondaryAuthHeader() || materials.multiHeaderAuthSurface()))) {
            secondary = SyntheticIdentityService.secondaryAuthHeaderValue(token);
        }
        // ALG_NONE / EMPTY_BEARER：除非 AI 提供 secondary auth，否则通道保持独立。
        if (technique.get() == AuthBypassTechnique.ALG_NONE
                || technique.get() == AuthBypassTechnique.EMPTY_BEARER) {
            secondary = "";
        }
        return new AuthMaterialized(synth.track(), token, secondary, synth.provenance(), true);
    }
}
