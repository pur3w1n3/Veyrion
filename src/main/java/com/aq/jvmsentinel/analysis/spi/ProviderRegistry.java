package com.aq.jvmsentinel.analysis.spi;

import com.aq.jvmsentinel.analysis.spi.defaults.DefaultJvmProviders;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Process-local registry of versioned analysis providers.
 * Collect routes all outputs through {@link ProviderOutputGate}.
 */
public final class ProviderRegistry {
    private static final CopyOnWriteArrayList<AnalysisProvider> PROVIDERS = new CopyOnWriteArrayList<>();
    private static final Object LOCK = new Object();
    private static volatile boolean defaultsInstalled;

    private ProviderRegistry() {
    }

    /** Idempotent install of JVM default providers (Spring entry / sinks / AuthCoverage / packs). */
    public static void ensureDefaults() {
        if (defaultsInstalled) return;
        synchronized (LOCK) {
            if (defaultsInstalled) return;
            for (AnalysisProvider provider : DefaultJvmProviders.all()) {
                register(provider);
            }
            defaultsInstalled = true;
        }
    }

    public static void register(AnalysisProvider provider) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(provider.id(), "provider.id");
        if (provider.id().isBlank()) {
            throw new IllegalArgumentException("provider.id must not be blank");
        }
        PROVIDERS.removeIf(existing -> existing.id().equals(provider.id()));
        PROVIDERS.add(provider);
    }

    /**
     * Unregisters a provider. Only contributions from its {@link AnalysisProvider#declaredScope()}
     * disappear on the next {@link #collect(ProviderContext)}; other providers are unaffected.
     */
    public static boolean unregister(AnalysisProvider provider) {
        if (provider == null) return false;
        return PROVIDERS.removeIf(existing -> existing.id().equals(provider.id()));
    }

    public static boolean unregisterById(String providerId) {
        if (providerId == null || providerId.isBlank()) return false;
        return PROVIDERS.removeIf(existing -> existing.id().equals(providerId));
    }

    public static List<AnalysisProvider> all() {
        ensureDefaults();
        return List.copyOf(PROVIDERS);
    }

    public static List<AnalysisProvider> byKind(ProviderKind kind) {
        ensureDefaults();
        List<AnalysisProvider> matched = new ArrayList<>();
        for (AnalysisProvider provider : PROVIDERS) {
            if (provider.kinds().contains(kind)) matched.add(provider);
        }
        return List.copyOf(matched);
    }

    /**
     * Collect contributions from all registered providers, gated by schema/scope/budget/dedupe.
     * Providers cannot write Findings; status elevation is clamped/rejected.
     */
    public static ProviderBundle collect(ProviderContext context) {
        Objects.requireNonNull(context, "context");
        ensureDefaults();
        ProviderOutputGate gate = new ProviderOutputGate(context);
        for (AnalysisProvider provider : PROVIDERS) {
            try {
                contribute(provider, context, gate);
            } catch (RuntimeException ex) {
                gate.rejectForbidden("provider-error:" + provider.id() + ":"
                        + ex.getClass().getSimpleName());
            }
        }
        return gate.build();
    }

    private static void contribute(AnalysisProvider provider, ProviderContext context,
                                   ProviderOutputGate gate) {
        if (provider instanceof ArtifactProvider p) {
            for (ProviderContribution.ArtifactNodes item : nullToEmpty(p.contributeArtifacts(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptArtifacts(item);
                }
            }
        }
        if (provider instanceof EntryProvider p) {
            for (ProviderContribution.Entry item : nullToEmpty(p.contributeEntries(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptEntry(item);
                }
            }
        }
        if (provider instanceof TrustBoundaryProvider p) {
            for (ProviderContribution.TrustBoundary item
                    : nullToEmpty(p.contributeTrustBoundaries(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptTrustBoundary(item);
                }
            }
        }
        if (provider instanceof EffectModelProvider p) {
            for (ProviderContribution.Effect item : nullToEmpty(p.contributeEffects(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptEffect(item);
                }
            }
        }
        if (provider instanceof GuardModelProvider p) {
            for (ProviderContribution.Guard item : nullToEmpty(p.contributeGuards(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptGuard(item);
                }
            }
        }
        if (provider instanceof SanitizerModelProvider p) {
            for (ProviderContribution.Sanitizer item : nullToEmpty(p.contributeSanitizers(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptSanitizer(item);
                }
            }
        }
        if (provider instanceof MethodSummaryProvider p) {
            for (ProviderContribution.MethodSummary item
                    : nullToEmpty(p.contributeMethodSummaries(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptMethodSummary(item);
                }
            }
        }
        if (provider instanceof DetectorProvider p) {
            for (ProviderContribution.Detector item : nullToEmpty(p.contributeDetectors(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptDetector(item);
                }
            }
        }
        if (provider instanceof DynamicProbeProvider p) {
            for (ProviderContribution.DynamicProbe item : nullToEmpty(p.contributeProbes(context))) {
                if (owned(provider, item.providerId(), item.declaredScope(), gate)) {
                    gate.acceptProbe(item);
                }
            }
        }
    }

    private static boolean owned(AnalysisProvider provider, String contributionProviderId,
                                 String declaredScope, ProviderOutputGate gate) {
        if (!provider.id().equals(contributionProviderId)
                || !provider.declaredScope().equals(declaredScope)) {
            gate.rejectForbidden("provider-identity-mismatch:" + provider.id());
            return false;
        }
        return true;
    }
    private static <T> List<T> nullToEmpty(List<T> values) {
        return values == null ? List.of() : values;
    }

    /** Test helper: wipe registry and reinstall defaults. */
    public static void resetForTests() {
        synchronized (LOCK) {
            PROVIDERS.clear();
            defaultsInstalled = false;
        }
        ensureDefaults();
    }

    public static Set<String> providerIds() {
        ensureDefaults();
        Set<String> ids = new LinkedHashSet<>();
        for (AnalysisProvider provider : PROVIDERS) {
            ids.add(provider.id());
        }
        return Set.copyOf(ids);
    }
}
