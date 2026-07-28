package com.aq.jvmsentinel.analysis.spi.entry;

import com.aq.jvmsentinel.analysis.spi.EntryProvider;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderKind;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** P2 scaffolding EntryProvider for Spring WebFlux reactive handlers. */
public final class WebFluxEntryProvider implements EntryProvider {
    public static final String ID = "skeleton-webflux-entry";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String providerVersion() {
        return "skeleton-webflux-entry/0.1-scaffolding";
    }

    @Override
    public Set<ProviderKind> kinds() {
        return EnumSet.of(ProviderKind.ENTRY);
    }

    @Override
    public List<ProviderContribution.Entry> contributeEntries(ProviderContext context) {
        return SkeletonEntrySupport.fromClassMatches(
                context, id(), declaredScope(), "WEBFLUX",
                clazz -> SkeletonEntrySupport.implementsAny(clazz,
                        "org/springframework/web/reactive/function/server/HandlerFunction",
                        "org/springframework/web/server/WebFilter")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "WebFlux")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "RouterFunction"),
                "webflux:");
    }
}
