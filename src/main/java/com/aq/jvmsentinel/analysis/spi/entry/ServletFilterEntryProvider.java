package com.aq.jvmsentinel.analysis.spi.entry;

import com.aq.jvmsentinel.analysis.spi.EntryProvider;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderKind;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * P2 scaffolding EntryProvider for Servlet / Filter surfaces.
 * Returns empty when no interface/superclass/fixture class-name hit.
 */
public final class ServletFilterEntryProvider implements EntryProvider {
    public static final String ID = "skeleton-servlet-filter-entry";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String providerVersion() {
        return "skeleton-servlet-filter-entry/0.1-scaffolding";
    }

    @Override
    public Set<ProviderKind> kinds() {
        return EnumSet.of(ProviderKind.ENTRY);
    }

    @Override
    public List<ProviderContribution.Entry> contributeEntries(ProviderContext context) {
        List<ProviderContribution.Entry> out = new ArrayList<>();
        out.addAll(SkeletonEntrySupport.fromClassMatches(
                context, id(), declaredScope(), "SERVLET",
                clazz -> SkeletonEntrySupport.implementsAny(clazz,
                        "javax/servlet/Servlet",
                        "jakarta/servlet/Servlet",
                        "javax/servlet/http/HttpServlet",
                        "jakarta/servlet/http/HttpServlet")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "HttpServlet")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "P2FixtureServlet"),
                "servlet:"));
        out.addAll(SkeletonEntrySupport.fromClassMatches(
                context, id(), declaredScope(), "FILTER",
                clazz -> SkeletonEntrySupport.implementsAny(clazz,
                        "javax/servlet/Filter",
                        "jakarta/servlet/Filter")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "HttpFilter")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "P2FixtureFilter"),
                "filter:"));
        return List.copyOf(out);
    }
}
