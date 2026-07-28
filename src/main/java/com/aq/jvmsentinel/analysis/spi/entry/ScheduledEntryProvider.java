package com.aq.jvmsentinel.analysis.spi.entry;

import com.aq.jvmsentinel.analysis.spi.EntryProvider;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderKind;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** P2 scaffolding EntryProvider for scheduled / cron task methods. */
public final class ScheduledEntryProvider implements EntryProvider {
    public static final String ID = "skeleton-scheduled-entry";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String providerVersion() {
        return "skeleton-scheduled-entry/0.1-scaffolding";
    }

    @Override
    public Set<ProviderKind> kinds() {
        return EnumSet.of(ProviderKind.ENTRY);
    }

    @Override
    public List<ProviderContribution.Entry> contributeEntries(ProviderContext context) {
        return SkeletonEntrySupport.fromMethodMatches(
                context, id(), declaredScope(), "SCHEDULED",
                method -> SkeletonEntrySupport.methodNameHint(method,
                        "scheduled", "cron", "fixedrate", "fixeddelay")
                        || SkeletonEntrySupport.classNameHint(method.owner(), "Scheduled"),
                "scheduled:");
    }
}
