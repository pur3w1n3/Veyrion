package com.aq.jvmsentinel.analysis.spi.entry;

import com.aq.jvmsentinel.analysis.spi.EntryProvider;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderKind;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** P2 scaffolding EntryProvider for message / queue listeners. */
public final class MessageListenerEntryProvider implements EntryProvider {
    public static final String ID = "skeleton-message-listener-entry";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String providerVersion() {
        return "skeleton-message-listener-entry/0.1-scaffolding";
    }

    @Override
    public Set<ProviderKind> kinds() {
        return EnumSet.of(ProviderKind.ENTRY);
    }

    @Override
    public List<ProviderContribution.Entry> contributeEntries(ProviderContext context) {
        List<ProviderContribution.Entry> out = new ArrayList<>();
        out.addAll(SkeletonEntrySupport.fromClassMatches(
                context, id(), declaredScope(), "MESSAGE",
                clazz -> SkeletonEntrySupport.implementsAny(clazz,
                        "javax/jms/MessageListener",
                        "jakarta/jms/MessageListener",
                        "org/springframework/amqp/core/MessageListener")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "MessageListener")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "P2FixtureListener"),
                "listener:"));
        out.addAll(SkeletonEntrySupport.fromMethodMatches(
                context, id(), declaredScope(), "MESSAGE",
                method -> SkeletonEntrySupport.methodNameHint(method,
                        "onmessage", "kafkalistener", "jmslistener", "rabbitlistener"),
                "listener-method:"));
        return List.copyOf(out);
    }
}
