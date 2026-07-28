package com.aq.jvmsentinel.analysis.spi.entry;

import com.aq.jvmsentinel.analysis.spi.EntryProvider;
import com.aq.jvmsentinel.analysis.spi.ProviderContext;
import com.aq.jvmsentinel.analysis.spi.ProviderContribution;
import com.aq.jvmsentinel.analysis.spi.ProviderKind;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** P2 scaffolding EntryProvider for WebSocket and RPC entry surfaces. */
public final class WebSocketRpcEntryProvider implements EntryProvider {
    public static final String ID = "skeleton-websocket-rpc-entry";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String providerVersion() {
        return "skeleton-websocket-rpc-entry/0.1-scaffolding";
    }

    @Override
    public Set<ProviderKind> kinds() {
        return EnumSet.of(ProviderKind.ENTRY);
    }

    @Override
    public List<ProviderContribution.Entry> contributeEntries(ProviderContext context) {
        List<ProviderContribution.Entry> out = new ArrayList<>();
        out.addAll(SkeletonEntrySupport.fromClassMatches(
                context, id(), declaredScope(), "WEBSOCKET",
                clazz -> SkeletonEntrySupport.implementsAny(clazz,
                        "org/springframework/web/socket/WebSocketHandler",
                        "javax/websocket/Endpoint",
                        "jakarta/websocket/Endpoint")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "WebSocket"),
                "websocket:"));
        out.addAll(SkeletonEntrySupport.fromClassMatches(
                context, id(), declaredScope(), "RPC",
                clazz -> SkeletonEntrySupport.implementsAny(clazz,
                        "io/grpc/BindableService")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "Grpc")
                        || SkeletonEntrySupport.classNameHint(clazz.className(), "Rpc"),
                "rpc:"));
        return List.copyOf(out);
    }
}
