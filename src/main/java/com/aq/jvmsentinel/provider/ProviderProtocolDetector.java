package com.aq.jvmsentinel.provider;

import com.aq.jvmsentinel.provider.ProviderContracts.ProviderKind;
import com.aq.jvmsentinel.provider.ProviderModelInventoryClient.ProtocolProbeOutcome;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * 对候选协议发有界最小探测，按真实响应判定可用 kind。
 * URL/密钥形态仅用于探测顺序，不得单独定论。
 */
public final class ProviderProtocolDetector {
    public static final int SCHEMA_VERSION = 1;
    private static final int MAX_PARALLEL = 2;

    private final ProviderModelInventoryClient client;
    private final Clock clock;

    public ProviderProtocolDetector() {
        this(new ProviderModelInventoryClient(), Clock.systemUTC());
    }

    ProviderProtocolDetector(ProviderModelInventoryClient client, Clock clock) {
        this.client = Objects.requireNonNull(client, "client");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public DetectionResult detect(URI endpoint, byte[] apiKey) {
        Objects.requireNonNull(endpoint, "endpoint");
        byte[] secret = Objects.requireNonNull(apiKey, "apiKey").clone();
        try {
            List<ProviderKind> wireOrder = wireProbeOrder(endpoint);
            List<WireProbe> wireResults = probeWires(endpoint, secret, wireOrder);
            List<KindCandidate> candidates = expandCandidates(endpoint, wireResults);
            List<KindCandidate> viable = candidates.stream().filter(KindCandidate::viable).toList();
            String status;
            ProviderKind recommended = null;
            if (viable.isEmpty()) {
                status = "NONE";
            } else if (viable.size() == 1) {
                status = "UNIQUE";
                recommended = viable.get(0).kind();
            } else {
                status = "MULTIPLE";
                recommended = viable.get(0).kind();
            }
            String hint = null;
            if (viable.isEmpty() && looksLikeAzure(endpoint)) {
                hint = "AZURE_OPENAI_MANUAL";
            }
            return new DetectionResult(SCHEMA_VERSION, clock.instant(), status, recommended,
                    List.copyOf(candidates), hint);
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    private List<WireProbe> probeWires(URI endpoint, byte[] secret, List<ProviderKind> wireOrder) {
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(MAX_PARALLEL, wireOrder.size()),
                runnable -> {
                    Thread thread = new Thread(runnable, "provider-protocol-probe");
                    thread.setDaemon(true);
                    return thread;
                });
        try {
            List<CompletableFuture<WireProbe>> futures = new ArrayList<>();
            for (ProviderKind kind : wireOrder) {
                futures.add(CompletableFuture.supplyAsync(() -> {
                    byte[] copy = secret.clone();
                    try {
                        ProtocolProbeOutcome outcome = client.probe(endpoint, kind, copy);
                        return new WireProbe(kind, outcome);
                    } finally {
                        Arrays.fill(copy, (byte) 0);
                    }
                }, pool));
            }
            List<WireProbe> results = new ArrayList<>(wireOrder.size());
            for (int index = 0; index < futures.size(); index++) {
                CompletableFuture<WireProbe> future = futures.get(index);
                try {
                    results.add(future.get(8, TimeUnit.SECONDS));
                } catch (Exception timeoutOrFailure) {
                    future.cancel(true);
                    results.add(new WireProbe(wireOrder.get(index),
                            ProtocolProbeOutcome.failed("PROBE_TIMEOUT")));
                }
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private static List<KindCandidate> expandCandidates(URI endpoint, List<WireProbe> wireResults) {
        List<KindCandidate> candidates = new ArrayList<>();
        WireProbe openAi = null;
        WireProbe anthropic = null;
        for (WireProbe probe : wireResults) {
            if (probe.kind() == ProviderKind.OPENAI_CHAT) openAi = probe;
            if (probe.kind() == ProviderKind.ANTHROPIC_MESSAGES) anthropic = probe;
        }
        // 按探测顺序展开；OpenAI 线成功时同时给出兼容/本地可选 kind。
        for (WireProbe probe : wireResults) {
            if (probe.kind() == ProviderKind.OPENAI_CHAT) {
                candidates.add(toCandidate(ProviderKind.OPENAI_CHAT, probe.outcome(),
                        "OpenAI Chat /v1/models"));
                if (probe.outcome().viable()) {
                    candidates.add(new KindCandidate(ProviderKind.OPENAI_COMPATIBLE, true,
                            "ACCEPTED_SAME_WIRE",
                            "与 OpenAI Chat 相同 wire；可选旧类型 OpenAI 兼容",
                            probe.outcome().httpStatus()));
                    if (isLoopback(endpoint.getHost())) {
                        candidates.add(new KindCandidate(ProviderKind.LOCAL, true,
                                "ACCEPTED_SAME_WIRE",
                                "本机地址且 OpenAI wire 可用；可选本地（旧类型）",
                                probe.outcome().httpStatus()));
                    }
                } else {
                    candidates.add(new KindCandidate(ProviderKind.OPENAI_COMPATIBLE, false,
                            probe.outcome().reasonCode(),
                            "OpenAI 兼容 wire 探测未通过",
                            nullIfZero(probe.outcome().httpStatus())));
                }
            } else if (probe.kind() == ProviderKind.ANTHROPIC_MESSAGES) {
                candidates.add(toCandidate(ProviderKind.ANTHROPIC_MESSAGES, probe.outcome(),
                        "Anthropic Messages /v1/models"));
            }
        }
        if (looksLikeAzure(endpoint)) {
            boolean anyViable = candidates.stream().anyMatch(KindCandidate::viable);
            candidates.add(new KindCandidate(ProviderKind.AZURE_OPENAI, false,
                    "UNSUPPORTED_PROBE",
                    anyViable
                            ? "Azure OpenAI 无 inventory 探测能力；若目标确为 Azure 请手动选择"
                            : "现有客户端不支持 Azure inventory 探测；可手动选择 Azure OpenAI",
                    null));
        }
        // 保证失败的 wire 也出现在列表（便于 UI 解释），并去重
        if (openAi == null && anthropic == null) {
            return List.copyOf(candidates);
        }
        return List.copyOf(dedupe(candidates));
    }

    private static KindCandidate toCandidate(ProviderKind kind, ProtocolProbeOutcome outcome,
                                             String label) {
        String detail = outcome.viable()
                ? label + " 探测成功（样本模型数 " + outcome.modelSampleCount() + "）"
                : label + " 探测失败：" + outcome.reasonCode();
        return new KindCandidate(kind, outcome.viable(), outcome.reasonCode(), detail,
                nullIfZero(outcome.httpStatus()));
    }

    private static List<KindCandidate> dedupe(List<KindCandidate> candidates) {
        List<KindCandidate> unique = new ArrayList<>();
        for (KindCandidate candidate : candidates) {
            boolean exists = unique.stream().anyMatch(item -> item.kind() == candidate.kind());
            if (!exists) unique.add(candidate);
        }
        return unique;
    }

    /** URL 启发式仅决定探测顺序。 */
    static List<ProviderKind> wireProbeOrder(URI endpoint) {
        String host = hostOf(endpoint);
        String path = pathOf(endpoint);
        boolean anthropicFirst = host.contains("anthropic")
                || path.contains("/messages");
        if (anthropicFirst) {
            return List.of(ProviderKind.ANTHROPIC_MESSAGES, ProviderKind.OPENAI_CHAT);
        }
        return List.of(ProviderKind.OPENAI_CHAT, ProviderKind.ANTHROPIC_MESSAGES);
    }

    static boolean looksLikeAzure(URI endpoint) {
        String host = hostOf(endpoint);
        return host.contains("openai.azure.com") || host.contains("cognitiveservices.azure.com");
    }

    private static String hostOf(URI endpoint) {
        String host = endpoint.getHost();
        return host == null ? "" : host.toLowerCase(Locale.ROOT);
    }

    private static String pathOf(URI endpoint) {
        String path = endpoint.getPath();
        return path == null ? "" : path.toLowerCase(Locale.ROOT);
    }

    private static boolean isLoopback(String host) {
        if (host == null) return false;
        String normalized = host.toLowerCase(Locale.ROOT);
        return "localhost".equals(normalized)
                || "127.0.0.1".equals(normalized)
                || "::1".equals(normalized)
                || "0:0:0:0:0:0:0:1".equals(normalized);
    }

    private static Integer nullIfZero(int httpStatus) {
        return httpStatus == 0 ? null : httpStatus;
    }

    private record WireProbe(ProviderKind kind, ProtocolProbeOutcome outcome) { }

    public record KindCandidate(ProviderKind kind, boolean viable, String reasonCode,
                                String detail, Integer httpStatus) {
        public KindCandidate {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(reasonCode, "reasonCode");
            Objects.requireNonNull(detail, "detail");
            if (detail.length() > 512 || detail.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("detail is invalid");
            }
        }
    }

    public record DetectionResult(int schemaVersion, Instant probedAt, String status,
                                  ProviderKind recommendedKind, List<KindCandidate> candidates,
                                  String hint) {
        public DetectionResult {
            if (schemaVersion != SCHEMA_VERSION) {
                throw new IllegalArgumentException("unsupported schemaVersion");
            }
            Objects.requireNonNull(probedAt, "probedAt");
            Objects.requireNonNull(status, "status");
            if (!status.equals("UNIQUE") && !status.equals("MULTIPLE") && !status.equals("NONE")) {
                throw new IllegalArgumentException("status is invalid");
            }
            candidates = List.copyOf(Objects.requireNonNull(candidates, "candidates"));
            long viableCount = candidates.stream().filter(KindCandidate::viable).count();
            if ("NONE".equals(status)) {
                if (viableCount != 0 || recommendedKind != null) {
                    throw new IllegalArgumentException("NONE status must have no viable kinds");
                }
            } else if ("UNIQUE".equals(status)) {
                if (viableCount != 1 || recommendedKind == null) {
                    throw new IllegalArgumentException("UNIQUE status requires one recommended kind");
                }
            } else if (viableCount < 2 || recommendedKind == null) {
                throw new IllegalArgumentException("MULTIPLE status requires recommendation");
            }
        }
    }
}
