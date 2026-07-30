package com.aq.jvmsentinel.analysis.entry;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 分类 entry protocol，使 unknown / WebSocket 面保持 UNREACHED
 * 而非误标为 HTTP probe target。
 */
public final class NonHttpEntryProtocol {
    private static final Set<String> HTTP_FAMILY = Set.of("HTTP", "HTTPS");
    private static final Set<String> KNOWN_NON_HTTP = Set.of(
            "WEBSOCKET", "WS", "WSS", "GRPC", "RMI", "JMS", "AMQP", "TCP", "UDP");

    private NonHttpEntryProtocol() { }

    public record Classification(String protocol, boolean httpProbeEligible,
                                 String coverageStatus, String reasonCode) {
        public Classification {
            protocol = protocol == null || protocol.isBlank() ? "UNKNOWN" : protocol.toUpperCase(Locale.ROOT);
            coverageStatus = coverageStatus == null ? "UNREACHED" : coverageStatus;
            reasonCode = reasonCode == null ? "" : reasonCode;
            if (httpProbeEligible && !"HTTP".equals(protocol) && !"HTTPS".equals(protocol)) {
                throw new IllegalArgumentException("non-HTTP cannot be probe-eligible");
            }
        }
    }

    public static Classification classify(String protocol) {
        String normalized = protocol == null || protocol.isBlank()
                ? "UNKNOWN" : protocol.trim().toUpperCase(Locale.ROOT);
        if (HTTP_FAMILY.contains(normalized)) {
            return new Classification(normalized, true, "ELIGIBLE", "HTTP_FAMILY");
        }
        if (KNOWN_NON_HTTP.contains(normalized)) {
            return new Classification(normalized, false, "UNREACHED", "NON_HTTP_ADAPTER_STUB");
        }
        return new Classification(normalized, false, "UNREACHED", "UNKNOWN_PROTOCOL");
    }

    public static boolean isHttpProbeEligible(String protocol) {
        return classify(protocol).httpProbeEligible();
    }

    public static String requireHttpOrThrow(String protocol) {
        Classification c = classify(protocol);
        if (!c.httpProbeEligible()) {
            throw new IllegalArgumentException(c.reasonCode());
        }
        return c.protocol();
    }

    public static Set<String> knownNonHttp() {
        return KNOWN_NON_HTTP;
    }
}
