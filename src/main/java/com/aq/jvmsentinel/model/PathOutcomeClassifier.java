package com.aq.jvmsentinel.model;

import java.util.Locale;
import java.util.Set;

/** Maps HTTP/transport probe signals to the minimum PathOutcomeClass taxonomy. */
public final class PathOutcomeClassifier {
    private static final Set<String> TRANSPORT = Set.of(
            "ConnectException", "SocketException", "SocketTimeoutException",
            "NoRouteToHostException", "UnknownHostException", "EOFException",
            "ConnectionReset", "BrokenPipe");

    private PathOutcomeClassifier() { }

    public static PathOutcomeClass classify(int httpStatus, String errorClass, String detail) {
        String error = errorClass == null ? "" : errorClass;
        String text = detail == null ? "" : detail.toLowerCase(Locale.ROOT);
        if (error.contains("SocketTimeout") || text.contains("read timed out")
                || text.contains("timeout")) {
            if (text.contains("connect")) return PathOutcomeClass.COLD_START;
            return PathOutcomeClass.BUSINESS_TIMEOUT;
        }
        if (TRANSPORT.stream().anyMatch(error::contains)
                || text.contains("connection refused")
                || text.contains("connection reset")) {
            if (text.contains("refused") || error.contains("ConnectException")) {
                return PathOutcomeClass.COLD_START;
            }
            return PathOutcomeClass.TRANSPORT_ERROR;
        }
        if (httpStatus == 401 || httpStatus == 403
                || text.contains("unauthorized") || text.contains("forbidden")
                || text.contains("login") || text.contains("auth")) {
            return PathOutcomeClass.AUTH_CHALLENGE;
        }
        if (httpStatus == 404) return PathOutcomeClass.REACHED_NO_BIND;
        if (httpStatus == 409 || httpStatus == 423 || httpStatus == 429) {
            return PathOutcomeClass.ENGINE_BUSY;
        }
        if (httpStatus == 500 || httpStatus == 502 || httpStatus == 503) {
            if (text.contains("table") || text.contains("sql") || text.contains("jdbc")
                    || text.contains("redis") || text.contains("mock")) {
                return PathOutcomeClass.DEPENDENCY_MOCK_GAP;
            }
            return PathOutcomeClass.ENGINE_BUSY;
        }
        if (httpStatus >= 200 && httpStatus < 500) return PathOutcomeClass.HTTP_OBSERVED;
        if (httpStatus < 0) return PathOutcomeClass.UNKNOWN;
        return PathOutcomeClass.UNKNOWN;
    }
}
