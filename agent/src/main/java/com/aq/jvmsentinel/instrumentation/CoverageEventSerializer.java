package com.aq.jvmsentinel.instrumentation;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Encodes branch hits without exceeding EventWriter's 256-character detail value limit. */
final class CoverageEventSerializer {
    private static final int MAX_DETAIL_VALUE_LENGTH = 256;

    private CoverageEventSerializer() {
    }

    static List<Map<String, String>> serialize(String className, String methodDescriptor, BitSet hits) {
        if (hits == null || hits.isEmpty()) return List.of();

        List<String> hitChunks = encodeHitChunks(hits);
        List<Map<String, String>> events = new ArrayList<>(hitChunks.size());
        for (int index = 0; index < hitChunks.size(); index++) {
            Map<String, String> detail = new LinkedHashMap<>();
            detail.put("captureMode", "JVM_BRANCH_SITE");
            detail.put("encoding", "COMMA_SEPARATED_HIT_INDICES");
            detail.put("classname", truncate(className));
            detail.put("methodDesc", truncate(methodDescriptor));
            detail.put("hits", hitChunks.get(index));
            if (hitChunks.size() > 1) {
                detail.put("chunk", (index + 1) + "/" + hitChunks.size());
            }
            events.add(Map.copyOf(detail));
        }
        return List.copyOf(events);
    }

    private static List<String> encodeHitChunks(BitSet hits) {
        List<String> chunks = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int hit = hits.nextSetBit(0); hit >= 0; hit = hits.nextSetBit(hit + 1)) {
            String encoded = Integer.toString(hit);
            int additional = encoded.length() + (current.isEmpty() ? 0 : 1);
            if (!current.isEmpty() && current.length() + additional > MAX_DETAIL_VALUE_LENGTH) {
                chunks.add(current.toString());
                current.setLength(0);
            }
            if (!current.isEmpty()) current.append(',');
            current.append(encoded);
            if (hit == Integer.MAX_VALUE) break;
        }
        if (!current.isEmpty()) chunks.add(current.toString());
        return chunks;
    }

    private static String truncate(String value) {
        if (value == null) return "";
        return value.length() <= MAX_DETAIL_VALUE_LENGTH
                ? value
                : value.substring(0, MAX_DETAIL_VALUE_LENGTH);
    }
}
