package com.aq.jvmsentinel.analysis.kernel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * 用于 bottom-up effect/guard/sanitizer 传播的有界 method summary。
 * Provenance 为 inference；永非 FACT 升级。
 */
public record MethodSummary(
        String owner,
        String name,
        String descriptor,
        List<String> effects,
        List<String> guards,
        List<String> sanitizers,
        Set<Integer> returnTaintParams,
        List<String> fieldWrites,
        List<String> fieldReads,
        boolean complete,
        List<String> stopReasons) {

    public MethodSummary {
        owner = owner == null ? "" : owner;
        name = name == null ? "" : name;
        descriptor = descriptor == null ? "" : descriptor;
        effects = List.copyOf(effects == null ? List.of() : effects);
        guards = List.copyOf(guards == null ? List.of() : guards);
        sanitizers = List.copyOf(sanitizers == null ? List.of() : sanitizers);
        returnTaintParams = Set.copyOf(returnTaintParams == null ? Set.of() : returnTaintParams);
        fieldWrites = List.copyOf(fieldWrites == null ? List.of() : fieldWrites);
        fieldReads = List.copyOf(fieldReads == null ? List.of() : fieldReads);
        stopReasons = List.copyOf(stopReasons == null ? List.of() : stopReasons);
    }

    public String methodKey() {
        return CfgBuilder.methodIdentity(owner, name, descriptor);
    }

    public ObjectNode toJson(ObjectMapper mapper) {
        Objects.requireNonNull(mapper, "mapper");
        ObjectNode root = mapper.createObjectNode();
        root.put("owner", owner);
        root.put("name", name);
        root.put("descriptor", descriptor);
        root.put("complete", complete);
        root.put("provenance", "KERNEL_INFERENCE");
        putStrings(root.putArray("effects"), effects);
        putStrings(root.putArray("guards"), guards);
        putStrings(root.putArray("sanitizers"), sanitizers);
        putStrings(root.putArray("fieldWrites"), fieldWrites);
        putStrings(root.putArray("fieldReads"), fieldReads);
        ArrayNode returns = root.putArray("returnTaintParams");
        for (Integer param : returnTaintParams) {
            returns.add(param);
        }
        putStrings(root.putArray("stopReasons"), stopReasons);
        return root;
    }

    private static void putStrings(ArrayNode array, List<String> values) {
        for (String value : values) {
            array.add(value);
        }
    }
}
