package com.aq.jvmsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 说明：P0-14：public schema registry fixture + TS/Java consumer field drift 检查。
 * 使用轻量 hand validator（无新 JSON Schema 依赖）。
 */
public final class SchemaContractAcceptanceTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final AtomicInteger ASSERTIONS = new AtomicInteger();

    private static final Set<String> FINDING_REQUIRED = Set.of(
            "schemaVersion", "projectId", "artifactDigest", "scanId", "findingId", "title",
            "severity", "verificationStatus", "entrypointId", "entry", "sinkId", "sink",
            "dependency", "dependencyMode", "evidenceCount", "confidence");
    private static final Set<String> FINDING_OPTIONAL = Set.of(
            "dependencyRefs", "evidenceRefs", "rootCause", "hypothesisId", "securityProperty",
            "extensions");
    private static final Set<String> FINDING_CLOSED_STATUS = Set.of(
            "STATIC_INFERRED", "DYNAMIC_SUSPECTED", "DYNAMIC_CONFIRMED", "VERIFIED", "UNREACHED");
    private static final Set<String> OPEN_KIND_FIELDS = Set.of("family", "kind");

    public static void main(String[] args) throws Exception {
        AcceptanceAssertions.reset();
        ASSERTIONS.set(0);
        Path root = projectRoot();
        Path schemas = root.resolve("contracts/schemas");
        Path fixtures = root.resolve("contracts/fixtures");

        check(Files.isDirectory(schemas), "contracts/schemas registry exists");
        check(Files.isRegularFile(schemas.resolve("api/finding.v1.json")), "finding.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("domain/security-hypothesis.v1.json")),
                "security-hypothesis.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("domain/coverage-matrix.v1.json")),
                "coverage-matrix.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("domain/evidence-graph.v1.json")),
                "evidence-graph.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("domain/provider-bundle.v1.json")),
                "provider-bundle.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("worker/runtime-observation.v1.json")),
                "runtime-observation.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("analyzer/capability-negotiation.v1.json")),
                "analyzer capability-negotiation.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("analyzer/ir-chunk.v1.json")),
                "analyzer ir-chunk.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("analyzer/analyzer-result.v1.json")),
                "analyzer analyzer-result.v1 schema present");
        check(Files.isRegularFile(schemas.resolve("runtime/run-profile.v1.json")),
                "runtime run-profile.v1 schema present");
        check(Files.isRegularFile(root.resolve("contracts/README.md")), "contracts README present");

        JsonNode findingSchema = readJson(schemas.resolve("api/finding.v1.json"));
        assertSchemaDeclares(findingSchema, FINDING_REQUIRED, FINDING_OPTIONAL);

        validateExpectOk(findingSchema, fixtures.resolve("finding.valid.json"), "finding.valid");
        validateExpectFail(findingSchema, fixtures.resolve("finding.missing-required.json"),
                "finding.missing-required", "MISSING_REQUIRED");
        validateExpectFail(findingSchema, fixtures.resolve("finding.unknown-status.json"),
                "finding.unknown-status", "UNKNOWN_CLOSED_ENUM");

        JsonNode hypothesisSchema = readJson(schemas.resolve("domain/security-hypothesis.v1.json"));
        validateExpectOk(hypothesisSchema, fixtures.resolve("security-hypothesis.valid.json"),
                "hypothesis.valid");
        validateExpectOk(hypothesisSchema, fixtures.resolve("security-hypothesis.unknown-family.json"),
                "hypothesis.unknown-family allowed");

        JsonNode coverageSchema = readJson(schemas.resolve("domain/coverage-matrix.v1.json"));
        validateExpectOk(coverageSchema, fixtures.resolve("coverage-matrix.valid.json"),
                "coverage-matrix.valid");
        assertCoverageWireFixture(readJson(fixtures.resolve("coverage-matrix.valid.json")));

        JsonNode evidenceGraphSchema = readJson(schemas.resolve("domain/evidence-graph.v1.json"));
        validateExpectOk(evidenceGraphSchema, fixtures.resolve("evidence-graph.valid.json"),
                "evidence-graph.valid");

        JsonNode observationSchema = readJson(schemas.resolve("worker/runtime-observation.v1.json"));
        validateExpectOk(observationSchema, fixtures.resolve("runtime-observation.valid.json"),
                "runtime-observation.valid");
        validateExpectOk(observationSchema, fixtures.resolve("runtime-observation.unknown-kind.json"),
                "runtime-observation.unknown-kind allowed");

        JsonNode analyzerResultSchema = readJson(schemas.resolve("analyzer/analyzer-result.v1.json"));
        validateExpectOk(analyzerResultSchema, fixtures.resolve("analyzer-result.valid.json"),
                "analyzer-result.valid");
        JsonNode runProfileSchema = readJson(schemas.resolve("runtime/run-profile.v1.json"));
        validateExpectOk(runProfileSchema, fixtures.resolve("runtime-run-profile.valid.json"),
                "runtime-run-profile.valid");

        assertTypeScriptFindingFields(root.resolve("frontend/src/api.ts"));
        assertJavaFindingDtoFields(root.resolve(
                "src/main/java/com/aq/jvmsentinel/control/ApiDtos.java"));
        assertGeneratedContractTypes(root, findingSchema, hypothesisSchema, coverageSchema);

        System.out.println("SchemaContractAcceptanceTest: PASS ("
                + Math.max(ASSERTIONS.get(), AcceptanceAssertions.get()) + " assertions)");
    }

    /** Generated TS field constants must exist and match schema required sets. */
    private static void assertGeneratedContractTypes(
            Path root, JsonNode findingSchema, JsonNode hypothesisSchema, JsonNode coverageSchema)
            throws Exception {
        Path generated = root.resolve("frontend/src/generated/contracts.ts");
        check(Files.isRegularFile(generated), "frontend/src/generated/contracts.ts exists");
        String source = Files.readString(generated, StandardCharsets.UTF_8);
        check(source.contains("GENERATED FILE"), "generated contracts header present");
        check(source.contains("export const FindingRequiredFields"), "FindingRequiredFields exported");
        check(source.contains("export const SecurityHypothesisRequiredFields"),
                "SecurityHypothesisRequiredFields exported");
        check(source.contains("export const CoverageMatrixRequiredFields"),
                "CoverageMatrixRequiredFields exported");

        assertGeneratedRequiredMatchesSchema(source, "FindingRequiredFields", findingSchema);
        assertGeneratedRequiredMatchesSchema(source, "SecurityHypothesisRequiredFields", hypothesisSchema);
        assertGeneratedRequiredMatchesSchema(source, "CoverageMatrixRequiredFields", coverageSchema);
    }

    private static void assertGeneratedRequiredMatchesSchema(
            String source, String constName, JsonNode schema) {
        Set<String> schemaRequired = new LinkedHashSet<>();
        if (schema.path("required").isArray()) {
            for (JsonNode item : schema.get("required")) {
                schemaRequired.add(item.asText());
            }
        }
        Set<String> generated = extractTsConstStringSet(source, constName);
        check(!generated.isEmpty(), constName + " parsed non-empty");
        check(generated.equals(schemaRequired),
                constName + " matches schema required set; generated=" + generated
                        + " schema=" + schemaRequired);
    }

    private static Set<String> extractTsConstStringSet(String source, String constName) {
        Pattern block = Pattern.compile(
                "export\\s+const\\s+" + Pattern.quote(constName)
                        + "\\s*=\\s*\\[([\\s\\S]*?)]\\s*as\\s+const",
                Pattern.MULTILINE);
        Matcher matcher = block.matcher(source);
        check(matcher.find(), "TS const block found for " + constName);
        Set<String> fields = new LinkedHashSet<>();
        Matcher fieldMatch = Pattern.compile("'([^']+)'").matcher(matcher.group(1));
        while (fieldMatch.find()) {
            fields.add(fieldMatch.group(1));
        }
        return fields;
    }

    private static void assertSchemaDeclares(JsonNode schema, Set<String> required, Set<String> optional) {
        Set<String> declaredRequired = new LinkedHashSet<>();
        if (schema.path("required").isArray()) {
            for (JsonNode item : schema.get("required")) {
                declaredRequired.add(item.asText());
            }
        }
        check(declaredRequired.equals(required), "finding schema required set matches contract");
        JsonNode properties = schema.path("properties");
        for (String name : required) {
            check(properties.has(name), "schema properties include required " + name);
        }
        for (String name : optional) {
            check(properties.has(name), "schema properties include optional " + name);
        }
        check(properties.has("hypothesisId") && properties.has("securityProperty"),
                "finding schema exposes optional hypothesisId/securityProperty");
    }

    private static void assertCoverageWireFixture(JsonNode fixture) {
        JsonNode universe = fixture.path("artifactUniverseSummary");
        for (String field : List.of("classCount", "methodCount", "fieldCount", "dependencyCount",
                "incomplete", "note")) {
            check(universe.has(field), "coverage fixture universe matches producer field " + field);
        }
        JsonNode calls = fixture.path("callResolution");
        for (String field : List.of("DIRECT", "CHA", "UNRESOLVED", "unresolvedIsGap")) {
            check(calls.has(field), "coverage fixture callResolution matches producer field " + field);
        }
        JsonNode dynamic = fixture.path("dynamicExperiments");
        for (String field : List.of("pathRunCount", "effectiveAttemptCount", "unreachedCount",
                "stopReasonSamples")) {
            check(dynamic.has(field), "coverage fixture dynamicExperiments matches producer field " + field);
        }
        check(fixture.path("detectors").isArray()
                        && fixture.path("detectors").get(0).has("detectorVersion"),
                "coverage fixture detectors retain detectorVersion");
        check(fixture.path("honestyFlags").path("neverTreatSuccessAsSafe").asBoolean(false)
                        && fixture.path("honestyFlags").path("gapsNeverCountAsCovered").asBoolean(false),
                "coverage fixture retains fail-closed honesty flags");
        check(!fixture.path("gaps").path("countedAsCovered").asBoolean(true),
                "coverage fixture gaps never count as covered");
    }
    private static void validateExpectOk(JsonNode schema, Path fixture, String label) throws Exception {
        List<String> errors = validateAgainstSchema(schema, readJson(fixture));
        check(errors.isEmpty(), label + " fixture validates: " + errors);
    }

    private static void validateExpectFail(JsonNode schema, Path fixture, String label, String code)
            throws Exception {
        List<String> errors = validateAgainstSchema(schema, readJson(fixture));
        check(!errors.isEmpty(), label + " must fail validation");
        check(errors.stream().anyMatch(error -> error.startsWith(code)),
                label + " must report " + code + " but was " + errors);
    }

    /**
     * 最小 object validator：required、closed enum、additionalProperties 与
     * 说明：extension/x-veyrion-* exception 与 open kind/family 字符串。
     */
    static List<String> validateAgainstSchema(JsonNode schema, JsonNode instance) {
        List<String> errors = new ArrayList<>();
        if (!instance.isObject()) {
            errors.add("TYPE: root must be object");
            return errors;
        }
        Set<String> required = new LinkedHashSet<>();
        if (schema.path("required").isArray()) {
            for (JsonNode item : schema.get("required")) {
                required.add(item.asText());
            }
        }
        for (String name : required) {
            if (!instance.has(name) || instance.get(name).isNull()) {
                errors.add("MISSING_REQUIRED:" + name);
            }
        }
        JsonNode properties = schema.path("properties");
        boolean additionalAllowed = schema.path("additionalProperties").asBoolean(true);
        Iterator<String> fieldNames = instance.fieldNames();
        while (fieldNames.hasNext()) {
            String name = fieldNames.next();
            if (properties.has(name)) {
                JsonNode prop = properties.get(name);
                JsonNode value = instance.get(name);
                if ("verificationStatus".equals(name) && value.isTextual()
                        && !FINDING_CLOSED_STATUS.contains(value.asText())) {
                    errors.add("UNKNOWN_CLOSED_ENUM:verificationStatus");
                }
                if ("coverageStatus".equals(name) && prop.path("enum").isArray() && value.isTextual()) {
                    boolean known = false;
                    for (JsonNode allowed : prop.get("enum")) {
                        if (allowed.asText().equals(value.asText())) {
                            known = true;
                            break;
                        }
                    }
                    if (!known) {
                        errors.add("UNKNOWN_CLOSED_ENUM:coverageStatus");
                    }
                }
                if (OPEN_KIND_FIELDS.contains(name) && value.isTextual() && value.asText().isBlank()) {
                    errors.add("BLANK_OPEN_KIND:" + name);
                }
                if ("severity".equals(name) && prop.path("enum").isArray() && value.isTextual()) {
                    boolean known = false;
                    for (JsonNode allowed : prop.get("enum")) {
                        if (allowed.asText().equals(value.asText())) {
                            known = true;
                            break;
                        }
                    }
                    if (!known) {
                        errors.add("UNKNOWN_CLOSED_ENUM:severity");
                    }
                }
                continue;
            }
            if ("extensions".equals(name) || name.startsWith("x-veyrion-")) {
                continue;
            }
            if (!additionalAllowed) {
                errors.add("UNKNOWN_PROPERTY:" + name);
            }
        }
        if ("DATAFLOW".equals(instance.path("family").asText(""))
                && (blank(instance.path("source")) || blank(instance.path("effect")))) {
            errors.add("MISSING_REQUIRED:source|effect");
        }
        return errors;
    }

    private static boolean blank(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull()
                || (node.isTextual() && node.asText().isBlank());
    }

    private static void assertTypeScriptFindingFields(Path apiTs) throws Exception {
        check(Files.isRegularFile(apiTs), "frontend/src/api.ts exists");
        String source = Files.readString(apiTs, StandardCharsets.UTF_8);
        Matcher typeMatch = Pattern.compile(
                "export\\s+type\\s+Finding\\s*=\\s*\\{([\\s\\S]*?)\\n\\}",
                Pattern.MULTILINE).matcher(source);
        check(typeMatch.find(), "export type Finding block found in api.ts");
        String body = typeMatch.group(1);
        Set<String> fields = new LinkedHashSet<>();
        Matcher fieldMatch = Pattern.compile("^\\s*([A-Za-z_][A-Za-z0-9_]*)\\??\\s*:",
                Pattern.MULTILINE).matcher(body);
        while (fieldMatch.find()) {
            fields.add(fieldMatch.group(1));
        }
        check(fields.contains("hypothesisId"), "TS Finding includes hypothesisId");
        check(fields.contains("securityProperty"), "TS Finding includes securityProperty");
        // 共享 wire 名不得与 schema optional/required 集 drift。
        for (String shared : List.of("findingId", "entrypointId", "sinkId", "verificationStatus",
                "evidenceCount", "confidence", "schemaVersion", "projectId", "artifactDigest",
                "scanId", "entry", "sink", "dependency", "dependencyMode", "rootCause",
                "evidenceRefs")) {
            check(fields.contains(shared), "TS Finding includes shared field " + shared);
        }
        check(fields.containsAll(Set.of("hypothesisId", "securityProperty")),
                "TS optional hypothesis fields stay aligned with schema");
    }

    private static void assertJavaFindingDtoFields(Path apiDtos) throws Exception {
        check(Files.isRegularFile(apiDtos), "ApiDtos.java exists");
        String source = Files.readString(apiDtos, StandardCharsets.UTF_8);
        int start = source.indexOf("public record FindingDto");
        check(start >= 0, "FindingDto record present");
        int end = source.indexOf("{", start);
        check(end > start, "FindingDto header parseable");
        String header = source.substring(start, end);
        for (String required : FINDING_REQUIRED) {
            check(header.contains(required), "Java FindingDto declares " + required);
        }
        check(header.contains("hypothesisId") && header.contains("securityProperty"),
                "Java FindingDto declares optional hypothesisId/securityProperty");
    }

    private static JsonNode readJson(Path path) throws Exception {
        return JSON.readTree(Files.readString(path, StandardCharsets.UTF_8));
    }

    public static Path projectRoot() throws Exception {
        Path dir = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
        for (Path cursor = dir; cursor != null; cursor = cursor.getParent()) {
            if (Files.isRegularFile(cursor.resolve("pom.xml"))
                    && Files.isDirectory(cursor.resolve("contracts"))) {
                return cursor;
            }
        }
        throw new IllegalStateException("project root with pom.xml + contracts/ not found from "
                + dir.toString().toLowerCase(Locale.ROOT));
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
        ASSERTIONS.incrementAndGet();
        AcceptanceAssertions.record();
    }
}
