package com.aq.jvmsentinel.domain.pathdebug;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * World Pack manifest: profile/env/license/files/schema/seed/dependency stubs (P0-21).
 */
public record WorldPackManifest(
        int schemaVersion,
        String worldPackId,
        String profileId,
        WorldPackDependencyMode dependencyMode,
        Map<String, String> env,
        Map<String, String> systemProperties,
        List<String> licenseMaterials,
        List<String> fileMaterials,
        List<String> schemaSeeds,
        List<String> dependencyStubs,
        List<String> missingMaterialGaps
) {
    public static final int SCHEMA_VERSION = 1;
    public static final String PRODUCER = "world-pack-planner/0.1";

    public WorldPackManifest {
        if (schemaVersion != SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported WorldPack schemaVersion=" + schemaVersion);
        }
        Objects.requireNonNull(worldPackId, "worldPackId");
        if (worldPackId.isBlank()) {
            throw new IllegalArgumentException("worldPackId must not be blank");
        }
        Objects.requireNonNull(dependencyMode, "dependencyMode");
        profileId = profileId == null || profileId.isBlank() ? "default" : profileId.trim();
        env = Map.copyOf(env == null ? Map.of() : env);
        systemProperties = Map.copyOf(systemProperties == null ? Map.of() : systemProperties);
        licenseMaterials = List.copyOf(licenseMaterials == null ? List.of() : licenseMaterials);
        fileMaterials = List.copyOf(fileMaterials == null ? List.of() : fileMaterials);
        schemaSeeds = List.copyOf(schemaSeeds == null ? List.of() : schemaSeeds);
        dependencyStubs = List.copyOf(dependencyStubs == null ? List.of() : dependencyStubs);
        missingMaterialGaps = List.copyOf(missingMaterialGaps == null ? List.of() : missingMaterialGaps);
    }

    public static WorldPackManifest minimalMockContinue(String worldPackId) {
        return new WorldPackManifest(
                SCHEMA_VERSION,
                worldPackId,
                "default",
                WorldPackDependencyMode.MOCK_CONTINUE,
                Map.of(),
                Map.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of("JDBC_STUB", "REDIS_STUB", "MYSQL_STUB"),
                List.of());
    }

    public static WorldPackManifest observeFail(String worldPackId, List<String> gaps) {
        return new WorldPackManifest(
                SCHEMA_VERSION,
                worldPackId,
                "default",
                WorldPackDependencyMode.OBSERVE_FAIL,
                Map.of(),
                Map.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                gaps == null ? List.of() : gaps);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("schemaVersion", schemaVersion);
        map.put("worldPackId", worldPackId);
        map.put("profileId", profileId);
        map.put("dependencyMode", dependencyMode.name());
        map.put("env", new LinkedHashMap<>(env));
        map.put("systemProperties", new LinkedHashMap<>(systemProperties));
        map.put("licenseMaterials", new ArrayList<>(licenseMaterials));
        map.put("fileMaterials", new ArrayList<>(fileMaterials));
        map.put("schemaSeeds", new ArrayList<>(schemaSeeds));
        map.put("dependencyStubs", new ArrayList<>(dependencyStubs));
        map.put("missingMaterialGaps", new ArrayList<>(missingMaterialGaps));
        map.put("producer", PRODUCER);
        return map;
    }

    @SuppressWarnings("unchecked")
    public static WorldPackManifest fromMap(Map<String, Object> map) {
        Objects.requireNonNull(map, "map");
        int version = map.get("schemaVersion") instanceof Number n ? n.intValue() : SCHEMA_VERSION;
        return new WorldPackManifest(
                version,
                string(map.get("worldPackId")),
                string(map.get("profileId")),
                WorldPackDependencyMode.parseOrDefault(string(map.get("dependencyMode"))),
                stringMap(map.get("env")),
                stringMap(map.get("systemProperties")),
                stringList(map.get("licenseMaterials")),
                stringList(map.get("fileMaterials")),
                stringList(map.get("schemaSeeds")),
                stringList(map.get("dependencyStubs")),
                stringList(map.get("missingMaterialGaps")));
    }

    private static String string(Object value) {
        return value == null ? "" : value.toString().trim();
    }

    private static List<String> stringList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (item != null && !item.toString().isBlank()) {
                out.add(item.toString());
            }
        }
        return out;
    }

    private static Map<String, String> stringMap(Object value) {
        if (!(value instanceof Map<?, ?> map)) {
            return Map.of();
        }
        Map<String, String> out = new LinkedHashMap<>();
        map.forEach((k, v) -> {
            if (k != null && v != null) {
                out.put(k.toString(), v.toString());
            }
        });
        return out;
    }
}
