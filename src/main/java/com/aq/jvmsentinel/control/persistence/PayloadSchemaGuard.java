package com.aq.jvmsentinel.control.persistence;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Ensures persisted JSON payloads carry {@code schemaVersion >= 1} after V015.
 * Models that omit the field stay unchanged; persistence wraps/unwraps the version.
 */
public final class PayloadSchemaGuard {
    public static final int MIN_SCHEMA_VERSION = 1;

    private PayloadSchemaGuard() {
    }

    public static int requireJsonSchemaVersion(ObjectMapper mapper, String payloadJson, String label) {
        try {
            JsonNode root = mapper.readTree(payloadJson);
            if (root == null || !root.isObject()) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        label + " payload is not a JSON object");
            }
            JsonNode versionNode = root.get("schemaVersion");
            if (versionNode == null || !versionNode.isNumber()
                    || versionNode.asInt() < MIN_SCHEMA_VERSION) {
                throw new SQLiteControlPlanePersistence.PersistenceException(
                        label + " lacks schemaVersion >= " + MIN_SCHEMA_VERSION
                                + "; run V015 migration");
            }
            return versionNode.asInt();
        } catch (SQLiteControlPlanePersistence.PersistenceException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    label + " payload is invalid", failure);
        }
    }

    public static String withSchemaVersion(ObjectMapper mapper, Object value, int schemaVersion) {
        try {
            ObjectNode node = mapper.valueToTree(value);
            node.put("schemaVersion", schemaVersion);
            return mapper.writeValueAsString(node);
        } catch (Exception failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    "could not encode payload with schemaVersion", failure);
        }
    }

    public static <T> T readIgnoringSchemaVersion(ObjectMapper mapper, String payloadJson,
                                                  Class<T> type, String label) {
        requireJsonSchemaVersion(mapper, payloadJson, label);
        try {
            ObjectNode node = (ObjectNode) mapper.readTree(payloadJson);
            node.remove("schemaVersion");
            return mapper.treeToValue(node, type);
        } catch (SQLiteControlPlanePersistence.PersistenceException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    label + " payload could not be decoded", failure);
        }
    }

    public static void requireColumnSchemaVersion(int schemaVersion, String label) {
        if (schemaVersion < MIN_SCHEMA_VERSION) {
            throw new SQLiteControlPlanePersistence.PersistenceException(
                    label + " lacks schemaVersion >= " + MIN_SCHEMA_VERSION
                            + "; run V015 migration");
        }
    }
}
