package com.aq.jvmsentinel.model;

public enum VerificationStatus {
    STATIC_INFERRED,
    DYNAMIC_SUSPECTED,
    /** 恶意 SQL 片段未经过滤到达实际 JDBC/mock statement。 */
    DYNAMIC_CONFIRMED,
    VERIFIED,
    UNREACHED
}
