package com.aq.jvmsentinel.model;

public enum VerificationStatus {
    STATIC_INFERRED,
    DYNAMIC_SUSPECTED,
    /** Malicious SQL fragment reached the actual JDBC/mock statement without filtering. */
    DYNAMIC_CONFIRMED,
    VERIFIED,
    UNREACHED
}
