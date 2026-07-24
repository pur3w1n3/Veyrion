package com.aq.jvmsentinel.worker;

public enum StopReason {
    USER_CANCELLED,
    BUDGET_EXHAUSTED,
    WALL_CLOCK_TIMEOUT,
    LEASE_EXPIRED,
    POLICY_REJECTED,
    WORKER_FAILURE,
    TRACE_REJECTED,
    COMPLETED
}
