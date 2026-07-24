package com.aq.jvmsentinel.worker;

public enum TaskLifecycle {
    QUEUED,
    LEASED,
    RUNNING,
    PAUSED,
    CANCELLED,
    COMPLETED,
    FAILED
}
