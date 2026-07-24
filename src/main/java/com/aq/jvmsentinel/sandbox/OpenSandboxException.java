package com.aq.jvmsentinel.sandbox;

/** Sanitized adapter failure. Remote response bodies and credentials are never included in messages. */
public final class OpenSandboxException extends RuntimeException {
    private final String code;
    private final int httpStatus;

    public OpenSandboxException(String code, int httpStatus, String message, Throwable cause) {
        super(message, cause);
        this.code = SandboxContracts.text(code, "code", 128);
        this.httpStatus = httpStatus;
    }

    public String code() { return code; }
    public int httpStatus() { return httpStatus; }

    static OpenSandboxException capability(String detail) {
        return new OpenSandboxException("CAPABILITY_DOWNGRADE", 0, detail, null);
    }

    static OpenSandboxException protocol(String detail, Throwable cause) {
        return new OpenSandboxException("MALFORMED_RESPONSE", 0, detail, cause);
    }
}
