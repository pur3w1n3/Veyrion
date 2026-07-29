package com.aq.jvmsentinel.analysis.identity;

/** How an {@link IdentityMaterial} is applied to an HTTP probe. Framework-agnostic. */
public enum AuthChannel {
    HEADER,
    COOKIE,
    BODY
}
