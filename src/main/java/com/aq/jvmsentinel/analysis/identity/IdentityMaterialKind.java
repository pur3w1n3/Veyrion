package com.aq.jvmsentinel.analysis.identity;

/**
 * Neutral identity-material kinds. Framework names are never required fields —
 * adapters/harvesters may cite them only in provenance notes.
 */
public enum IdentityMaterialKind {
    /** Symmetric/HMAC signing material usable for BEARER minting. */
    SIGNING_KEY,
    /** Cookie-channel session / remember-me material (key or cookie name). */
    SESSION_COOKIE,
    /** Login form path hint (not applied as a probe credential this round). */
    LOGIN_FORM,
    /** Pre-minted or template bearer token material. */
    BEARER_TOKEN,
    /** Symmetric cipher key for cookie encryption surfaces (not a JWT secret). */
    CIPHER_KEY
}
