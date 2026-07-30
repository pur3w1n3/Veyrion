package com.aq.jvmsentinel.analysis.identity;

/**
 * 中性 identity-material kind。Framework 名永非必填 field —
 * adapter/harvester 仅在 provenance note 引用。
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
