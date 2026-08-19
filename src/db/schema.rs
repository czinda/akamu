/// Row types that mirror the SQLite schema columns.
///
/// Each struct maps 1-to-1 to a database table and is used to transfer data
/// between the DB layer and the application.  All integer timestamps are Unix
/// epoch seconds stored as `i64`.
/// These are plain data structs used to transfer data between the DB and application layers.

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AccountRow {
    pub id: String,
    pub status: String,
    pub contact: Option<String>, // JSON array string
    pub public_key: Vec<u8>,     // DER-encoded SPKI
    pub jwk_thumbprint: String,
    pub created: i64,
    pub updated: i64,
    /// JSON array of permitted profile IDs, e.g. `'["tls-server","mtc-tls"]'`.
    /// `NULL` / `None` means no restriction — the account may use any profile.
    pub profile_grants: Option<String>,
    /// CA this account is scoped to.  Empty string means server-wide (no CA restriction).
    /// Non-empty only when `server.account_scope = "ca"`.
    pub ca_id: String,
    /// Kerberos principal stored at registration time when the account was created via a
    /// GSSAPI-authenticated EAB key (`eab_keys.bound_principal`).  `None` for accounts
    /// not using GSSAPI EAB.
    pub kerberos_principal: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OrderRow {
    pub id: String,
    pub account_id: String,
    pub status: String,
    pub expires: Option<i64>,
    pub identifiers: String, // JSON [{type,value}]
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub error: Option<String>,
    pub certificate_id: Option<String>,
    pub replaces: Option<String>, // RFC 9773 ARI cert_id of predecessor
    pub created: i64,
    pub updated: i64,
    // RFC 8739 STAR fields
    pub star_start_date: Option<i64>,
    pub star_end_date: Option<i64>,
    pub star_lifetime_secs: Option<i64>,
    pub star_lifetime_adjust_secs: i64, // NOT NULL DEFAULT 0 in schema
    pub star_allow_cert_get: i64,       // 0=false, 1=true
    pub star_canceled_at: Option<i64>,
    /// Stored CSR DER for STAR reissuance and delegation upstream finalization.
    /// For delegation orders with an upstream CA this field is set atomically with
    /// `status='processing'` in `set_processing_with_csr_der`.
    pub star_csr_der: Option<Vec<u8>>,
    // draft-ietf-acme-profiles-01
    pub profile: Option<String>,
    /// CA that will issue / issued the certificate for this order.
    /// Defaults to `'default'` for rows created before the multi-CA migration.
    pub ca_id: String,
    // RFC 9115 delegation fields
    pub delegation_id: Option<String>,
    pub allow_cert_get: i64, // 0/1; non-STAR top-level allow-certificate-get
    pub upstream_order_url: Option<String>,
    pub upstream_cert_url: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthorizationRow {
    pub id: String,
    pub order_id: String,
    pub account_id: String,
    pub status: String,
    pub identifier: String, // JSON {"type":..,"value":..}
    pub expires: Option<i64>,
    pub wildcard: i64,               // 0=false, 1=true
    pub subdomain_auth_allowed: i64, // 0=false, 1=true (RFC 9444)
    pub created: i64,
    pub updated: i64,
    /// CA that owns this authorization.  Empty string means "any CA" for
    /// pre-existing rows created before migration 0014/0013.
    pub ca_id: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChallengeRow {
    pub id: String,
    pub authz_id: String,
    #[sqlx(rename = "type")]
    pub r#type: String,
    pub status: String,
    pub token: String,
    pub validated: Option<i64>,
    pub error: Option<String>,
    pub created: i64,
    pub updated: i64,
    /// base64url token-part1 sent in the RFC 8823 email-reply-00 challenge email.
    #[sqlx(default)]
    pub email_token_part1: Option<String>,
    /// Message-ID of the sent challenge email; matched against In-Reply-To in the response.
    #[sqlx(default)]
    pub email_message_id: Option<String>,
    /// RFC 9447 tkauth-01: authority token type (e.g. `"atc"`).
    #[sqlx(default)]
    pub tkauth_type: Option<String>,
    /// RFC 9447 tkauth-01: Token Authority URL hint in challenge response.
    #[sqlx(default)]
    pub token_authority: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LandmarkRow {
    pub id: i64,
    pub ca_id: String,
    pub sequence_no: i64,
    pub tree_size: i64,
    pub cert_der: Option<Vec<u8>>,
    pub created: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CosignatureRow {
    pub id: i64,
    pub checkpoint_id: i64,
    pub cosigner_url: String,
    pub signature_der: Vec<u8>,
    pub created: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CheckpointRow {
    pub id: i64,
    pub ca_id: String,
    pub tree_size: i64,
    pub root_hex: String,
    pub signature: Vec<u8>,
    pub created: i64,
}

/// Idempotency-cache row for a leaf-append forwarded to this node's MTC
/// writer election. `proof_cbor` is a CBOR-encoded `Vec<Vec<u8>>`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MtcForwardedAppendRow {
    pub leaf_index: i64,
    pub tree_size: i64,
    pub proof_cbor: Vec<u8>,
}

/// Minimal certificate projection for standalone MTC cert construction.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CertForStandalone {
    pub id: String,
    pub der: Vec<u8>,
    pub mtc_log_index: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CertificateRow {
    pub id: String,
    pub order_id: String,
    pub account_id: String,
    pub serial_number: String,
    pub status: String,
    pub der: Vec<u8>,
    pub pem: String,
    pub not_before: i64,
    pub not_after: i64,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<i64>,
    pub mtc_log_index: Option<i64>,
    pub created: i64,
    pub suggested_window_start: Option<i64>,
    pub suggested_window_end: Option<i64>,
    pub replaced_by: Option<String>, // RFC 9773: order_id that replaced this cert
    pub subject_dn: Option<String>,  // RFC 4514 subject DN string (FAU_SCR_EXT.1)
    /// CA that issued this certificate.
    /// Defaults to `'default'` for rows created before the multi-CA migration.
    pub ca_id: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CrossCertRow {
    pub id: String,
    /// CA that signed this cross-certificate.
    pub issuer_ca_id: String,
    /// akamu CA ID of the subject CA, or `None` if the subject is an external CA.
    pub subject_ca_id: Option<String>,
    /// RFC 4514 subject DN string.
    pub subject_dn: String,
    /// DER-encoded SubjectPublicKeyInfo of the subject CA key.
    pub subject_spki: Vec<u8>,
    /// DER-encoded cross-certificate.
    pub cross_cert_der: Vec<u8>,
    /// PEM-encoded cross-certificate for download.
    pub cross_cert_pem: String,
    pub not_before: i64,
    pub not_after: i64,
    /// Hex-encoded serial number (same format as `certificates.serial_number`).
    pub serial_number: String,
    pub created: i64,
}

/// Minimal projection used by CRL generation — avoids loading DER/PEM blobs.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CrlEntry {
    pub serial_number: String,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<i64>,
}

/// MTC revoked range: a contiguous range of log entry indices marked as revoked (§5.6).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RevokedRangeRow {
    pub id: i64,
    pub ca_id: String,
    pub range_start: i64,
    pub range_end: i64,
    pub created: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PolicyRuleRow {
    pub id: String,
    pub scope: String,
    pub name: String,
    pub rule_json: String,
    /// Stored as `i64` for SQLite compatibility (no native boolean type).
    /// CRDT layer uses `bool`; convert with `i64::from(b)` / `v != 0`.
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: Option<String>,
}

/// RFC 9115 delegation configuration object (NDC-facing).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DelegationRow {
    pub id: String,
    pub account_id: String,
    pub csr_template: String,      // JSON per RFC 9115 §4
    pub cname_map: Option<String>, // JSON {fqdn: fqdn}, nullable
    pub created: i64,
    pub updated: i64,
}
