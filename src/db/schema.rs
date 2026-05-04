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
    pub star_csr_der: Option<Vec<u8>>, // stored CSR DER for reissuance
    // draft-aaron-acme-profiles-01
    pub profile: Option<String>,
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
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LandmarkRow {
    pub id: i64,
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
    pub tree_size: i64,
    pub root_hex: String,
    pub signature: Vec<u8>,
    pub created: i64,
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
}
