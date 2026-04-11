/// Row types that mirror the SQLite schema columns.
/// These are plain data structs used to transfer data between the DB and application layers.

#[derive(Debug, Clone)]
pub struct AccountRow {
    pub id: String,
    pub status: String,
    pub contact: Option<String>, // JSON array string
    pub public_key: Vec<u8>,     // DER-encoded SPKI
    pub jwk_thumbprint: String,
    pub created: i64,
    pub updated: i64,
}

#[derive(Debug, Clone)]
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
    pub star_lifetime_adjust_secs: i64, // default 0
    pub star_allow_cert_get: bool,
    pub star_canceled_at: Option<i64>,
    pub star_csr_der: Option<Vec<u8>>, // stored CSR DER for reissuance
    // draft-aaron-acme-profiles-01
    pub profile: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationRow {
    pub id: String,
    pub order_id: String,
    pub account_id: String,
    pub status: String,
    pub identifier: String, // JSON {"type":..,"value":..}
    pub expires: Option<i64>,
    pub wildcard: bool,
    pub subdomain_auth_allowed: bool,
    pub created: i64,
    pub updated: i64,
}

#[derive(Debug, Clone)]
pub struct ChallengeRow {
    pub id: String,
    pub authz_id: String,
    pub r#type: String,
    pub status: String,
    pub token: String,
    pub validated: Option<i64>,
    pub error: Option<String>,
    pub created: i64,
    pub updated: i64,
}

#[derive(Debug, Clone)]
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
}
