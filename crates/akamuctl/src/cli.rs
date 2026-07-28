use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "akamuctl", about = "akamu server administration CLI")]
pub(crate) struct Cli {
    /// Path to akamuctl.toml config file.
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Server admin URL (overrides config).
    #[arg(long, value_name = "URL")]
    pub server_url: Option<String>,

    /// CA certificate for server TLS verification.
    #[arg(long, value_name = "FILE")]
    pub ca_cert: Option<PathBuf>,

    /// mTLS client certificate file (PEM).
    #[arg(long, value_name = "FILE", conflicts_with = "pkcs12")]
    pub cert: Option<PathBuf>,

    /// mTLS client private key file (PEM).
    #[arg(long, value_name = "FILE", conflicts_with = "pkcs12")]
    pub key: Option<PathBuf>,

    /// PKCS#12 file containing client certificate and private key.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["cert", "key"])]
    pub pkcs12: Option<PathBuf>,

    /// Password for the PKCS#12 file (default: empty).
    /// WARNING: visible in process listings; prefer --pkcs12-password-file.
    #[arg(
        long,
        value_name = "PASSWORD",
        requires = "pkcs12",
        conflicts_with = "pkcs12_password_file"
    )]
    pub pkcs12_password: Option<String>,

    /// Read the PKCS#12 password from FILE (use "-" for stdin).
    #[arg(
        long,
        value_name = "FILE",
        requires = "pkcs12",
        conflicts_with = "pkcs12_password"
    )]
    pub pkcs12_password_file: Option<PathBuf>,

    /// Output format: `table` (default) or `json`.
    #[arg(long, short = 'o', default_value = "table")]
    pub output: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Authenticate and cache session token.
    Login {
        /// Use GSSAPI/Kerberos (Negotiate) instead of mTLS.
        /// The service principal is taken from `[server].gssapi_service` in the
        /// config, or derived automatically as `HTTP@<hostname>` from the server URL.
        /// Requires a valid Kerberos TGT in the ccache (run kinit first).
        #[arg(long)]
        gssapi: bool,
    },
    /// Invalidate current session token.
    Logout,
    /// Print server and cosigner statistics.
    Stats,
    /// Query audit events.
    Audit {
        /// Filter by event type (e.g. cert.issue).
        #[arg(long)]
        r#type: Option<String>,
        /// Filter by subject (JWK thumbprint, serial, account UUID).
        #[arg(long)]
        subject: Option<String>,
        /// Filter from this RFC 3339 timestamp.
        #[arg(long)]
        from: Option<String>,
        /// Filter until this RFC 3339 timestamp.
        #[arg(long)]
        until: Option<String>,
        /// Filter by outcome: `success` or `failure`.
        #[arg(long)]
        outcome: Option<String>,
        /// Maximum number of results (default 100).
        #[arg(long, default_value = "100")]
        limit: u32,
        /// Offset for pagination (default 0).
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Manage operators.
    #[command(subcommand)]
    Operator(OperatorCmd),
    /// Manage EAB keys.
    #[command(subcommand)]
    Eab(EabCmd),
    /// Manage certificates.
    #[command(subcommand)]
    Cert(CertCmd),
    /// Manage accounts.
    #[command(subcommand)]
    Account(AccountCmd),
    /// Manage certificate profiles.
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Manage orders.
    #[command(subcommand)]
    Order(OrderCmd),
    /// Show redacted server configuration.
    ServerConfig,
    /// Revoke a certificate.
    Revoke {
        /// Certificate ID to revoke.
        cert_id: String,
        /// Revocation reason code (default 0 = unspecified).
        #[arg(long, default_value = "0")]
        reason: u8,
    },
    /// Force immediate CRL regeneration.
    CrlForce,
    /// Show cached session identity.
    Whoami,
    /// Cosigner administration.
    #[command(subcommand)]
    Cosigner(CosignerCmd),
    /// Configuration utilities.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Manage CAs (list, show, cert, crl-force, cross-sign).
    #[command(subcommand)]
    Ca(CaCmd),
    /// Manage cross-certificates.
    #[command(subcommand)]
    CrossCert(CrossCertCmd),
    /// Manage RFC 9115 delegation objects.
    #[command(subcommand)]
    Delegation(DelegationCmd),
    /// MTC transparency log queries and actions.
    #[command(subcommand)]
    Mtc(MtcCmd),
    /// Manage issuance policy rules.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// RFC 9447 authority token administration.
    #[command(subcommand)]
    Tkauth(TkauthCmd),
    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
pub(crate) enum TkauthCmd {
    /// Delete expired entries from the JTI replay-prevention cache.
    PruneJti {
        /// Print the count of expired entries without deleting them.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum PolicyCmd {
    /// List active policy rules.
    ListRules {
        /// Filter by scope (default: issuance).
        #[arg(long, default_value = "issuance")]
        scope: String,
    },
    /// Add a new policy rule.
    AddRule {
        #[arg(long)]
        name: String,
        /// Rule type: allow or deny.
        #[arg(long, value_name = "TYPE", value_parser = ["allow", "deny"])]
        r#type: String,
        #[arg(long, value_name = "PROFILE")]
        profile: Vec<String>,
        #[arg(long, value_name = "CA")]
        ca: Vec<String>,
        /// Restrict to a specific ACME account ID (repeatable).
        #[arg(long, value_name = "ACCOUNT")]
        account: Vec<String>,
        #[arg(long, value_name = "GROUP")]
        account_group: Vec<String>,
        #[arg(long, value_name = "PATTERN")]
        identifier: Vec<String>,
        #[arg(long, value_name = "KEY_TYPE")]
        key_type: Vec<String>,
        #[arg(long)]
        valid_from: Option<String>,
        #[arg(long)]
        valid_until: Option<String>,
        /// Scope (default: issuance).
        #[arg(long, default_value = "issuance")]
        scope: String,
        /// Create the rule enabled or disabled (default: true).
        #[arg(long, default_value = "true")]
        enabled: bool,
    },
    /// Remove a policy rule by name or ID.
    #[command(group(clap::ArgGroup::new("target").required(true).args(["name", "id"])))]
    RemoveRule {
        /// Rule name.
        #[arg(long)]
        name: Option<String>,
        /// Rule UUID.
        #[arg(long)]
        id: Option<String>,
        /// Scope to search when using --name (default: issuance).
        #[arg(long, default_value = "issuance")]
        scope: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConfigCmd {
    /// Print an annotated example akamuctl.toml to stdout.
    ///
    /// Redirect to a file as a starting point:
    ///   akamuctl config generate > ~/.config/akamu/akamuctl.toml
    Generate,
    /// Validate the configuration file.
    Validate,
}

#[derive(Subcommand)]
pub(crate) enum OperatorCmd {
    /// List all operators.
    List,
    /// Show an operator's details.
    Show {
        /// Operator ID.
        id: i64,
    },
    /// Add a new operator.
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        role: String,
        /// Path to operator's client certificate (for fingerprint extraction).
        #[arg(long, value_name = "FILE")]
        cert_file: Option<PathBuf>,
        /// GSSAPI Kerberos principal.
        #[arg(long)]
        gssapi_principal: Option<String>,
    },
    /// Update an operator's fields.
    Update {
        /// Operator ID.
        id: i64,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        role: Option<String>,
        /// Path to operator's client certificate (for fingerprint extraction).
        #[arg(long, value_name = "FILE")]
        cert_file: Option<PathBuf>,
        /// GSSAPI Kerberos principal.
        #[arg(long)]
        gssapi_principal: Option<String>,
    },
    /// Deactivate an operator.
    Remove {
        /// Operator ID.
        id: i64,
    },
    /// Re-activate a previously deactivated operator.
    Activate {
        /// Operator ID.
        id: i64,
    },
    /// Unlock a locked operator (reset failed auth counter).
    Unlock {
        /// Operator ID.
        id: i64,
    },
}

#[derive(Subcommand)]
pub(crate) enum EabCmd {
    /// List EAB keys.
    List {
        #[arg(long)]
        used: bool,
        #[arg(long)]
        unused: bool,
    },
    /// Show an EAB key's details.
    Show { kid: String },
    /// Provision a new EAB key.
    Add {
        #[arg(long)]
        kid: Option<String>,
        #[arg(long)]
        hmac_key: Option<String>,
        #[arg(long = "profile", value_name = "PROFILE")]
        profiles: Vec<String>,
    },
    /// Deactivate an EAB key.
    Remove { kid: String },
}

#[derive(Subcommand)]
pub(crate) enum CertCmd {
    /// List certificates.
    List {
        #[arg(long)]
        serial: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        after: Option<String>,
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        status: Option<String>,
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
        #[arg(long, default_value = "20")]
        limit: u32,
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Show a certificate's metadata.
    Show {
        /// Certificate ID (UUID).
        id: String,
    },
    /// Download a certificate as PEM or DER.
    Download {
        /// Certificate ID (UUID).
        id: String,
        /// Output format: pem (default) or der.
        #[arg(long, default_value = "pem")]
        format: String,
        /// Write to file instead of stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub(crate) enum AccountCmd {
    /// List accounts.
    List {
        /// Filter by status (valid, deactivated).
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value = "100")]
        limit: u32,
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Show an account's details.
    Show {
        /// Account ID (UUID).
        id: String,
    },
    /// Admin-initiated account deactivation.
    Deactivate {
        /// Account ID (UUID).
        id: String,
    },
    /// Manage profile grants.
    #[command(subcommand)]
    Grants(AccountGrantsCmd),
}

#[derive(Subcommand)]
pub(crate) enum ProfileCmd {
    /// List loaded certificate profiles.
    List,
    /// Add a new certificate profile.
    Add {
        /// Profile ID.
        id: String,
        /// JSON file with profile parameters.
        #[arg(long, value_name = "FILE")]
        params_file: PathBuf,
    },
    /// Update an existing certificate profile.
    Update {
        /// Profile ID.
        id: String,
        /// JSON file with profile parameters.
        #[arg(long, value_name = "FILE")]
        params_file: PathBuf,
    },
    /// Remove a certificate profile.
    Remove {
        /// Profile ID.
        id: String,
    },
    /// Show a single certificate profile by ID.
    Show {
        /// Profile ID.
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum OrderCmd {
    /// List orders.
    List {
        /// Filter by account ID.
        #[arg(long)]
        account_id: Option<String>,
        /// Filter by status.
        #[arg(long)]
        status: Option<String>,
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
        #[arg(long, default_value = "100")]
        limit: u32,
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Show an order's details.
    Show {
        /// Order ID (UUID).
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum AccountGrantsCmd {
    /// Show profile grants for an account.
    Get { id: String },
    /// Set profile grants for an account.
    Set {
        id: String,
        #[arg(long = "profile", value_name = "PROFILE")]
        profiles: Vec<String>,
    },
    /// Clear all profile grants (unrestricted).
    Clear { id: String },
}

#[derive(Subcommand)]
pub(crate) enum DelegationCmd {
    /// List delegation objects (optionally filtered by account).
    List {
        /// Filter to delegations owned by this account ID.
        #[arg(long)]
        account_id: Option<String>,
    },
    /// Show a single delegation object.
    Show {
        /// Delegation ID (UUID).
        id: String,
    },
    /// Create a delegation for an account.
    Add {
        /// Account ID to create the delegation for.
        #[arg(long)]
        account_id: String,
        /// JSON file containing the CSR template (RFC 9115 §4).
        #[arg(long, value_name = "FILE")]
        csr_template: PathBuf,
        /// JSON file containing the CNAME map (optional).
        #[arg(long, value_name = "FILE")]
        cname_map: Option<PathBuf>,
    },
    /// Replace the CSR template and CNAME map for a delegation.
    Update {
        /// Delegation ID (UUID).
        id: String,
        /// JSON file containing the replacement CSR template.
        #[arg(long, value_name = "FILE")]
        csr_template: PathBuf,
        /// JSON file containing the replacement CNAME map.
        #[arg(long, value_name = "FILE", conflicts_with = "clear_cname_map")]
        cname_map: Option<PathBuf>,
        /// Remove the CNAME map (set to null).
        #[arg(long, conflicts_with = "cname_map")]
        clear_cname_map: bool,
    },
    /// Delete a delegation (fails if active orders reference it).
    Remove {
        /// Delegation ID (UUID).
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum CosignerCmd {
    /// Authenticate and cache cosigner session token.
    Login,
    /// Invalidate cosigner session token.
    Logout,
    /// Cosigner status.
    Status,
    /// Cosigner statistics.
    Stats,
    /// Show redacted cosigner configuration.
    Config,
}

#[derive(Subcommand)]
pub(crate) enum MtcCmd {
    /// Show the current tree size.
    TreeSize {
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Show the current tree root hash.
    Root {
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// List landmarks (JSON).
    Landmarks {
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Show landmark list (spec text/plain format).
    LandmarkList {
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Download a landmark certificate DER.
    LandmarkCert {
        /// Landmark sequence number.
        seq: i64,
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
        /// Write to file instead of hex-dumping to stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Show parsed details of a landmark certificate.
    LandmarkCertShow {
        /// Landmark sequence number.
        seq: i64,
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Show an inclusion proof for a certificate.
    InclusionProof {
        /// Certificate ID (UUID).
        cert_id: String,
    },
    /// Download a standalone MTC certificate DER.
    Standalone {
        /// Certificate ID (UUID).
        cert_id: String,
        /// Write to file instead of hex-dumping to stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Show a consistency proof between two tree sizes.
    ConsistencyProof {
        /// Older tree size.
        #[arg(long)]
        from: u64,
        /// Newer tree size.
        #[arg(long)]
        to: u64,
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Show the subtree root hash for a range.
    SubtreeRoot {
        /// Start index (inclusive).
        #[arg(long)]
        start: u64,
        /// End index (exclusive).
        #[arg(long)]
        end: u64,
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Show revoked index ranges.
    RevokedRanges {
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Show the C2SP tlog checkpoint.
    Checkpoint {
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Show the C2SP tlog cosignature.
    Cosignature {
        /// Filter by CA identifier.
        #[arg(long, value_name = "CA_ID")]
        ca: Option<String>,
    },
    /// Force an immediate checkpoint.
    ForceCheckpoint {
        /// CA identifier (required).
        #[arg(long, value_name = "CA_ID")]
        ca: String,
    },
    /// Force an immediate landmark allocation.
    ForceLandmark {
        /// CA identifier (required).
        #[arg(long, value_name = "CA_ID")]
        ca: String,
    },
    /// Print the Witness Network log-list entry for this CA's MTC log.
    LogListEntry {
        /// CA identifier (required).
        #[arg(long, value_name = "CA_ID")]
        ca: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum CaCmd {
    /// List all configured CAs.
    List,
    /// Show details for a specific CA.
    Show {
        /// CA identifier.
        id: String,
    },
    /// Download the CA certificate PEM.
    Cert {
        /// CA identifier.
        id: String,
        /// Write to file instead of stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Invalidate the CRL cache for a specific CA.
    CrlForce {
        /// CA identifier.
        id: String,
    },
    /// Issue a cross-certificate from one CA signing another CA's public key.
    CrossSign {
        /// CA identifier of the signing (issuer) CA.
        issuer_id: String,
        /// CA identifier of the subject CA on this server.
        #[arg(long, group = "subject")]
        subject_ca_id: Option<String>,
        /// PEM file of an external CA certificate to cross-sign.
        #[arg(long, group = "subject", value_name = "FILE")]
        subject_cert: Option<PathBuf>,
        /// Validity of the cross-certificate in years.
        #[arg(long, default_value = "5")]
        validity_years: u32,
    },
}

#[derive(Subcommand)]
pub(crate) enum CrossCertCmd {
    /// List cross-certificates.
    List {
        /// Filter by issuer CA identifier.
        #[arg(long)]
        issuer_ca: Option<String>,
        /// Filter by subject CA identifier.
        #[arg(long)]
        subject_ca: Option<String>,
        #[arg(long, default_value = "100")]
        limit: u32,
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Download a cross-certificate PEM by UUID.
    Download {
        /// Cross-certificate UUID.
        id: String,
        /// Write to file instead of stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Show cross-certificate metadata by UUID.
    Show {
        /// Cross-certificate UUID.
        id: String,
    },
}
