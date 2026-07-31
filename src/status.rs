//! Typed status enums for ACME resource lifecycle states.
//!
//! Mirrors the pattern used by [`crate::state::OperatorRole`]: no `sqlx::Type`
//! impl, no derive-macro machinery. The DB layer always binds/reads plain
//! `String`/`&str` (see `db::schema` row structs); `.parse::<XStatus>()` /
//! `.as_str()` are used only at the specific call sites that need a typed
//! comparison or a typed write parameter.

/// RFC 8555 §7.1.3 order status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
    /// RFC 8739 §3.1.2 STAR auto-renewal cancellation.
    Canceled,
}

impl std::str::FromStr for OrderStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "processing" => Ok(Self::Processing),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "canceled" => Ok(Self::Canceled),
            _ => Err(format!("unknown order status: {s:?}")),
        }
    }
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Canceled => "canceled",
        }
    }
}

impl std::fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 8555 §7.1.2 account status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

impl std::str::FromStr for AccountStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "valid" => Ok(Self::Valid),
            "deactivated" => Ok(Self::Deactivated),
            "revoked" => Ok(Self::Revoked),
            _ => Err(format!("unknown account status: {s:?}")),
        }
    }
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Deactivated => "deactivated",
            Self::Revoked => "revoked",
        }
    }
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 8555 §7.1.6 authorization status. `Expired` and `Revoked` are part of
/// the RFC vocabulary but are not currently assigned by any code path in this
/// server; they are included for completeness so the CHECK constraint on
/// `authorizations.status` doesn't need to change if that ever does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

impl std::str::FromStr for AuthzStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "deactivated" => Ok(Self::Deactivated),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(format!("unknown authorization status: {s:?}")),
        }
    }
}

impl AuthzStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Deactivated => "deactivated",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

impl std::fmt::Display for AuthzStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 8555 §8 challenge status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

impl std::str::FromStr for ChallengeStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "processing" => Ok(Self::Processing),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            _ => Err(format!("unknown challenge status: {s:?}")),
        }
    }
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }
}

impl std::fmt::Display for ChallengeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Issued-certificate status. Not part of the RFC 8555 core object model —
/// tracked internally for CRL/OCSP/CRDT purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    Valid,
    Revoked,
}

impl std::str::FromStr for CertStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "valid" => Ok(Self::Valid),
            "revoked" => Ok(Self::Revoked),
            _ => Err(format!("unknown certificate status: {s:?}")),
        }
    }
}

impl CertStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Revoked => "revoked",
        }
    }
}

impl std::fmt::Display for CertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_status_round_trips_and_rejects_unknown() {
        for s in [
            OrderStatus::Pending,
            OrderStatus::Ready,
            OrderStatus::Processing,
            OrderStatus::Valid,
            OrderStatus::Invalid,
            OrderStatus::Canceled,
        ] {
            assert_eq!(s.as_str().parse::<OrderStatus>().unwrap(), s);
        }
        assert!("bogus".parse::<OrderStatus>().is_err());
    }

    #[test]
    fn account_status_round_trips_and_rejects_unknown() {
        for s in [
            AccountStatus::Valid,
            AccountStatus::Deactivated,
            AccountStatus::Revoked,
        ] {
            assert_eq!(s.as_str().parse::<AccountStatus>().unwrap(), s);
        }
        assert!("bogus".parse::<AccountStatus>().is_err());
    }

    #[test]
    fn authz_status_round_trips_and_rejects_unknown() {
        for s in [
            AuthzStatus::Pending,
            AuthzStatus::Valid,
            AuthzStatus::Invalid,
            AuthzStatus::Deactivated,
            AuthzStatus::Expired,
            AuthzStatus::Revoked,
        ] {
            assert_eq!(s.as_str().parse::<AuthzStatus>().unwrap(), s);
        }
        assert!("bogus".parse::<AuthzStatus>().is_err());
    }

    #[test]
    fn challenge_status_round_trips_and_rejects_unknown() {
        for s in [
            ChallengeStatus::Pending,
            ChallengeStatus::Processing,
            ChallengeStatus::Valid,
            ChallengeStatus::Invalid,
        ] {
            assert_eq!(s.as_str().parse::<ChallengeStatus>().unwrap(), s);
        }
        assert!("bogus".parse::<ChallengeStatus>().is_err());
    }

    #[test]
    fn cert_status_round_trips_and_rejects_unknown() {
        for s in [CertStatus::Valid, CertStatus::Revoked] {
            assert_eq!(s.as_str().parse::<CertStatus>().unwrap(), s);
        }
        assert!("bogus".parse::<CertStatus>().is_err());
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(OrderStatus::Canceled.to_string(), "canceled");
        assert_eq!(AccountStatus::Deactivated.to_string(), "deactivated");
        assert_eq!(AuthzStatus::Expired.to_string(), "expired");
        assert_eq!(ChallengeStatus::Processing.to_string(), "processing");
        assert_eq!(CertStatus::Revoked.to_string(), "revoked");
    }
}
