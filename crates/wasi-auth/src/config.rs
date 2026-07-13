//! Validated runtime security profiles.

use http::Uri;
use thiserror::Error;

/// Durable database selected by an authentication deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DatabaseProfile {
    /// Production PostgreSQL storage.
    Postgres,
    /// Spin SQLite local-development storage.
    SpinSqlite,
}

/// Mail delivery selected by an authentication deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MailProfile {
    /// HTTPS webhook delivery from Spin.
    HttpWebhook,
    /// Local in-memory capture.
    Capture,
}

/// Signing algorithm accepted by the production token issuer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// NIST P-256 ECDSA with SHA-256.
    Es256,
}

/// Untrusted runtime settings validated into a deployment profile.
#[derive(Clone, Debug)]
pub struct RuntimeSecurityConfig {
    /// Public browser origin.
    pub public_origin: String,
    /// WebAuthn relying-party identifier.
    pub webauthn_rp_id: String,
    /// Database adapter.
    pub database: DatabaseProfile,
    /// Mail adapter.
    pub mail: MailProfile,
    /// Token signing algorithm.
    pub signing_algorithm: SigningAlgorithm,
    /// Session lifetime in seconds.
    pub session_ttl_seconds: u64,
    /// One-time token lifetime in seconds.
    pub one_time_token_ttl_seconds: u64,
    /// Whether OAuth callback verification may be bypassed.
    pub oauth_development_bypass: bool,
    /// Whether insecure development cookies are enabled.
    pub development_cookies: bool,
    /// Application secret used for keyed hashing and encryption derivation.
    pub application_secret: Vec<u8>,
}

/// Validated local-development profile.
#[derive(Clone, Debug)]
pub struct DevelopmentConfig(RuntimeSecurityConfig);

impl DevelopmentConfig {
    /// Validates loopback-only development settings.
    ///
    /// # Errors
    ///
    /// Rejects non-loopback HTTP origins, invalid RP IDs, TTLs, or secrets.
    pub fn new(config: RuntimeSecurityConfig) -> Result<Self, ConfigurationError> {
        validate_common(&config)?;
        let uri = parse_origin(&config.public_origin)?;
        if uri.scheme_str() == Some("http") && !is_loopback_host(origin_host(&uri)?) {
            return Err(ConfigurationError::InsecureOrigin);
        }
        Ok(Self(config))
    }

    /// Returns the validated settings.
    #[must_use]
    pub const fn as_runtime(&self) -> &RuntimeSecurityConfig {
        &self.0
    }
}

/// Validated production profile.
#[derive(Clone, Debug)]
pub struct ProductionConfig(RuntimeSecurityConfig);

impl ProductionConfig {
    /// Validates fail-closed production settings.
    ///
    /// # Errors
    ///
    /// Rejects every development adapter or bypass, insecure origin, invalid
    /// WebAuthn scope, weak/default secret, or unsafe TTL.
    pub fn new(config: RuntimeSecurityConfig) -> Result<Self, ConfigurationError> {
        validate_common(&config)?;
        let uri = parse_origin(&config.public_origin)?;
        if uri.scheme_str() != Some("https") {
            return Err(ConfigurationError::InsecureOrigin);
        }
        if config.database != DatabaseProfile::Postgres {
            return Err(ConfigurationError::ProductionDatabaseRequired);
        }
        if config.mail != MailProfile::HttpWebhook {
            return Err(ConfigurationError::ProductionMailRequired);
        }
        if config.oauth_development_bypass || config.development_cookies {
            return Err(ConfigurationError::DevelopmentFeatureEnabled);
        }
        Ok(Self(config))
    }

    /// Returns the validated settings.
    #[must_use]
    pub const fn as_runtime(&self) -> &RuntimeSecurityConfig {
        &self.0
    }
}

/// Runtime security configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ConfigurationError {
    /// Public origin is malformed or includes path/query data.
    #[error("public origin is invalid")]
    InvalidOrigin,
    /// Production or non-loopback traffic uses plaintext HTTP.
    #[error("public origin must use HTTPS")]
    InsecureOrigin,
    /// WebAuthn RP ID does not scope the public origin host.
    #[error("WebAuthn RP ID does not match the public origin")]
    WebauthnRpMismatch,
    /// Session or one-time token TTL is outside the supported bound.
    #[error("authentication TTL is outside the supported bound")]
    InvalidTtl,
    /// Application secret is missing, weak, or a known placeholder.
    #[error("application secret is not production quality")]
    InvalidSecret,
    /// Production requires PostgreSQL.
    #[error("production requires PostgreSQL")]
    ProductionDatabaseRequired,
    /// Production requires HTTP webhook mail.
    #[error("production requires HTTP webhook mail")]
    ProductionMailRequired,
    /// A development-only bypass or cookie is enabled.
    #[error("development-only behavior is enabled in production")]
    DevelopmentFeatureEnabled,
}

fn validate_common(config: &RuntimeSecurityConfig) -> Result<(), ConfigurationError> {
    let uri = parse_origin(&config.public_origin)?;
    let host = origin_host(&uri)?;
    if config.webauthn_rp_id.is_empty()
        || !(host == config.webauthn_rp_id
            || host.ends_with(&format!(".{}", config.webauthn_rp_id)))
    {
        return Err(ConfigurationError::WebauthnRpMismatch);
    }
    if !(300..=2_592_000).contains(&config.session_ttl_seconds)
        || !(60..=86_400).contains(&config.one_time_token_ttl_seconds)
    {
        return Err(ConfigurationError::InvalidTtl);
    }
    let secret = config.application_secret.as_slice();
    if secret.len() < 32
        || secret.iter().all(|byte| *byte == 0)
        || secret == b"change-me-change-me-change-me-change-me"
    {
        return Err(ConfigurationError::InvalidSecret);
    }
    Ok(())
}

fn parse_origin(value: &str) -> Result<Uri, ConfigurationError> {
    let uri = value
        .parse::<Uri>()
        .map_err(|_| ConfigurationError::InvalidOrigin)?;
    if uri.scheme().is_none()
        || uri.authority().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
    {
        return Err(ConfigurationError::InvalidOrigin);
    }
    Ok(uri)
}

fn origin_host(uri: &Uri) -> Result<&str, ConfigurationError> {
    uri.host().ok_or(ConfigurationError::InvalidOrigin)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production_fixture() -> RuntimeSecurityConfig {
        RuntimeSecurityConfig {
            public_origin: "https://app.example.com".to_owned(),
            webauthn_rp_id: "example.com".to_owned(),
            database: DatabaseProfile::Postgres,
            mail: MailProfile::HttpWebhook,
            signing_algorithm: SigningAlgorithm::Es256,
            session_ttl_seconds: 3_600,
            one_time_token_ttl_seconds: 900,
            oauth_development_bypass: false,
            development_cookies: false,
            application_secret: vec![7; 32],
        }
    }

    #[test]
    fn production_accepts_hardened_profile() {
        assert!(ProductionConfig::new(production_fixture()).is_ok());
    }

    #[test]
    fn production_rejects_every_development_escape_hatch() {
        let mut config = production_fixture();
        config.oauth_development_bypass = true;
        assert_eq!(
            ProductionConfig::new(config).unwrap_err(),
            ConfigurationError::DevelopmentFeatureEnabled
        );
    }

    #[test]
    fn production_rejects_mismatched_webauthn_scope() {
        let mut config = production_fixture();
        config.webauthn_rp_id = "attacker.example".to_owned();
        assert_eq!(
            ProductionConfig::new(config).unwrap_err(),
            ConfigurationError::WebauthnRpMismatch
        );
    }
}
