//! TOTP and one-time recovery-code primitives.
//!
//! Raw TOTP secrets and recovery codes are deliberately non-serializable and
//! redact their debug output. Applications should show them once, then store
//! only encrypted TOTP material and keyed recovery-code hashes.

use std::error::Error as StdError;
use std::fmt;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

use super::{AuthenticationError, RandomSource, SecretMaterial};

const TOTP_SECRET_BYTES: usize = 20;
const RECOVERY_CODE_BYTES: usize = 10;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Invalid MFA configuration, code, or secret material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum MfaError {
    /// TOTP period, digit count, or skew is outside supported bounds.
    #[error("invalid TOTP configuration")]
    InvalidConfiguration,
    /// The supplied one-time code is not canonical.
    #[error("invalid one-time code")]
    InvalidCode,
    /// The TOTP secret or recovery-code pepper is too short.
    #[error("invalid MFA secret material")]
    InvalidSecret,
}

/// Failure while generating secret material from an injected random source.
#[derive(Debug, Error)]
pub enum MfaGenerationError<E>
where
    E: StdError + Send + Sync + 'static,
{
    /// The randomness provider failed.
    #[error("MFA randomness provider failed")]
    Random(#[source] E),
    /// Generated material failed an internal invariant.
    #[error(transparent)]
    Invalid(#[from] AuthenticationError),
}

/// Bounded RFC 6238 configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotpConfig {
    period_seconds: u64,
    digits: u32,
    allowed_skew_steps: u8,
}

impl TotpConfig {
    /// Creates a TOTP configuration.
    ///
    /// Supported codes contain six through eight digits, use a 15 through
    /// 120 second period, and permit at most two adjacent time steps.
    ///
    /// # Errors
    ///
    /// Returns [`MfaError::InvalidConfiguration`] outside those bounds.
    pub const fn new(
        period_seconds: u64,
        digits: u32,
        allowed_skew_steps: u8,
    ) -> Result<Self, MfaError> {
        if period_seconds < 15
            || period_seconds > 120
            || digits < 6
            || digits > 8
            || allowed_skew_steps > 2
        {
            return Err(MfaError::InvalidConfiguration);
        }
        Ok(Self {
            period_seconds,
            digits,
            allowed_skew_steps,
        })
    }

    /// Returns the time-step duration.
    #[must_use]
    pub const fn period_seconds(self) -> u64 {
        self.period_seconds
    }

    /// Returns the decimal code width.
    #[must_use]
    pub const fn digits(self) -> u32 {
        self.digits
    }

    /// Returns the accepted clock-skew window in adjacent steps.
    #[must_use]
    pub const fn allowed_skew_steps(self) -> u8 {
        self.allowed_skew_steps
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            period_seconds: 30,
            digits: 6,
            allowed_skew_steps: 1,
        }
    }
}

/// Raw TOTP seed displayed once and then encrypted at rest.
pub struct TotpSecret(SecretMaterial);

impl TotpSecret {
    /// Generates a 160-bit TOTP secret from an injected cryptographic source.
    ///
    /// # Errors
    ///
    /// Returns [`MfaGenerationError`] when randomness fails.
    pub fn generate<R>(random: &R) -> Result<Self, MfaGenerationError<R::Error>>
    where
        R: RandomSource,
    {
        let mut bytes = vec![0_u8; TOTP_SECRET_BYTES];
        random
            .fill_bytes(&mut bytes)
            .map_err(MfaGenerationError::Random)?;
        Ok(Self(SecretMaterial::new(bytes)?))
    }

    /// Wraps an existing secret containing at least 128 bits.
    ///
    /// # Errors
    ///
    /// Returns [`MfaError::InvalidSecret`] for short material.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, MfaError> {
        let bytes = bytes.into();
        if bytes.len() < 16 {
            return Err(MfaError::InvalidSecret);
        }
        let material = SecretMaterial::new(bytes).map_err(|_| MfaError::InvalidSecret)?;
        Ok(Self(material))
    }

    /// Returns the raw bytes for cryptography or encrypted persistence.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Returns the unpadded RFC 4648 Base32 provisioning value.
    #[must_use]
    pub fn provisioning_base32(&self) -> String {
        encode_base32(self.expose())
    }
}

impl fmt::Debug for TotpSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TotpSecret([REDACTED])")
    }
}

/// Raw one-time recovery code displayed only during enrollment.
pub struct RecoveryCode(String);

impl RecoveryCode {
    /// Generates a 16-character Base32 code grouped for readability.
    ///
    /// # Errors
    ///
    /// Returns [`MfaGenerationError`] when randomness fails.
    pub fn generate<R>(random: &R) -> Result<Self, MfaGenerationError<R::Error>>
    where
        R: RandomSource,
    {
        let mut bytes = [0_u8; RECOVERY_CODE_BYTES];
        random
            .fill_bytes(&mut bytes)
            .map_err(MfaGenerationError::Random)?;
        let compact = encode_base32(&bytes);
        let grouped = compact
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).expect("Base32 is ASCII"))
            .collect::<Vec<_>>()
            .join("-");
        Ok(Self(grouped))
    }

    /// Returns the code for its one-time enrollment display.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCode([REDACTED])")
    }
}

impl Drop for RecoveryCode {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Keyed recovery-code digest safe to persist.
#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryCodeHash([u8; 32]);

impl RecoveryCodeHash {
    /// Returns the fixed-width persistence representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Restores a stored digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for RecoveryCodeHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCodeHash([REDACTED])")
    }
}

/// Produces a standards-compatible `otpauth://` enrollment URI.
///
/// # Errors
///
/// Returns [`MfaError::InvalidCode`] when issuer or account is empty.
pub fn provisioning_uri(
    issuer: &str,
    account: &str,
    secret: &TotpSecret,
    config: TotpConfig,
) -> Result<String, MfaError> {
    if issuer.trim().is_empty() || account.trim().is_empty() {
        return Err(MfaError::InvalidCode);
    }
    let issuer = percent_encode(issuer.trim());
    let account = percent_encode(account.trim());
    Ok(format!(
        "otpauth://totp/{issuer}:{account}?secret={}&issuer={issuer}&algorithm=SHA1&digits={}&period={}",
        secret.provisioning_base32(),
        config.digits(),
        config.period_seconds()
    ))
}

/// Verifies a TOTP code in constant time over the bounded skew window.
///
/// Returns the matched RFC 6238 time step when the code is valid.
///
/// # Errors
///
/// Returns [`MfaError`] for malformed codes or short secret material.
pub fn verify_totp(
    secret: &[u8],
    code: &str,
    unix_seconds: u64,
    config: TotpConfig,
) -> Result<Option<u64>, MfaError> {
    if secret.len() < 16 {
        return Err(MfaError::InvalidSecret);
    }
    if code.len() != config.digits() as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MfaError::InvalidCode);
    }
    let step = unix_seconds / config.period_seconds();
    let skew = u64::from(config.allowed_skew_steps());
    let mut matched_step = None::<u64>;
    for offset in 0..=skew {
        if let Some(candidate_step) = step.checked_sub(offset) {
            if verify_totp_step(secret, code.as_bytes(), candidate_step, config.digits()) == 1 {
                matched_step = Some(matched_step.map_or(candidate_step, |current| {
                    current.max(candidate_step)
                }));
            }
        }
        if offset != 0
            && let Some(candidate_step) = step.checked_add(offset)
            && verify_totp_step(secret, code.as_bytes(), candidate_step, config.digits()) == 1
        {
            matched_step = Some(matched_step.map_or(candidate_step, |current| {
                current.max(candidate_step)
            }));
        }
    }
    Ok(matched_step)
}

/// Hashes a normalized recovery code with an application pepper.
///
/// # Errors
///
/// Returns [`MfaError`] for a pepper shorter than 128 bits or a malformed code.
pub fn hash_recovery_code(pepper: &[u8], code: &str) -> Result<RecoveryCodeHash, MfaError> {
    if pepper.len() < 16 {
        return Err(MfaError::InvalidSecret);
    }
    let normalized = normalize_recovery_code(code)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).map_err(|_| MfaError::InvalidSecret)?;
    mac.update(normalized.as_bytes());
    let digest: [u8; 32] = mac.finalize().into_bytes().into();
    Ok(RecoveryCodeHash(digest))
}

/// Verifies a recovery code against a keyed persisted digest.
///
/// # Errors
///
/// Returns [`MfaError`] for malformed input or invalid pepper material.
pub fn verify_recovery_code(
    pepper: &[u8],
    candidate: &str,
    expected: &RecoveryCodeHash,
) -> Result<bool, MfaError> {
    let candidate = hash_recovery_code(pepper, candidate)?;
    Ok(candidate.0.ct_eq(&expected.0).into())
}

fn verify_totp_step(secret: &[u8], code: &[u8], step: u64, digits: u32) -> u8 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts arbitrary key sizes");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let value = binary % 10_u32.pow(digits);
    let expected = format!("{value:0width$}", width = digits as usize);
    expected.as_bytes().ct_eq(code).unwrap_u8()
}

fn normalize_recovery_code(code: &str) -> Result<String, MfaError> {
    let normalized = code
        .bytes()
        .filter(|byte| *byte != b'-' && !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    if normalized.len() != 16 || !normalized.iter().all(|byte| BASE32_ALPHABET.contains(byte)) {
        return Err(MfaError::InvalidCode);
    }
    String::from_utf8(normalized).map_err(|_| MfaError::InvalidCode)
}

fn encode_base32(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut accumulator = 0_u32;
    let mut bit_count = 0_u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let index = ((accumulator >> bit_count) & 0x1f) as usize;
            output.push(char::from(BASE32_ALPHABET[index]));
        }
    }
    if bit_count > 0 {
        let index = ((accumulator << (5 - bit_count)) & 0x1f) as usize;
        output.push(char::from(BASE32_ALPHABET[index]));
    }
    output
}

fn percent_encode(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut output, "%{byte:02X}").expect("writing to a string cannot fail");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Error)]
    #[error("test random source failed")]
    struct RandomError;

    struct FixedRandom;

    impl RandomSource for FixedRandom {
        type Error = RandomError;

        fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), Self::Error> {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte = index as u8;
            }
            Ok(())
        }
    }

    #[test]
    fn matches_rfc_6238_sha1_vector() {
        let config = TotpConfig::new(30, 8, 0).unwrap();
        assert_eq!(
            verify_totp(b"12345678901234567890", "94287082", 59, config).unwrap(),
            Some(1)
        );
        assert_eq!(
            verify_totp(b"12345678901234567890", "94287081", 59, config).unwrap(),
            None
        );
    }

    #[test]
    fn accepts_only_the_bounded_skew_window() {
        let secret = b"12345678901234567890";
        let exact = TotpConfig::new(30, 8, 0).unwrap();
        let skewed = TotpConfig::new(30, 8, 1).unwrap();
        assert_eq!(verify_totp(secret, "94287082", 89, exact).unwrap(), None);
        assert_eq!(verify_totp(secret, "94287082", 89, skewed).unwrap(), Some(1));
        assert_eq!(verify_totp(secret, "94287082", 119, skewed).unwrap(), None);
    }

    #[test]
    fn returns_the_highest_matching_step_in_the_skew_window() {
        let secret = b"12345678901234567890";
        let config = TotpConfig::new(30, 8, 1).unwrap();
        assert_eq!(verify_totp(secret, "94287082", 89, config).unwrap(), Some(1));
    }

    #[test]
    fn generated_secrets_and_codes_redact_debug_output() {
        let secret = TotpSecret::generate(&FixedRandom).unwrap();
        let code = RecoveryCode::generate(&FixedRandom).unwrap();
        assert_eq!(
            secret.provisioning_base32(),
            "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQT"
        );
        assert_eq!(code.expose(), "AAAQ-EAYE-AUDA-OCAJ");
        assert_eq!(format!("{secret:?}"), "TotpSecret([REDACTED])");
        assert_eq!(format!("{code:?}"), "RecoveryCode([REDACTED])");
    }

    #[test]
    fn recovery_codes_are_keyed_and_constant_time_comparable() {
        let pepper = b"0123456789abcdef0123456789abcdef";
        let hash = hash_recovery_code(pepper, "AAAQ-EAYE-AUDA-OCAJ").unwrap();
        assert!(verify_recovery_code(pepper, "aaaq eaye auda ocaj", &hash).unwrap());
        assert!(!verify_recovery_code(pepper, "BAAQ-EAYE-AUDA-OCAJ", &hash).unwrap());
        assert_eq!(format!("{hash:?}"), "RecoveryCodeHash([REDACTED])");
    }

    #[test]
    fn provisioning_uri_escapes_tenant_and_account_names() {
        let secret = TotpSecret::generate(&FixedRandom).unwrap();
        let uri = provisioning_uri(
            "Example Corp",
            "user+admin@example.test",
            &secret,
            TotpConfig::default(),
        )
        .unwrap();
        assert!(uri.starts_with("otpauth://totp/Example%20Corp:user%2Badmin%40example.test?"));
        assert!(uri.contains("issuer=Example%20Corp"));
    }
}
