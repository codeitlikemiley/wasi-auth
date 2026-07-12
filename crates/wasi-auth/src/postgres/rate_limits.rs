//! Atomic PostgreSQL rate-limit buckets for authentication workflows.

use std::{error::Error as StdError, fmt::Write as _};

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::authentication::Clock;

const CHECK_RATE_LIMIT_SQL: &str = include_str!("check_rate_limit.sql");
const MAX_SCOPE_BYTES: usize = 64;
const MAX_SUBJECT_BYTES: usize = 1_024;

/// Result of consuming one attempt from a bounded rate bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitDecision {
    /// Whether the operation may continue.
    pub allowed: bool,
    /// Remaining window duration when another attempt should be retried.
    pub retry_after_seconds: u64,
}

/// PostgreSQL-backed rate limiter.
pub struct RateLimitService<T, C> {
    store: PostgresAuthStore<T>,
    clock: C,
}

impl<T, C> RateLimitService<T, C> {
    /// Assembles a limiter from its runtime dependencies.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C) -> Self {
        Self { store, clock }
    }
}

impl<T, C> RateLimitService<T, C>
where
    T: PostgresTransport,
    C: Clock,
{
    /// Atomically consumes one attempt from a hashed subject bucket.
    ///
    /// # Errors
    ///
    /// Rejects malformed bounds and propagates PostgreSQL or row failures.
    pub async fn check(
        &self,
        scope: &str,
        subject: &str,
        maximum_attempts: u64,
        window_seconds: u64,
    ) -> Result<RateLimitDecision, RateLimitError<T::Error>> {
        if scope.is_empty()
            || scope.len() > MAX_SCOPE_BYTES
            || scope.chars().any(char::is_control)
            || subject.is_empty()
            || subject.len() > MAX_SUBJECT_BYTES
            || !(1..=10_000).contains(&maximum_attempts)
            || !(1..=86_400).contains(&window_seconds)
        {
            return Err(RateLimitError::InvalidRequest);
        }
        let bucket_key = bucket_key(scope, subject);
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let rows = self
            .store
            .transport()
            .query(
                CHECK_RATE_LIMIT_SQL,
                vec![
                    PgValue::Text(bucket_key),
                    PgValue::I64(u64_to_i64(maximum_attempts)),
                    PgValue::I64(u64_to_i64(window_seconds.saturating_mul(1_000))),
                    PgValue::I64(u64_to_i64(now_ms)),
                ],
            )
            .await
            .map_err(RateLimitError::Transport)?;
        let row = rows.first().ok_or(RateLimitError::InvalidRow)?;
        let retry_after_ms = row.required_i64("retry_after_ms")?;
        Ok(RateLimitDecision {
            allowed: row.bool("allowed")?.ok_or(RateLimitError::InvalidRow)?,
            retry_after_seconds: u64::try_from(retry_after_ms)
                .map_err(|_| RateLimitError::InvalidRow)?
                .saturating_add(999)
                .saturating_div(1_000),
        })
    }
}

fn bucket_key(scope: &str, subject: &str) -> String {
    let mut digest = Sha256::new();
    digest.update((scope.len() as u64).to_be_bytes());
    digest.update(scope.as_bytes());
    digest.update((subject.len() as u64).to_be_bytes());
    digest.update(subject.as_bytes());
    let digest = digest.finalize();
    let mut encoded = String::with_capacity(scope.len() + 1 + digest.len() * 2);
    encoded.push_str(scope);
    encoded.push(':');
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Rate-limit persistence failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RateLimitError<E: StdError + Send + Sync + 'static> {
    /// Scope, subject, attempt count, or window violated supported bounds.
    #[error("rate-limit request is invalid")]
    InvalidRequest,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL rate-limit transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned malformed data.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned no decision row.
    #[error("PostgreSQL returned no rate-limit decision")]
    InvalidRow,
}

#[cfg(test)]
mod tests {
    use super::bucket_key;

    #[test]
    fn bucket_subject_is_not_stored_in_plaintext() {
        let key = bucket_key("password-login", "person@example.com");
        assert!(key.starts_with("password-login:"));
        assert!(!key.contains("person@example.com"));
        assert_eq!(key.len(), "password-login:".len() + 64);
    }
}
