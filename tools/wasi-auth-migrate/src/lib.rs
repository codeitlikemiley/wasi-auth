//! Offline migration from legacy DDD auth JSONL exports.
//!
//! Every input envelope produces a newly shaped bootstrap event. Known secret
//! fields are removed recursively, encrypted with AES-256-GCM into a separate
//! vault-import stream, and replaced by opaque credential references. The
//! utility verifies counts, references, ciphertext authentication, and output
//! redaction before publishing the output directory atomically.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

const BOOTSTRAP_FILE: &str = "bootstrap-events.jsonl";
const VAULT_FILE: &str = "vault-import.jsonl";
const MANIFEST_FILE: &str = "manifest.json";
const NONCE_BYTES: usize = 12;

/// Migration input, destination, and AES-256 key.
pub struct MigrationConfig {
    /// Legacy event-envelope JSONL export.
    pub input: PathBuf,
    /// New directory that receives verified migration artifacts.
    pub output: PathBuf,
    /// Offline AES-256-GCM migration key.
    pub key: [u8; 32],
}

impl std::fmt::Debug for MigrationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MigrationConfig")
            .field("input", &self.input)
            .field("output", &self.output)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Verified migration totals.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationReport {
    /// Number of non-empty source event envelopes.
    pub event_count: u64,
    /// Number of extracted encrypted secret values.
    pub secret_count: u64,
}

/// Offline migration failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MigrationError {
    /// Input, key, or output filesystem operation failed.
    #[error("migration I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A source event or generated artifact was invalid JSON.
    #[error("migration JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// The key file was not exactly 32 bytes or 64 hexadecimal characters.
    #[error("migration key must contain 32 raw bytes or 64 hexadecimal characters")]
    InvalidKey,
    /// An input line was missing required event-envelope fields.
    #[error("legacy event at line {line} is invalid: {reason}")]
    InvalidEvent {
        /// One-based source line.
        line: usize,
        /// Stable validation reason without source payload data.
        reason: &'static str,
    },
    /// The destination already exists and is never overwritten.
    #[error("migration output directory already exists")]
    OutputExists,
    /// Cryptographic randomness or authenticated encryption failed.
    #[error("migration encryption failed")]
    Encryption,
    /// Post-write verification rejected the generated artifacts.
    #[error("migration output verification failed: {0}")]
    Verification(&'static str),
}

#[derive(Debug, Deserialize)]
struct LegacyEnvelope {
    #[serde(default)]
    event_id: Option<String>,
    aggregate_type: String,
    aggregate_id: Value,
    revision: u64,
    event_type: String,
    payload: Value,
}

#[derive(Debug, Serialize)]
struct BootstrapEvent {
    event_id: String,
    aggregate_type: String,
    aggregate_id: String,
    revision: u64,
    event_type: &'static str,
    payload: BootstrapPayload,
    source_sha256: String,
}

#[derive(Debug, Serialize)]
struct BootstrapPayload {
    legacy_event_type: String,
    lifecycle: Value,
    credential_references: Vec<CredentialReference>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CredentialReference {
    credential_id: String,
    kind: String,
    secret_version: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultRecord {
    credential_id: String,
    kind: String,
    secret_version: u64,
    key_version: String,
    nonce_base64: String,
    ciphertext_base64: String,
    source_sha256: String,
}

#[derive(Debug, Serialize)]
struct Manifest {
    format: &'static str,
    event_count: u64,
    secret_count: u64,
    bootstrap_sha256: String,
    vault_sha256: String,
    verified: bool,
}

struct PendingSecret {
    reference: CredentialReference,
    plaintext: Vec<u8>,
}

impl Drop for PendingSecret {
    fn drop(&mut self) {
        self.plaintext.fill(0);
    }
}

/// Loads a migration key without accepting it on the process command line.
///
/// # Errors
///
/// Returns [`MigrationError`] for unreadable or incorrectly sized material.
pub fn load_key_file(path: &Path) -> Result<[u8; 32], MigrationError> {
    let mut bytes = fs::read(path)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let result = if bytes.len() == 32 {
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| MigrationError::InvalidKey)
    } else if bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit) {
        let mut key = [0_u8; 32];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(pair).map_err(|_| MigrationError::InvalidKey)?;
            key[index] = u8::from_str_radix(text, 16).map_err(|_| MigrationError::InvalidKey)?;
        }
        Ok(key)
    } else {
        Err(MigrationError::InvalidKey)
    };
    bytes.fill(0);
    result
}

/// Migrates and verifies a legacy event export into a new directory.
///
/// # Errors
///
/// Returns [`MigrationError`] without publishing partial output. Existing
/// destination directories are never overwritten.
pub fn migrate(config: &MigrationConfig) -> Result<MigrationReport, MigrationError> {
    if config.output.exists() {
        return Err(MigrationError::OutputExists);
    }
    let parent = config.output.parent().unwrap_or_else(|| Path::new("."));
    let nonce = random_bytes::<NONCE_BYTES>()?;
    let temporary = parent.join(format!(
        ".wasi-auth-migrate-{}",
        hex(&Sha256::digest(nonce))[..24].to_owned()
    ));
    if temporary.exists() {
        return Err(MigrationError::OutputExists);
    }
    fs::create_dir(&temporary)?;

    let result = migrate_into(config, &temporary);
    match result {
        Ok(report) => {
            fs::rename(&temporary, &config.output)?;
            Ok(report)
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary);
            Err(error)
        }
    }
}

fn migrate_into(
    config: &MigrationConfig,
    output: &Path,
) -> Result<MigrationReport, MigrationError> {
    let input = BufReader::new(File::open(&config.input)?);
    let bootstrap_path = output.join(BOOTSTRAP_FILE);
    let vault_path = output.join(VAULT_FILE);
    let mut bootstrap = BufWriter::new(private_file(&bootstrap_path)?);
    let mut vault = BufWriter::new(private_file(&vault_path)?);
    let cipher = Aes256Gcm::new_from_slice(&config.key).map_err(|_| MigrationError::Encryption)?;
    let mut report = MigrationReport {
        event_count: 0,
        secret_count: 0,
    };

    for (index, line) in input.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let line_number = index + 1;
        let source_hash = hex(&Sha256::digest(line.as_bytes()));
        let envelope: LegacyEnvelope =
            serde_json::from_str(&line).map_err(|_| MigrationError::InvalidEvent {
                line: line_number,
                reason: "invalid JSON envelope",
            })?;
        validate_envelope(&envelope, line_number)?;
        let aggregate_id = canonical_aggregate_id(&envelope.aggregate_id, line_number)?;
        let mut pending = Vec::new();
        let lifecycle = sanitize_value(
            envelope.payload,
            "$",
            &source_hash,
            &mut pending,
            line_number,
        )?;
        let references = pending
            .iter()
            .map(|secret| secret.reference.clone())
            .collect::<Vec<_>>();

        let bootstrap_event = BootstrapEvent {
            event_id: format!("bootstrap:{}", &source_hash[..32]),
            aggregate_type: envelope.aggregate_type,
            aggregate_id,
            revision: envelope.revision,
            event_type: "auth.migration.bootstrap",
            payload: BootstrapPayload {
                legacy_event_type: envelope.event_type,
                lifecycle,
                credential_references: references,
            },
            source_sha256: source_hash.clone(),
        };
        serde_json::to_writer(&mut bootstrap, &bootstrap_event)?;
        bootstrap.write_all(b"\n")?;

        for secret in pending {
            let record = encrypt_secret(&cipher, secret, &source_hash)?;
            serde_json::to_writer(&mut vault, &record)?;
            vault.write_all(b"\n")?;
            report.secret_count += 1;
        }
        report.event_count += 1;
    }
    bootstrap.flush()?;
    vault.flush()?;

    verify_outputs(output, &config.key, report)?;
    let manifest = Manifest {
        format: "wasi-auth-offline-migration-v1",
        event_count: report.event_count,
        secret_count: report.secret_count,
        bootstrap_sha256: file_hash(&bootstrap_path)?,
        vault_sha256: file_hash(&vault_path)?,
        verified: true,
    };
    let mut manifest_file = BufWriter::new(private_file(&output.join(MANIFEST_FILE))?);
    serde_json::to_writer_pretty(&mut manifest_file, &manifest)?;
    manifest_file.write_all(b"\n")?;
    manifest_file.flush()?;
    Ok(report)
}

fn validate_envelope(envelope: &LegacyEnvelope, line: usize) -> Result<(), MigrationError> {
    if envelope.aggregate_type.trim().is_empty() || envelope.aggregate_type.len() > 128 {
        return Err(MigrationError::InvalidEvent {
            line,
            reason: "invalid aggregate_type",
        });
    }
    if envelope.event_type.trim().is_empty()
        || envelope.event_type.len() > 128
        || envelope.revision == 0
    {
        return Err(MigrationError::InvalidEvent {
            line,
            reason: "invalid event_type or revision",
        });
    }
    if envelope.event_id.as_deref().is_some_and(str::is_empty) {
        return Err(MigrationError::InvalidEvent {
            line,
            reason: "empty event_id",
        });
    }
    Ok(())
}

fn canonical_aggregate_id(value: &Value, line: usize) -> Result<String, MigrationError> {
    let id = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        other => serde_json::to_string(other)?,
    };
    if id.is_empty() || id.len() > 512 || id.chars().any(char::is_control) {
        return Err(MigrationError::InvalidEvent {
            line,
            reason: "invalid aggregate_id",
        });
    }
    Ok(id)
}

fn sanitize_value(
    value: Value,
    path: &str,
    source_hash: &str,
    secrets: &mut Vec<PendingSecret>,
    line: usize,
) -> Result<Value, MigrationError> {
    match value {
        Value::Object(object) => {
            let mut sanitized = Map::new();
            for (key, value) in object {
                let child_path = format!("{path}.{key}");
                if secret_kind(&key).is_some() {
                    if value.is_null() {
                        continue;
                    }
                    let kind = secret_kind(&key).expect("checked above").to_owned();
                    let plaintext = match value {
                        Value::String(value) => value.into_bytes(),
                        value => serde_json::to_vec(&value)?,
                    };
                    if plaintext.is_empty() {
                        return Err(MigrationError::InvalidEvent {
                            line,
                            reason: "empty secret-bearing field",
                        });
                    }
                    let id_hash = Sha256::digest(format!("{source_hash}:{child_path}").as_bytes());
                    let reference = CredentialReference {
                        credential_id: format!("legacy:{}", &hex(&id_hash)[..32]),
                        kind,
                        secret_version: 1,
                    };
                    secrets.push(PendingSecret {
                        reference,
                        plaintext,
                    });
                } else {
                    sanitized.insert(
                        key,
                        sanitize_value(value, &child_path, source_hash, secrets, line)?,
                    );
                }
            }
            Ok(Value::Object(sanitized))
        }
        Value::Array(values) => values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                sanitize_value(
                    value,
                    &format!("{path}[{index}]"),
                    source_hash,
                    secrets,
                    line,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        value => Ok(value),
    }
}

fn secret_kind(key: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    match key.as_str() {
        "password_hash" => Some("password"),
        "refresh_token" | "refresh_token_hash" | "access_token" | "id_token" => Some("token"),
        "totp_secret" => Some("totp"),
        "recovery_code" | "recovery_code_hash" | "recovery_codes" => Some("recovery_code"),
        "private_key" | "private_key_pem" | "signing_material" => Some("signing_key"),
        "client_secret" | "client_secret_value" => Some("oauth_client"),
        "pkce_verifier" | "code_verifier" => Some("oauth_verifier"),
        "challenge_state" => Some("challenge"),
        _ => None,
    }
}

fn encrypt_secret(
    cipher: &Aes256Gcm,
    secret: PendingSecret,
    source_hash: &str,
) -> Result<VaultRecord, MigrationError> {
    let nonce = random_bytes::<NONCE_BYTES>()?;
    let aad = format!(
        "{}:{}:{}",
        secret.reference.credential_id, secret.reference.secret_version, source_hash
    );
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &secret.plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| MigrationError::Encryption)?;
    Ok(VaultRecord {
        credential_id: secret.reference.credential_id.clone(),
        kind: secret.reference.kind.clone(),
        secret_version: secret.reference.secret_version,
        key_version: "offline-import-v1".to_owned(),
        nonce_base64: STANDARD_NO_PAD.encode(nonce),
        ciphertext_base64: STANDARD_NO_PAD.encode(ciphertext),
        source_sha256: source_hash.to_owned(),
    })
}

fn verify_outputs(
    output: &Path,
    key: &[u8; 32],
    expected: MigrationReport,
) -> Result<(), MigrationError> {
    let bootstrap_path = output.join(BOOTSTRAP_FILE);
    let vault_path = output.join(VAULT_FILE);
    let mut references = BTreeSet::new();
    let mut event_count = 0_u64;
    for line in BufReader::new(File::open(&bootstrap_path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line)?;
        if contains_forbidden_secret_key(&value) {
            return Err(MigrationError::Verification(
                "bootstrap event retained a secret-bearing field",
            ));
        }
        let event: BootstrapEventReader = serde_json::from_value(value)?;
        if event.event_type != "auth.migration.bootstrap" {
            return Err(MigrationError::Verification(
                "bootstrap event type is not sanitized",
            ));
        }
        for reference in event.payload.credential_references {
            if !references.insert(reference.credential_id) {
                return Err(MigrationError::Verification(
                    "duplicate credential reference",
                ));
            }
        }
        event_count += 1;
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| MigrationError::Encryption)?;
    let mut secrets = BTreeSet::new();
    let mut secret_count = 0_u64;
    for line in BufReader::new(File::open(vault_path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: VaultRecord = serde_json::from_str(&line)?;
        let nonce = STANDARD_NO_PAD
            .decode(&record.nonce_base64)
            .map_err(|_| MigrationError::Verification("invalid vault nonce"))?;
        if nonce.len() != NONCE_BYTES {
            return Err(MigrationError::Verification("invalid vault nonce size"));
        }
        let ciphertext = STANDARD_NO_PAD
            .decode(&record.ciphertext_base64)
            .map_err(|_| MigrationError::Verification("invalid vault ciphertext"))?;
        let aad = format!(
            "{}:{}:{}",
            record.credential_id, record.secret_version, record.source_sha256
        );
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| MigrationError::Verification("vault authentication failed"))?;
        if plaintext.is_empty() {
            return Err(MigrationError::Verification("empty vault secret"));
        }
        plaintext.fill(0);
        secrets.insert(record.credential_id);
        secret_count += 1;
    }
    if event_count != expected.event_count
        || secret_count != expected.secret_count
        || references != secrets
    {
        return Err(MigrationError::Verification("count or reference mismatch"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct BootstrapEventReader {
    event_type: String,
    payload: BootstrapPayloadReader,
}

#[derive(Deserialize)]
struct BootstrapPayloadReader {
    credential_references: Vec<CredentialReference>,
}

fn contains_forbidden_secret_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| secret_kind(key).is_some() || contains_forbidden_secret_key(value)),
        Value::Array(values) => values.iter().any(contains_forbidden_secret_key),
        _ => false,
    }
}

fn private_file(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], MigrationError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| MigrationError::Encryption)?;
    Ok(bytes)
}

fn file_hash(path: &Path) -> Result<String, MigrationError> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_extracts_secrets_and_never_copies_legacy_events_verbatim() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("legacy.jsonl");
        fs::write(
            &input,
            concat!(
                r#"{"event_id":"old-1","aggregate_type":"auth_password_credential","aggregate_id":"user-1","revision":1,"event_type":"auth_password_hash_set","payload":{"PasswordHashSet":{"user_id":"user-1","tenant_id":"tenant-1","password_hash":"$argon2id$secret","hash_algorithm":"argon2id","changed_at_ms":10}}}"#,
                "\n",
                r#"{"event_id":"old-2","aggregate_type":"auth_session","aggregate_id":"session-1","revision":1,"event_type":"auth_session_issued","payload":{"SessionIssued":{"user_id":"user-1","refresh_token_hash":"refresh-secret","expires_at_ms":20}}}"#,
                "\n"
            ),
        )
        .unwrap();
        let output = temporary.path().join("output");
        let report = migrate(&MigrationConfig {
            input,
            output: output.clone(),
            key: [7_u8; 32],
        })
        .unwrap();

        assert_eq!(
            report,
            MigrationReport {
                event_count: 2,
                secret_count: 2,
            }
        );
        let bootstrap = fs::read_to_string(output.join(BOOTSTRAP_FILE)).unwrap();
        assert!(!bootstrap.contains("$argon2id$secret"));
        assert!(!bootstrap.contains("refresh-secret"));
        assert!(!bootstrap.contains(r#""password_hash""#));
        assert!(!bootstrap.contains(r#""refresh_token_hash""#));
        assert!(bootstrap.contains("auth.migration.bootstrap"));
        assert!(bootstrap.contains("credential_references"));
        let manifest: Value =
            serde_json::from_str(&fs::read_to_string(output.join(MANIFEST_FILE)).unwrap()).unwrap();
        assert_eq!(manifest["verified"], true);
    }

    #[test]
    fn migration_refuses_to_overwrite_an_existing_destination() {
        let temporary = tempfile::tempdir().unwrap();
        let input = temporary.path().join("legacy.jsonl");
        fs::write(&input, "").unwrap();
        let output = temporary.path().join("output");
        fs::create_dir(&output).unwrap();

        let error = migrate(&MigrationConfig {
            input,
            output,
            key: [7_u8; 32],
        })
        .unwrap_err();
        assert!(matches!(error, MigrationError::OutputExists));
    }

    #[test]
    fn key_file_accepts_hex_without_exposing_it_in_debug() {
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("key");
        fs::write(
            &key_path,
            "0707070707070707070707070707070707070707070707070707070707070707\n",
        )
        .unwrap();
        let key = load_key_file(&key_path).unwrap();
        assert_eq!(key, [7_u8; 32]);
        let config = MigrationConfig {
            input: PathBuf::from("input"),
            output: PathBuf::from("output"),
            key,
        };
        assert!(!format!("{config:?}").contains("07070707"));
    }
}
