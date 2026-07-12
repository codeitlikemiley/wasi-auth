//! Provider-neutral transactional email contracts.

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "mail-http")]
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
#[cfg(feature = "mail-http")]
use http::{Request, Response, Uri};

#[cfg(feature = "mail-http")]
const MAX_WEBHOOK_RESPONSE_BYTES: usize = 16 * 1024;

/// Transactional email category used for auditing and templates.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum EmailKind {
    /// New account email verification.
    Verification,
    /// Password reset request.
    PasswordReset,
    /// Organization membership invitation.
    Invitation,
    /// Credential, MFA, or session security notification.
    SecurityNotification,
}

/// Validated email recipient.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Recipient(String);

impl Recipient {
    /// Validates a recipient address for the application mail boundary.
    ///
    /// This is deliberately a bounded structural check; SMTP providers remain
    /// responsible for authoritative mailbox validation.
    ///
    /// # Errors
    ///
    /// Returns [`MailMessageError::InvalidRecipient`] for malformed input.
    pub fn new(value: impl Into<String>) -> Result<Self, MailMessageError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed != value
            || value.len() > 320
            || value.chars().any(char::is_control)
            || value.split_once('@').is_none_or(|(local, domain)| {
                local.is_empty() || domain.is_empty() || !domain.contains('.')
            })
        {
            return Err(MailMessageError::InvalidRecipient);
        }
        Ok(Self(value))
    }

    /// Returns the validated recipient.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Failure while constructing an outbound message.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum MailMessageError {
    /// The recipient did not satisfy the bounded address contract.
    #[error("mail recipient is invalid")]
    InvalidRecipient,
    /// The subject was empty, oversized, or contained control characters.
    #[error("mail subject is invalid")]
    InvalidSubject,
    /// The message body was empty or exceeded the transactional email bound.
    #[error("mail body is invalid")]
    InvalidBody,
}

/// Sensitive transactional email ready for a concrete delivery adapter.
///
/// Debug output is intentionally redacted because verification, reset, and
/// invitation bodies can contain one-time bearer secrets.
#[derive(Clone)]
pub struct EmailMessage {
    kind: EmailKind,
    recipient: Recipient,
    subject: String,
    text_body: String,
    correlation_id: String,
}

impl EmailMessage {
    /// Constructs a bounded message.
    ///
    /// # Errors
    ///
    /// Returns [`MailMessageError`] for invalid subject or body content.
    pub fn new(
        kind: EmailKind,
        recipient: Recipient,
        subject: impl Into<String>,
        text_body: impl Into<String>,
        correlation_id: impl Into<String>,
    ) -> Result<Self, MailMessageError> {
        let subject = subject.into();
        if subject.is_empty() || subject.len() > 200 || subject.chars().any(char::is_control) {
            return Err(MailMessageError::InvalidSubject);
        }
        let text_body = text_body.into();
        if text_body.is_empty() || text_body.len() > 128 * 1024 {
            return Err(MailMessageError::InvalidBody);
        }
        Ok(Self {
            kind,
            recipient,
            subject,
            text_body,
            correlation_id: correlation_id.into(),
        })
    }

    /// Returns the message category.
    #[must_use]
    pub const fn kind(&self) -> EmailKind {
        self.kind
    }

    /// Returns the recipient.
    #[must_use]
    pub const fn recipient(&self) -> &Recipient {
        &self.recipient
    }

    /// Returns the message subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the sensitive text body for a delivery adapter.
    #[must_use]
    pub fn text_body(&self) -> &str {
        &self.text_body
    }

    /// Returns the non-secret correlation identifier.
    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
}

impl fmt::Debug for EmailMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailMessage")
            .field("kind", &self.kind)
            .field("recipient", &"[REDACTED]")
            .field("subject", &self.subject)
            .field("text_body", &"[REDACTED]")
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

/// Successful provider delivery identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryId(String);

impl DeliveryId {
    /// Creates a provider delivery identifier.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the provider delivery identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Static-dispatch transactional email provider.
pub trait Mailer: Sync {
    /// Provider-specific delivery error.
    type Error: StdError + Send + Sync + 'static;

    /// Delivers one message.
    fn send<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> impl Future<Output = Result<DeliveryId, Self::Error>> + Send + 'a;
}

/// Generic adapter error used by host-provided SMTP and HTTP transports.
#[derive(Debug, Error)]
#[error("mail transport failed")]
pub struct MailTransportError(#[source] pub Box<dyn StdError + Send + Sync>);

/// Host SMTP transport used by [`SmtpMailer`].
#[cfg(feature = "mail-smtp")]
pub trait SmtpTransport: Sync {
    /// Sends one already-validated message.
    fn deliver<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> impl Future<Output = Result<DeliveryId, MailTransportError>> + Send + 'a;
}

/// SMTP mailer backed by a host-specific transport.
#[cfg(feature = "mail-smtp")]
#[derive(Clone, Debug)]
pub struct SmtpMailer<T> {
    transport: T,
}

#[cfg(feature = "mail-smtp")]
impl<T> SmtpMailer<T> {
    /// Wraps a host SMTP transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }
}

#[cfg(feature = "mail-smtp")]
impl<T> Mailer for SmtpMailer<T>
where
    T: SmtpTransport,
{
    type Error = MailTransportError;

    fn send<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> impl Future<Output = Result<DeliveryId, Self::Error>> + Send + 'a {
        self.transport.deliver(message)
    }
}

/// Runtime HTTP transport used by [`HttpMailer`].
#[cfg(feature = "mail-http")]
pub trait HttpMailTransport: Sync {
    /// Transport-specific failure.
    type Error: StdError + Send + Sync + 'static;

    /// Sends one bounded webhook request.
    fn send<'a>(
        &'a self,
        request: Request<Vec<u8>>,
    ) -> impl Future<Output = Result<Response<Vec<u8>>, Self::Error>> + Send + 'a;
}

/// HTTP webhook endpoint accepted by the production mail adapter.
#[cfg(feature = "mail-http")]
#[derive(Clone)]
pub struct HttpMailEndpoint(Uri);

#[cfg(feature = "mail-http")]
impl HttpMailEndpoint {
    /// Parses an HTTPS endpoint or loopback HTTP endpoint for local testing.
    ///
    /// # Errors
    ///
    /// Returns [`HttpMailConfigurationError`] for malformed or unsafe input.
    pub fn new(value: &str) -> Result<Self, HttpMailConfigurationError> {
        let uri = value
            .parse::<Uri>()
            .map_err(|_| HttpMailConfigurationError::InvalidEndpoint)?;
        let scheme = uri
            .scheme_str()
            .ok_or(HttpMailConfigurationError::InvalidEndpoint)?;
        let host = uri
            .host()
            .ok_or(HttpMailConfigurationError::InvalidEndpoint)?;
        let authority = uri
            .authority()
            .ok_or(HttpMailConfigurationError::InvalidEndpoint)?;
        let secure = scheme == "https";
        let loopback = scheme == "http" && matches!(host, "localhost" | "127.0.0.1" | "[::1]");
        if (!secure && !loopback)
            || authority.as_str().contains('@')
            || uri.query().is_some()
            || uri.path().is_empty()
            || uri.path() == "/"
        {
            return Err(HttpMailConfigurationError::InvalidEndpoint);
        }
        Ok(Self(uri))
    }
}

#[cfg(feature = "mail-http")]
impl fmt::Debug for HttpMailEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpMailEndpoint([REDACTED])")
    }
}

/// Secret bearer credential for an HTTP mail webhook.
#[cfg(feature = "mail-http")]
#[derive(Clone)]
pub struct HttpMailBearerToken(String);

#[cfg(feature = "mail-http")]
impl HttpMailBearerToken {
    /// Validates a bounded bearer credential.
    ///
    /// # Errors
    ///
    /// Returns [`HttpMailConfigurationError`] for empty or malformed input.
    pub fn new(value: impl Into<String>) -> Result<Self, HttpMailConfigurationError> {
        let value = value.into();
        if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err(HttpMailConfigurationError::InvalidBearerToken);
        }
        Ok(Self(value))
    }
}

#[cfg(feature = "mail-http")]
impl fmt::Debug for HttpMailBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HttpMailBearerToken([REDACTED])")
    }
}

/// Invalid HTTP mail adapter configuration.
#[cfg(feature = "mail-http")]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum HttpMailConfigurationError {
    /// Endpoint is malformed or does not use HTTPS/loopback HTTP.
    #[error("HTTP mail endpoint is invalid")]
    InvalidEndpoint,
    /// Bearer credential is malformed.
    #[error("HTTP mail bearer token is invalid")]
    InvalidBearerToken,
}

/// HTTP mail delivery failure with all provider details redacted.
#[cfg(feature = "mail-http")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpMailError {
    /// Request serialization or construction failed.
    #[error("HTTP mail request is invalid")]
    InvalidRequest,
    /// Runtime outbound HTTP failed.
    #[error("HTTP mail transport failed")]
    Transport(#[source] Box<dyn StdError + Send + Sync>),
    /// Provider returned a non-success status.
    #[error("HTTP mail provider rejected delivery")]
    Provider,
    /// Provider returned a malformed or oversized response.
    #[error("HTTP mail provider response is invalid")]
    InvalidResponse,
}

/// HTTP-webhook mailer backed by a runtime outbound HTTP client.
///
/// The request body is the versioned JSON contract
/// `wasi-auth.mail.v1`. `correlation_id` is also sent as the
/// `Idempotency-Key` header, allowing safe at-least-once outbox retries.
#[cfg(feature = "mail-http")]
#[derive(Clone)]
pub struct HttpMailer<T> {
    endpoint: HttpMailEndpoint,
    bearer_token: HttpMailBearerToken,
    transport: T,
}

#[cfg(feature = "mail-http")]
impl<T> fmt::Debug for HttpMailer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpMailer")
            .field("endpoint", &self.endpoint)
            .field("bearer_token", &self.bearer_token)
            .field("transport", &"[REDACTED]")
            .finish()
    }
}

#[cfg(feature = "mail-http")]
impl<T> HttpMailer<T> {
    /// Constructs a webhook mailer with validated configuration.
    #[must_use]
    pub const fn new(
        endpoint: HttpMailEndpoint,
        bearer_token: HttpMailBearerToken,
        transport: T,
    ) -> Self {
        Self {
            endpoint,
            bearer_token,
            transport,
        }
    }
}

#[cfg(feature = "mail-http")]
impl<T> Mailer for HttpMailer<T>
where
    T: HttpMailTransport,
{
    type Error = HttpMailError;

    async fn send(&self, message: &EmailMessage) -> Result<DeliveryId, Self::Error> {
        let body = serde_json::to_vec(&HttpWebhookRequest::from(message))
            .map_err(|_| HttpMailError::InvalidRequest)?;
        let authorization = format!("Bearer {}", self.bearer_token.0);
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint.0.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .header(AUTHORIZATION, authorization)
            .header("Idempotency-Key", message.correlation_id())
            .body(body)
            .map_err(|_| HttpMailError::InvalidRequest)?;
        let response = self
            .transport
            .send(request)
            .await
            .map_err(|error| HttpMailError::Transport(Box::new(error)))?;
        if !response.status().is_success() {
            return Err(HttpMailError::Provider);
        }
        if response.body().len() > MAX_WEBHOOK_RESPONSE_BYTES {
            return Err(HttpMailError::InvalidResponse);
        }
        let response: HttpWebhookResponse =
            serde_json::from_slice(response.body()).map_err(|_| HttpMailError::InvalidResponse)?;
        if response.delivery_id.is_empty()
            || response.delivery_id.len() > 512
            || response.delivery_id.chars().any(char::is_control)
        {
            return Err(HttpMailError::InvalidResponse);
        }
        Ok(DeliveryId::new(response.delivery_id))
    }
}

#[cfg(feature = "mail-http")]
#[derive(Serialize)]
struct HttpWebhookRequest<'a> {
    contract: &'static str,
    kind: &'static str,
    to: &'a str,
    subject: &'a str,
    text: &'a str,
    correlation_id: &'a str,
}

#[cfg(feature = "mail-http")]
impl<'a> From<&'a EmailMessage> for HttpWebhookRequest<'a> {
    fn from(message: &'a EmailMessage) -> Self {
        Self {
            contract: "wasi-auth.mail.v1",
            kind: match message.kind() {
                EmailKind::Verification => "verification",
                EmailKind::PasswordReset => "password_reset",
                EmailKind::Invitation => "invitation",
                EmailKind::SecurityNotification => "security_notification",
            },
            to: message.recipient().as_str(),
            subject: message.subject(),
            text: message.text_body(),
            correlation_id: message.correlation_id(),
        }
    }
}

#[cfg(feature = "mail-http")]
#[derive(Deserialize)]
struct HttpWebhookResponse {
    delivery_id: String,
}

/// In-memory message retained by the development capture adapter.
#[cfg(any(test, feature = "mail-capture"))]
#[derive(Clone, Debug)]
pub struct CapturedEmail {
    message: EmailMessage,
    delivery_id: DeliveryId,
}

#[cfg(any(test, feature = "mail-capture"))]
impl CapturedEmail {
    /// Returns the captured message.
    #[must_use]
    pub const fn message(&self) -> &EmailMessage {
        &self.message
    }

    /// Returns its development delivery identifier.
    #[must_use]
    pub const fn delivery_id(&self) -> &DeliveryId {
        &self.delivery_id
    }
}

/// Development-only mail capture sink.
#[cfg(any(test, feature = "mail-capture"))]
#[derive(Debug, Default)]
pub struct CaptureMailer {
    messages: std::sync::Mutex<Vec<CapturedEmail>>,
}

/// Development capture failure.
#[cfg(any(test, feature = "mail-capture"))]
#[derive(Clone, Copy, Debug, Error)]
#[error("development mail capture lock is unavailable")]
pub struct CaptureMailError;

#[cfg(any(test, feature = "mail-capture"))]
impl CaptureMailer {
    /// Returns a snapshot of captured messages.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureMailError`] if the capture lock was poisoned.
    pub fn messages(&self) -> Result<Vec<CapturedEmail>, CaptureMailError> {
        self.messages
            .lock()
            .map(|messages| messages.clone())
            .map_err(|_| CaptureMailError)
    }
}

#[cfg(any(test, feature = "mail-capture"))]
impl Mailer for CaptureMailer {
    type Error = CaptureMailError;

    async fn send(&self, message: &EmailMessage) -> Result<DeliveryId, Self::Error> {
        let mut messages = self.messages.lock().map_err(|_| CaptureMailError)?;
        let delivery_id = DeliveryId::new(format!("capture-{}", messages.len() + 1));
        messages.push(CapturedEmail {
            message: message.clone(),
            delivery_id: delivery_id.clone(),
        });
        Ok(delivery_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_recipient_and_body() {
        let message = EmailMessage::new(
            EmailKind::PasswordReset,
            Recipient::new("user@example.test").expect("valid fixture"),
            "Reset password",
            "https://example.test/reset?token=secret",
            "request-one",
        )
        .expect("valid fixture");

        let debug = format!("{message:?}");

        assert!(!debug.contains("token=secret"));
    }

    #[test]
    #[cfg(feature = "mail-http")]
    fn http_mailer_uses_versioned_idempotent_contract_and_redacts_config() {
        #[derive(Default)]
        struct FakeTransport {
            request: std::sync::Mutex<Option<Request<Vec<u8>>>>,
        }

        impl HttpMailTransport for FakeTransport {
            type Error = std::io::Error;

            async fn send(
                &self,
                request: Request<Vec<u8>>,
            ) -> Result<Response<Vec<u8>>, Self::Error> {
                *self.request.lock().expect("request lock") = Some(request);
                Ok(Response::builder()
                    .status(202)
                    .header(CONTENT_TYPE, "application/json")
                    .body(br#"{"delivery_id":"provider-123"}"#.to_vec())
                    .expect("response"))
            }
        }

        let transport = FakeTransport::default();
        let mailer = HttpMailer::new(
            HttpMailEndpoint::new("https://mail.example.test/v1/send").expect("endpoint"),
            HttpMailBearerToken::new("super-secret-token").expect("token"),
            transport,
        );
        let message = EmailMessage::new(
            EmailKind::Verification,
            Recipient::new("user@example.test").expect("recipient"),
            "Verify email",
            "https://example.test/verify?token=one-time-secret",
            "mail-123",
        )
        .expect("message");

        let delivery = futures::executor::block_on(mailer.send(&message)).expect("delivery");
        assert_eq!(delivery.as_str(), "provider-123");
        let request = mailer
            .transport
            .request
            .lock()
            .expect("request lock")
            .take()
            .expect("request captured");
        assert_eq!(request.headers()["Idempotency-Key"], "mail-123");
        let body: serde_json::Value = serde_json::from_slice(request.body()).expect("JSON body");
        assert_eq!(body["contract"], "wasi-auth.mail.v1");
        assert_eq!(body["kind"], "verification");
        assert_eq!(body["to"], "user@example.test");
        let debug = format!("{mailer:?}");
        assert!(!debug.contains("super-secret-token"));
        assert!(!debug.contains("mail.example.test"));
    }

    #[test]
    #[cfg(feature = "mail-http")]
    fn http_mail_endpoint_rejects_non_loopback_plaintext_http() {
        assert_eq!(
            HttpMailEndpoint::new("http://mail.example.test/v1/send").unwrap_err(),
            HttpMailConfigurationError::InvalidEndpoint
        );
        for endpoint in [
            "https://user:password@mail.example.test/v1/send",
            "https://mail.example.test/v1/send?token=secret",
        ] {
            assert_eq!(
                HttpMailEndpoint::new(endpoint).unwrap_err(),
                HttpMailConfigurationError::InvalidEndpoint
            );
        }
    }
}
