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

/// Invalid transactional-mail product or public URL configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransactionalMailConfigError {
    /// Product name was empty, oversized, or contained control characters.
    #[error("transactional mail product name is invalid")]
    InvalidProductName,
    /// Action URL or public base URL violated the HTTPS/loopback contract.
    #[error("transactional mail action URL is invalid")]
    InvalidActionUrl,
    /// An action token violated the bounded URL contract.
    #[error("transactional mail action token is invalid")]
    InvalidActionToken,
}

/// Validated product name used when rendering transactional mail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailProductName(String);

impl MailProductName {
    /// Creates a bounded, printable product name.
    ///
    /// # Errors
    ///
    /// Rejects empty, surrounding-whitespace, oversized, or control content.
    pub fn new(value: impl Into<String>) -> Result<Self, TransactionalMailConfigError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 80
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(TransactionalMailConfigError::InvalidProductName);
        }
        Ok(Self(value))
    }

    /// Returns the validated display name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated absolute URL containing a one-time mail action.
#[derive(Clone, Eq, PartialEq)]
pub struct MailActionUrl(String);

impl MailActionUrl {
    /// Creates an HTTPS URL or loopback HTTP URL without credentials/fragments.
    ///
    /// # Errors
    ///
    /// Rejects malformed, insecure, credential-bearing, fragmented, or
    /// oversized URLs.
    pub fn new(value: impl Into<String>) -> Result<Self, TransactionalMailConfigError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 2_048
            || value.chars().any(char::is_whitespace)
            || value.contains('#')
        {
            return Err(TransactionalMailConfigError::InvalidActionUrl);
        }
        let (secure, remainder) = if let Some(remainder) = value.strip_prefix("https://") {
            (true, remainder)
        } else if let Some(remainder) = value.strip_prefix("http://") {
            (false, remainder)
        } else {
            return Err(TransactionalMailConfigError::InvalidActionUrl);
        };
        let authority = remainder
            .split(['/', '?'])
            .next()
            .ok_or(TransactionalMailConfigError::InvalidActionUrl)?;
        if authority.is_empty() || authority.contains('@') {
            return Err(TransactionalMailConfigError::InvalidActionUrl);
        }
        if !secure {
            let host = authority
                .strip_prefix('[')
                .and_then(|value| value.split_once(']').map(|(host, _)| host))
                .unwrap_or_else(|| authority.split(':').next().unwrap_or_default());
            if !matches!(host, "localhost" | "127.0.0.1" | "::1") {
                return Err(TransactionalMailConfigError::InvalidActionUrl);
            }
        }
        Ok(Self(value))
    }

    /// Returns the validated absolute action URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MailActionUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MailActionUrl([REDACTED])")
    }
}

/// Startup-validated product and public-origin mail configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionalMailConfig {
    product_name: MailProductName,
    public_base_url: String,
}

impl TransactionalMailConfig {
    /// Validates the product name and an HTTPS or loopback HTTP origin.
    ///
    /// # Errors
    ///
    /// Rejects public origins containing paths, queries, fragments, or
    /// credentials.
    pub fn new(
        product_name: MailProductName,
        public_base_url: impl Into<String>,
    ) -> Result<Self, TransactionalMailConfigError> {
        let public_base_url = public_base_url.into();
        let trimmed = public_base_url.trim_end_matches('/');
        MailActionUrl::new(format!("{trimmed}/"))?;
        let scheme_end = trimmed
            .find("://")
            .ok_or(TransactionalMailConfigError::InvalidActionUrl)?
            + 3;
        if trimmed[scheme_end..].contains(['/', '?', '#']) {
            return Err(TransactionalMailConfigError::InvalidActionUrl);
        }
        Ok(Self {
            product_name,
            public_base_url: trimmed.to_owned(),
        })
    }

    /// Renders one immutable action message for durable enqueue.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, or control-character-containing token.
    pub fn render(
        &self,
        kind: EmailKind,
        token: &str,
    ) -> Result<(MailActionUrl, RenderedTransactionalMail), TransactionalMailConfigError> {
        if token.is_empty()
            || token.len() > 1_024
            || token.chars().any(char::is_control)
            || token.contains(['&', '#'])
        {
            return Err(TransactionalMailConfigError::InvalidActionToken);
        }
        let path = match kind {
            EmailKind::Verification => "/verify-email",
            EmailKind::PasswordReset => "/reset-password",
            EmailKind::Invitation => "/invitations/accept",
            EmailKind::SecurityNotification => "/account/security",
        };
        let action_url =
            MailActionUrl::new(format!("{}{path}?token={token}", self.public_base_url))?;
        let rendered =
            render_transactional_mail(kind, action_url.as_str(), self.product_name.as_str());
        Ok((action_url, rendered))
    }
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
    html_body: Option<String>,
    action_url: Option<MailActionUrl>,
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
            html_body: None,
            action_url: None,
            correlation_id: correlation_id.into(),
        })
    }

    /// Attaches an HTML body for multipart delivery.
    ///
    /// # Errors
    ///
    /// Returns [`MailMessageError::InvalidBody`] when the HTML is empty or oversized.
    pub fn with_html_body(
        mut self,
        html_body: impl Into<String>,
    ) -> Result<Self, MailMessageError> {
        let html_body = html_body.into();
        if html_body.is_empty() || html_body.len() > 128 * 1024 {
            return Err(MailMessageError::InvalidBody);
        }
        self.html_body = Some(html_body);
        Ok(self)
    }

    /// Attaches the validated one-time action URL for capture and auditing.
    #[must_use]
    pub fn with_action_url(mut self, action_url: MailActionUrl) -> Self {
        self.action_url = Some(action_url);
        self
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

    /// Returns the optional HTML body for multipart delivery.
    #[must_use]
    pub fn html_body(&self) -> Option<&str> {
        self.html_body.as_deref()
    }

    /// Returns the non-secret correlation identifier.
    #[must_use]
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    /// First absolute `http(s)` URL found in the text body (for capture/dev tools).
    #[must_use]
    pub fn action_url(&self) -> Option<&str> {
        self.action_url
            .as_ref()
            .map(MailActionUrl::as_str)
            .or_else(|| first_http_url(self.text_body.as_str()))
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
            .field("html_body", &self.html_body.as_ref().map(|_| "[REDACTED]"))
            .field(
                "action_url",
                &self.action_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("correlation_id", &self.correlation_id)
            .finish()
    }
}

/// Productized subject + multipart bodies for a one-time action link.
#[derive(Clone, Eq, PartialEq)]
pub struct RenderedTransactionalMail {
    /// Message subject line.
    pub subject: String,
    /// Plain-text body (always present).
    pub text_body: String,
    /// HTML body with a primary CTA button.
    pub html_body: String,
}

impl fmt::Debug for RenderedTransactionalMail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedTransactionalMail")
            .field("subject", &self.subject)
            .field("text_body", &"[REDACTED]")
            .field("html_body", &"[REDACTED]")
            .finish()
    }
}

/// Renders verification, password-reset, or invitation copy for `action_url`.
///
/// `product_name` appears in the subject and body (for example `Goldcoders`).
/// The plain-text body is intentionally multi-paragraph so clients never show
/// only a bare URL. HTML is a simple table layout for broad client support.
#[must_use]
pub fn render_transactional_mail(
    kind: EmailKind,
    action_url: &str,
    product_name: &str,
) -> RenderedTransactionalMail {
    let product = if product_name.trim().is_empty() {
        "Goldcoders"
    } else {
        product_name.trim()
    };
    let (subject, heading, intro, cta, ignore) = match kind {
        EmailKind::Verification => (
            format!("Verify your email for {product}"),
            "Verify your email".to_owned(),
            format!(
                "Thanks for signing up for {product}. Confirm this email address so we can finish creating your account and keep it secure."
            ),
            "Verify email address",
            "If you did not create an account, you can ignore this message. No account will be activated without verification.",
        ),
        EmailKind::PasswordReset => (
            format!("Reset your {product} password"),
            "Reset your password".to_owned(),
            format!(
                "We received a request to reset the password for your {product} account. Use the button below within the next hour to choose a new password."
            ),
            "Reset password",
            "If you did not request a password reset, you can ignore this message. Your password will stay the same.",
        ),
        EmailKind::Invitation => (
            format!("You are invited to join a {product} organization"),
            "Organization invitation".to_owned(),
            format!(
                "You have been invited to join an organization on {product}. Open the link below, sign in with this email address, then accept the invitation."
            ),
            "Accept invitation",
            "If you were not expecting this invitation, you can ignore this message.",
        ),
        EmailKind::SecurityNotification => (
            format!("Security notice from {product}"),
            "Security notice".to_owned(),
            format!(
                "A security-sensitive change was made on your {product} account. Review your account if this was not you."
            ),
            "Review account",
            "If you do not recognize this activity, change your password and review active sessions immediately.",
        ),
    };

    // Multi-line plain text first so every client (including text-only previews)
    // shows human copy around the one-time link — never a bare URL alone.
    let text_body = format!(
        "Hi,\n\n\
         {intro}\n\n\
         {cta}:\n\
         {action_url}\n\n\
         If the button or link above does not work, copy and paste the full URL into your browser.\n\n\
         {ignore}\n\n\
         —\n\
         {product}\n\
         This is an automated message; replies are not monitored.\n"
    );

    let safe_url = html_escape(action_url);
    let safe_product = html_escape(product);
    let safe_intro = html_escape(&intro);
    let safe_heading = html_escape(&heading);
    let safe_cta = html_escape(cta);
    let safe_ignore = html_escape(ignore);
    let safe_subject = html_escape(&subject);
    let html_body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <meta name="supported-color-schemes" content="light">
  <title>{safe_subject}</title>
</head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#18181b;-webkit-font-smoothing:antialiased;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">
    {safe_intro}
  </div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f4f5;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;background:#ffffff;border:1px solid #e4e4e7;border-radius:12px;">
        <tr><td style="padding:28px 28px 8px;font-size:12px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#71717a;">{safe_product}</td></tr>
        <tr><td style="padding:8px 28px 0;font-size:22px;font-weight:600;letter-spacing:-0.02em;line-height:1.25;color:#18181b;">{safe_heading}</td></tr>
        <tr><td style="padding:14px 28px 0;font-size:15px;line-height:1.65;color:#52525b;">{safe_intro}</td></tr>
        <tr><td style="padding:28px 28px 0;" align="left">
          <a href="{safe_url}" style="display:inline-block;background:#18181b;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;line-height:1;padding:14px 20px;border-radius:8px;">{safe_cta}</a>
        </td></tr>
        <tr><td style="padding:24px 28px 0;font-size:13px;line-height:1.55;color:#71717a;">Button not working? Copy and paste this link into your browser:</td></tr>
        <tr><td style="padding:8px 28px 0;font-size:13px;line-height:1.5;word-break:break-all;"><a href="{safe_url}" style="color:#18181b;text-decoration:underline;">{safe_url}</a></td></tr>
        <tr><td style="padding:28px;border-top:1px solid #e4e4e7;font-size:12px;line-height:1.55;color:#a1a1aa;">{safe_ignore}<br><br>This is an automated message from {safe_product}.</td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"#
    );

    RenderedTransactionalMail {
        subject,
        text_body,
        html_body,
    }
}

#[derive(Serialize)]
struct DurableMailPayloadV2<'a> {
    version: u8,
    kind: &'a str,
    recipient: &'a str,
    subject: &'a str,
    text_body: &'a str,
    html_body: &'a str,
    action_url: &'a str,
}

pub(crate) fn durable_transactional_mail_payload(
    config: &TransactionalMailConfig,
    kind: EmailKind,
    recipient: &str,
    token: &str,
) -> Result<Vec<u8>, ()> {
    let (action_url, rendered) = config.render(kind, token).map_err(|_| ())?;
    let kind = match kind {
        EmailKind::Verification => "email_verification",
        EmailKind::PasswordReset => "password_reset",
        EmailKind::Invitation => "invitation",
        EmailKind::SecurityNotification => "security_notification",
    };
    serde_json::to_vec(&DurableMailPayloadV2 {
        version: 2,
        kind,
        recipient,
        subject: &rendered.subject,
        text_body: &rendered.text_body,
        html_body: &rendered.html_body,
        action_url: action_url.as_str(),
    })
    .map_err(|_| ())
}

fn first_http_url(text: &str) -> Option<&str> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(url) = trimmed
            .split_whitespace()
            .find(|part| part.starts_with("http://") || part.starts_with("https://"))
        {
            return Some(url);
        }
    }
    None
}

fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
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
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<&'a str>,
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
            html: message.html_body(),
            correlation_id: message.correlation_id(),
        }
    }
}

#[cfg(feature = "mail-http")]
#[derive(Deserialize)]
struct HttpWebhookResponse {
    delivery_id: String,
}

/// Secret API credential for the Resend email API.
#[cfg(feature = "mail-resend")]
#[derive(Clone)]
pub struct ResendApiKey(String);

#[cfg(feature = "mail-resend")]
impl ResendApiKey {
    /// Validates a bounded Resend API key.
    ///
    /// # Errors
    ///
    /// Returns [`ResendConfigurationError::InvalidApiKey`] for malformed input.
    pub fn new(value: impl Into<String>) -> Result<Self, ResendConfigurationError> {
        let value = value.into();
        if !value.starts_with("re_") || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err(ResendConfigurationError::InvalidApiKey);
        }
        Ok(Self(value))
    }
}

#[cfg(feature = "mail-resend")]
impl fmt::Debug for ResendApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResendApiKey([REDACTED])")
    }
}

/// Validated sender identity used by Resend.
#[cfg(feature = "mail-resend")]
#[derive(Clone, Debug)]
pub struct ResendFromAddress(String);

#[cfg(feature = "mail-resend")]
impl ResendFromAddress {
    /// Validates a sender address or `Name <address>` identity.
    ///
    /// # Errors
    ///
    /// Returns [`ResendConfigurationError::InvalidFromAddress`] for malformed input.
    pub fn new(value: impl Into<String>) -> Result<Self, ResendConfigurationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 320
            || value.chars().any(char::is_control)
            || !value.contains('@')
        {
            return Err(ResendConfigurationError::InvalidFromAddress);
        }
        Ok(Self(value))
    }
}

/// Invalid Resend adapter configuration.
#[cfg(feature = "mail-resend")]
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ResendConfigurationError {
    /// API key is missing, malformed, or oversized.
    #[error("Resend API key is invalid")]
    InvalidApiKey,
    /// Sender identity is missing, malformed, or oversized.
    #[error("Resend sender identity is invalid")]
    InvalidFromAddress,
}

/// Resend delivery failure with provider details and credentials redacted.
#[cfg(feature = "mail-resend")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ResendMailError {
    /// Request serialization or construction failed.
    #[error("Resend mail request is invalid")]
    InvalidRequest,
    /// Runtime outbound HTTP failed.
    #[error("Resend mail transport failed")]
    Transport(#[source] Box<dyn StdError + Send + Sync>),
    /// Resend returned a non-success status.
    #[error("Resend rejected delivery")]
    Provider,
    /// Resend returned a malformed or oversized response.
    #[error("Resend response is invalid")]
    InvalidResponse,
}

/// Transactional mail adapter for Resend's `POST /emails` API.
///
/// The outbox correlation ID is sent as Resend's idempotency key so retries
/// remain safe after a provider success followed by a lost database ack.
#[cfg(feature = "mail-resend")]
#[derive(Clone)]
pub struct ResendMailer<T> {
    api_key: ResendApiKey,
    from: ResendFromAddress,
    transport: T,
}

#[cfg(feature = "mail-resend")]
impl<T> fmt::Debug for ResendMailer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResendMailer")
            .field("api_key", &self.api_key)
            .field("from", &"[REDACTED]")
            .field("transport", &"[REDACTED]")
            .finish()
    }
}

#[cfg(feature = "mail-resend")]
impl<T> ResendMailer<T> {
    /// Constructs a Resend mailer with validated configuration.
    #[must_use]
    pub const fn new(api_key: ResendApiKey, from: ResendFromAddress, transport: T) -> Self {
        Self {
            api_key,
            from,
            transport,
        }
    }
}

#[cfg(feature = "mail-resend")]
impl<T> Mailer for ResendMailer<T>
where
    T: HttpMailTransport,
{
    type Error = ResendMailError;

    async fn send(&self, message: &EmailMessage) -> Result<DeliveryId, Self::Error> {
        let body = serde_json::to_vec(&ResendRequest {
            from: &self.from.0,
            to: [message.recipient().as_str()],
            subject: message.subject(),
            text: message.text_body(),
            html: message.html_body(),
        })
        .map_err(|_| ResendMailError::InvalidRequest)?;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("https://api.resend.com/emails")
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .header(AUTHORIZATION, format!("Bearer {}", self.api_key.0))
            .header("Idempotency-Key", message.correlation_id())
            .body(body)
            .map_err(|_| ResendMailError::InvalidRequest)?;
        let response = self
            .transport
            .send(request)
            .await
            .map_err(|error| ResendMailError::Transport(Box::new(error)))?;
        if !response.status().is_success() {
            return Err(ResendMailError::Provider);
        }
        if response.body().len() > MAX_WEBHOOK_RESPONSE_BYTES {
            return Err(ResendMailError::InvalidResponse);
        }
        let response: ResendResponse = serde_json::from_slice(response.body())
            .map_err(|_| ResendMailError::InvalidResponse)?;
        if response.id.is_empty()
            || response.id.len() > 512
            || response.id.chars().any(char::is_control)
        {
            return Err(ResendMailError::InvalidResponse);
        }
        Ok(DeliveryId::new(response.id))
    }
}

#[cfg(feature = "mail-resend")]
#[derive(Serialize)]
struct ResendRequest<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<&'a str>,
}

#[cfg(feature = "mail-resend")]
#[derive(Deserialize)]
struct ResendResponse {
    id: String,
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
        .expect("valid fixture")
        .with_html_body("<a href=\"https://example.test/reset?token=secret\">Reset</a>")
        .expect("html");

        let debug = format!("{message:?}");

        assert!(!debug.contains("token=secret"));
        assert_eq!(
            message.action_url(),
            Some("https://example.test/reset?token=secret")
        );
    }

    #[test]
    fn transactional_templates_include_copy_cta_and_fallback_url() {
        let action = "http://127.0.0.1:3008/reset-password?token=abc";
        let rendered = render_transactional_mail(EmailKind::PasswordReset, action, "Goldcoders");
        assert!(rendered.subject.contains("password"));
        assert!(rendered.subject.contains("Goldcoders"));
        assert!(rendered.text_body.contains(action));
        assert!(rendered.text_body.contains("Hi,"));
        assert!(rendered.text_body.contains("If you did not request"));
        assert!(rendered.text_body.lines().count() > 5);
        assert_ne!(rendered.text_body.trim(), action);
        assert!(rendered.html_body.contains("Reset password"));
        assert!(rendered.html_body.contains(action));
        assert!(
            rendered
                .html_body
                .to_ascii_lowercase()
                .contains("copy and paste")
        );
        assert!(rendered.html_body.contains("<a href="));
    }

    #[test]
    fn verification_template_is_never_bare_url() {
        let action = "http://127.0.0.1:3008/verify-email?token=rZvuvY4qECzorVq9GlDYsz";
        let rendered = render_transactional_mail(EmailKind::Verification, action, "Goldcoders");
        assert!(rendered.subject.starts_with("Verify your email"));
        assert!(rendered.text_body.contains("Thanks for signing up"));
        assert!(rendered.text_body.contains(action));
        assert!(rendered.html_body.contains("Verify email address"));
        assert!(rendered.html_body.contains("Thanks for signing up"));
        assert_ne!(rendered.text_body.trim(), action);
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

    #[test]
    #[cfg(feature = "mail-resend")]
    fn resend_mailer_uses_provider_contract_and_redacts_credentials() {
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
                    .status(200)
                    .header(CONTENT_TYPE, "application/json")
                    .body(br#"{"id":"resend-message-123"}"#.to_vec())
                    .expect("response"))
            }
        }

        let mailer = ResendMailer::new(
            ResendApiKey::new("re_super-secret").expect("API key"),
            ResendFromAddress::new("Workspace <auth@example.test>").expect("sender"),
            FakeTransport::default(),
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
        assert_eq!(delivery.as_str(), "resend-message-123");
        let request = mailer
            .transport
            .request
            .lock()
            .expect("request lock")
            .take()
            .expect("request captured");
        assert_eq!(request.uri(), "https://api.resend.com/emails");
        assert_eq!(request.headers()["Idempotency-Key"], "mail-123");
        let body: serde_json::Value = serde_json::from_slice(request.body()).expect("JSON body");
        assert_eq!(body["from"], "Workspace <auth@example.test>");
        assert_eq!(body["to"][0], "user@example.test");
        let debug = format!("{mailer:?}");
        assert!(!debug.contains("re_super-secret"));
        assert!(!debug.contains("auth@example.test"));
    }
}
