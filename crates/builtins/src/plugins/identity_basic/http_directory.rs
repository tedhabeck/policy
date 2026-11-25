// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Delegated verification: the user-id and password go to a service, and its
// verdict is the record.
//
// Structured after the api-key HTTP backend, and deliberately stricter. That
// backend accepts `http://` and sends no credential of its own, which is
// defensible for high-entropy API keys. Here the request body is a reusable
// password, and the answer is the whole trust decision: a forged
// `valid: true` from anything that can answer is an authentication bypass
// whose fields then become roles. So, unlike the sibling:
//
// - HTTPS is required unless `allow_cleartext` is set.
// - A redirect is not followed. A 307 would replay the password to whatever
//   host its `Location` names.
// - A positive verdict this backend cannot fully read fails rather than
//   resolving to an empty record.
// - The service can be sent a credential of PPE's own, read through the
//   secret provider and never written inline.
//
// Do not harmonise these with the sibling. The difference is what is sent.
//
// TLS material and mutual authentication are not configured here, because the
// transport seam cannot carry them: trust roots and client certificates belong
// to the host that injects the transport. `ca_bundle`, `client_cert` and
// `client_key` are refused by name rather than as unknown keys, so the error
// says where that configuration lives.
//
// Timing across the transport is the service's to equalise. PPE sends the
// same request for a known and an unknown user and reports every failure with
// one message, but cannot establish from here that the service spends the same
// work on both.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use praxis_policy_core::host::{HostServices, HttpRequestError, InitExtensions};
use praxis_policy_core::http::HttpRequest;
use praxis_policy_core::http_retry::RetryPolicy;
use praxis_policy_core::secrets::SecretRef;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::BasicCredential;
use super::cache::CacheConfig;
use super::directory::{CredentialDirectory, DirectoryError, StoredVerifier, UserRecord};
use super::htpasswd::DEFAULT_MAX_CONCURRENT_VERIFICATIONS;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The `kind:` string an operator writes under `provider:`.
pub const KIND: &str = "http";

/// Response fields that describe the answer rather than the subject.
///
/// Stripped before the record reaches the map, together with the configured
/// verdict, expiry and request field names. `reason` in particular explains a
/// refusal, and must reach neither the claims nor a denial message.
pub const ENVELOPE_FIELDS: &[&str] = &["valid", "reason"];

/// A ceiling on the response body a verification will buffer.
const RESPONSE_MAX_BYTES: usize = 65_536; // 64 KiB

/// The default deadline for one verification, in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// What a transport failure reports, ahead of the transport's own error.
///
/// Neither half names the user-id, so a failure cannot become an existence
/// oracle.
const UNREACHABLE: &str = "the verification service could not be reached";

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// The HTTP backend's config block.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpUserConfig {
    /// Permit an `http://` URL, sending the password in cleartext.
    ///
    /// For a service on a loopback or otherwise protected link only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_cleartext: bool,

    /// Refused at load; the host transport owns trust roots.
    #[serde(default, skip_serializing)]
    ca_bundle: Option<IgnoredAny>,

    /// Reuse of the service's answers. Omitted, every request asks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheConfig>,

    /// Refused at load; the host transport owns client identity.
    #[serde(default, skip_serializing)]
    client_cert: Option<IgnoredAny>,

    /// Refused at load; the host transport owns client identity.
    #[serde(default, skip_serializing)]
    client_key: Option<IgnoredAny>,

    /// Bound on connection establishment alone. Left to the transport when
    /// omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_secs: Option<u64>,

    /// The response field carrying an RFC 3339 expiry, when the service
    /// sends one.
    #[serde(default = "default_expires_at_field")]
    pub expires_at_field: String,

    /// The maximum number of verifications in flight.
    ///
    /// Requests beyond this limit are rejected rather than queued.
    #[serde(default = "default_max_concurrent_verifications")]
    pub max_concurrent_verifications: usize,

    /// The request field the password is sent as.
    #[serde(default = "default_password_field")]
    pub password_field: String,

    /// A credential PPE presents to the service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_auth: Option<ServiceAuthConfig>,

    /// Overall deadline for one verification, covering connect and I/O.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Where to send the verification.
    pub url: String,

    /// The request field the user-id is sent as.
    #[serde(default = "default_user_id_field")]
    pub user_id_field: String,

    /// The boolean response field carrying the verdict.
    #[serde(default = "default_valid_field")]
    pub valid_field: String,
}

impl HttpUserConfig {
    /// Reject settings that cannot work, at config load.
    ///
    /// # Errors
    ///
    /// A URL that is not HTTPS without the cleartext opt-in, TLS material, an
    /// empty or colliding field name, a zero timeout, a verification capacity
    /// out of range, or a service credential that cannot be sent as a header.
    pub fn validate(&self) -> Result<(), String> {
        let url = self.url.to_ascii_lowercase();
        if !url.starts_with("https://") {
            if !url.starts_with("http://") {
                return Err(format!(
                    "`url` must be an absolute https URL, got '{}'",
                    self.url
                ));
            }
            if !self.allow_cleartext {
                return Err(
                    "`url` is http, which would send every password in cleartext; use https, \
                     or set `allow_cleartext: true` for a protected link"
                        .to_owned(),
                );
            }
        }
        if self.ca_bundle.is_some() || self.client_cert.is_some() || self.client_key.is_some() {
            return Err(
                "`ca_bundle`, `client_cert` and `client_key` are not settings of this backend: \
                 the host transport owns trust roots and client certificates, so configure \
                 them there"
                    .to_owned(),
            );
        }
        let names = [
            ("user_id_field", &self.user_id_field),
            ("password_field", &self.password_field),
            ("valid_field", &self.valid_field),
            ("expires_at_field", &self.expires_at_field),
        ];
        if let Some((key, _)) = names.iter().find(|(_, name)| name.trim().is_empty()) {
            return Err(format!("`{key}` is empty"));
        }
        if self.user_id_field == self.password_field {
            return Err("`user_id_field` and `password_field` name the same field".to_owned());
        }
        if self.timeout_secs == 0 {
            return Err("`timeout_secs` is zero, so every verification would time out".to_owned());
        }
        if self.max_concurrent_verifications == 0
            || self.max_concurrent_verifications > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(format!(
                "`max_concurrent_verifications` must be between 1 and {}",
                tokio::sync::Semaphore::MAX_PERMITS
            ));
        }
        if let Some(cache) = &self.cache {
            cache.validate()?;
        }
        if let Some(auth) = &self.service_auth {
            auth.validate()?;
        }
        Ok(())
    }
}

/// A credential PPE presents to the verification service, read from a
/// declared secret.
///
/// The plugin entry must grant `read_secret:<secret>`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAuthConfig {
    /// The request header the credential is sent in.
    #[serde(default = "default_auth_header")]
    pub header: String,

    /// Text sent before the secret, such as `"Bearer "`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,

    /// The `secrets.values` name holding the credential.
    pub secret: String,
}

impl ServiceAuthConfig {
    fn validate(&self) -> Result<(), String> {
        if self.secret.trim().is_empty() {
            return Err("`service_auth.secret` is empty".to_owned());
        }
        HttpRequest::get("https://localhost")
            .header(&self.header, &self.prefix)
            .map(|_| ())
            .map_err(|e| format!("`service_auth.header` or `service_auth.prefix`: {e}"))
    }
}

/// Users verified by a service, reached over HTTP.
#[derive(Debug)]
pub struct HttpUserDirectory {
    config: HttpUserConfig,
    secret: OnceLock<SecretRef>,
    verifications: tokio::sync::Semaphore,
}

impl HttpUserDirectory {
    /// Build the backend.
    ///
    /// # Errors
    ///
    /// Whatever [`HttpUserConfig::validate`] rejects.
    pub fn new(config: HttpUserConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            verifications: tokio::sync::Semaphore::new(config.max_concurrent_verifications),
            config,
            secret: OnceLock::new(),
        })
    }

    /// The request body: the user-id and password as separate JSON fields.
    ///
    /// Escaped straight into a zeroizing buffer sized for the worst case, so
    /// it never reallocates and leaves a copy behind. That is partial: the
    /// transport gets its own copy as `Bytes`, and the host's header map
    /// still holds the inbound credential.
    fn body(&self, credential: &BasicCredential) -> Result<Zeroizing<Vec<u8>>, DirectoryError> {
        credential.password().verify_with(|password| {
            // The decoder admits only UTF-8, so this is unreachable in
            // practice. The error is dropped because it carries an offset.
            let password = std::str::from_utf8(password).map_err(|_offset| {
                DirectoryError::Malformed("the password is not UTF-8".to_owned())
            })?;
            let user_id = credential.user_id();
            let fields = [
                self.config.user_id_field.as_str(),
                user_id,
                self.config.password_field.as_str(),
                password,
            ];
            // JSON escapes a byte to at most six (`\u001f`), plus quotes and
            // punctuation.
            let capacity = fields.iter().fold(16_usize, |total, field| {
                total.saturating_add(field.len().saturating_mul(6).saturating_add(3))
            });
            let mut body = Zeroizing::new(Vec::with_capacity(capacity));
            for (position, field) in fields.iter().enumerate() {
                body.push(match position {
                    0 => b'{',
                    2 => b',',
                    _ => b':',
                });
                serde_json::to_writer(&mut *body, field).map_err(|e| {
                    DirectoryError::Malformed(format!("could not encode the request: {e}"))
                })?;
            }
            body.push(b'}');
            Ok(body)
        })
    }

    /// The service credential as a header value, or why it cannot be sent.
    fn service_credential(
        &self,
        auth: &ServiceAuthConfig,
    ) -> Result<Zeroizing<String>, DirectoryError> {
        let Some(secret) = self.secret.get() else {
            return Err(DirectoryError::Unavailable(format!(
                "the service credential `{}` was never resolved, so the password is not sent",
                auth.secret
            )));
        };
        let value = secret.get();
        if value.is_empty() {
            return Err(DirectoryError::Unavailable(format!(
                "the service credential `{}` is empty, so the password is not sent",
                auth.secret
            )));
        }
        let mut rendered = Zeroizing::new(String::with_capacity(
            auth.prefix.len().saturating_add(value.len()),
        ));
        rendered.push_str(&auth.prefix);
        rendered.push_str(&value);
        Ok(rendered)
    }

    /// The outbound request, complete before anything is sent.
    fn request(&self, credential: &BasicCredential) -> Result<HttpRequest, DirectoryError> {
        let body = self.body(credential)?;
        let mut request = HttpRequest::post(&self.config.url, Bytes::copy_from_slice(&body))
            .timeout(Duration::from_secs(self.config.timeout_secs))
            .max_response_bytes(RESPONSE_MAX_BYTES)
            .header("content-type", "application/json")
            .and_then(|r| r.header("accept", "application/json"))
            .map_err(|e| {
                DirectoryError::Unavailable(format!("could not build the request: {e}"))
            })?;
        if let Some(secs) = self.config.connect_timeout_secs {
            request = request.connect_timeout(Duration::from_secs(secs));
        }
        if let Some(auth) = &self.config.service_auth {
            let value = self.service_credential(auth)?;
            // The header error is not formatted: it may describe the value.
            request = request.header(&auth.header, value.as_str()).map_err(
                |_may_describe_the_value| {
                    DirectoryError::Unavailable(format!(
                        "the service credential `{}` is not a legal header value",
                        auth.secret
                    ))
                },
            )?;
        }
        Ok(request)
    }

    /// Turn a 200 body into an outcome.
    fn read_response(&self, body: &[u8]) -> Result<Option<UserRecord>, DirectoryError> {
        // The parse error is not carried: it can quote the body.
        let parsed: Value = serde_json::from_slice(body).map_err(|_may_quote_the_body| {
            DirectoryError::Malformed("the response is not a JSON document".to_owned())
        })?;
        let Value::Object(mut object) = parsed else {
            return Err(DirectoryError::Malformed(
                "the response is not a JSON object".to_owned(),
            ));
        };

        // A missing verdict is unreadable rather than a refusal: defaulting it
        // either way guesses.
        let valid_field = &self.config.valid_field;
        let valid = match object.get(valid_field) {
            Some(Value::Bool(valid)) => *valid,
            Some(_) => {
                return Err(DirectoryError::Malformed(format!(
                    "`{valid_field}` is not a boolean"
                )));
            },
            None => {
                return Err(DirectoryError::Malformed(format!(
                    "the response carries no `{valid_field}` field"
                )));
            },
        };
        if !valid {
            return Ok(None);
        }

        let expires_at = match object.remove(&self.config.expires_at_field) {
            None => None,
            Some(Value::String(text)) => {
                Some(text.parse::<DateTime<Utc>>().map_err(|_unparsed| {
                    DirectoryError::Malformed(format!(
                        "`{}` is not an RFC 3339 timestamp",
                        self.config.expires_at_field
                    ))
                })?)
            },
            // Null included: an expiry that is present and unreadable must not
            // read as "never expires".
            Some(_) => {
                return Err(DirectoryError::Malformed(format!(
                    "`{}` is not an RFC 3339 timestamp",
                    self.config.expires_at_field
                )));
            },
        };

        let stripped = [
            valid_field.as_str(),
            self.config.user_id_field.as_str(),
            self.config.password_field.as_str(),
        ];
        let fields: HashMap<String, Value> = object
            .into_iter()
            .filter(|(name, _)| {
                !stripped.contains(&name.as_str()) && !ENVELOPE_FIELDS.contains(&name.as_str())
            })
            .collect();
        Ok(Some(UserRecord::new(
            fields,
            StoredVerifier::Delegated { valid: true },
            expires_at,
        )))
    }
}

#[async_trait::async_trait]
impl CredentialDirectory for HttpUserDirectory {
    /// Ask the service about the pair. A refusal is `None`, so an unknown
    /// user and a wrong password are one outcome here as on the wire.
    async fn lookup(
        &self,
        credential: &BasicCredential,
        services: &dyn HostServices,
    ) -> Result<Option<UserRecord>, DirectoryError> {
        // Built before a permit is taken or anything is sent, so a missing
        // service credential stops the password here.
        let request = self.request(credential)?;
        let _permit = self
            .verifications
            .try_acquire()
            .map_err(|_at_capacity| DirectoryError::Saturated)?;

        // Undelivered only: a verification that may have landed can have
        // counted a failed login at the service.
        let response = services
            .http_request(request, RetryPolicy::undelivered_only())
            .await
            .map_err(|error| match error {
                HttpRequestError::Unavailable(detail) => DirectoryError::Unavailable(format!(
                    "no HTTP transport for the verification service: {detail}"
                )),
                HttpRequestError::Transport(error) => {
                    DirectoryError::Unavailable(format!("{UNREACHABLE}: {error}"))
                },
            })?;

        match response.status {
            200 => self.read_response(&response.body),
            // Not followed: the `Location` could be any host, and following it
            // replays the password there.
            status @ 300..=399 => Err(DirectoryError::Unavailable(format!(
                "the verification service answered {status}; redirects are not followed"
            ))),
            status => Err(DirectoryError::Unavailable(format!(
                "the verification service answered {status}"
            ))),
        }
    }

    /// The service already verified the pair during the lookup, so this reads
    /// the verdict. A miss runs no local work: the remote call was the work,
    /// and it was the same call for a known and an unknown user.
    async fn verify(
        &self,
        record: Option<&UserRecord>,
        _credential: &BasicCredential,
        _services: &dyn HostServices,
    ) -> Result<bool, DirectoryError> {
        let Some(record) = record else {
            return Ok(false);
        };
        record.verify_against(|verifier| match verifier {
            StoredVerifier::Delegated { valid } => Ok(*valid),
            _ => Err(DirectoryError::Malformed(
                "a delegating backend cannot carry a stored hash".to_owned(),
            )),
        })
    }

    fn initialize(&self, ext: &InitExtensions) -> Result<(), String> {
        let Some(auth) = &self.config.service_auth else {
            return Ok(());
        };
        let secret = ext
            .resolve_secret(&auth.secret)
            .map_err(|e| e.to_string())?;
        // A second initialization keeps the first handle, which reads through
        // to the same value.
        let _first_wins = self.secret.set(secret);
        Ok(())
    }

    fn kind(&self) -> &'static str {
        KIND
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn default_auth_header() -> String {
    "authorization".to_owned()
}

fn default_expires_at_field() -> String {
    "expires_at".to_owned()
}

fn default_max_concurrent_verifications() -> usize {
    DEFAULT_MAX_CONCURRENT_VERIFICATIONS
}

fn default_password_field() -> String {
    "password".to_owned()
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

fn default_user_id_field() -> String {
    "user_id".to_owned()
}

fn default_valid_field() -> String {
    "valid".to_owned()
}
