// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The delegated-verification backend, driven by a fake transport.

use std::sync::Arc;
use std::time::Duration;

use praxis_policy_builtins::plugins::identity_basic::{
    CredentialDirectory as _, DirectoryError, HttpUserConfig, HttpUserDirectory, codes,
};
use praxis_policy_core::host::InitExtensions;
use praxis_policy_core::http::HttpTransportError;
use praxis_policy_core::http_testing::{FakeTransport, granting};
use praxis_policy_core::plugin::Plugin as _;
use praxis_policy_core::secrets::SecretRef;

use crate::support::{
    VERIFY_URL, basic_header, denial_code, extract_and_decode, http_block, resolve_over_http,
    resolver, verify_service,
};

const VALID: &str = r#"{
  "valid": true,
  "reason": "ok",
  "user_id": "alice",
  "password": "echoed by a careless service",
  "roles": ["admin"],
  "team": "platform"
}"#;

const REFUSED: &str = r#"{"valid": false, "reason": "alice has no account here"}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn a_valid_verdict_resolves_and_verifies() -> Result<(), DirectoryError> {
    let transport = verify_service(200, VALID);
    let services = granting(Arc::clone(&transport));
    let dir = directory(serde_json::json!({}));
    let alice = credential("alice", "pw");

    let record = dir.lookup(&alice, &services).await?;

    assert!(
        record.is_some(),
        "a valid verdict must be a record, not a miss"
    );
    assert!(
        dir.verify(record.as_ref(), &alice, &services).await?,
        "the delegated verdict is what verify reports"
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_verdict_is_a_miss_that_does_not_verify() -> Result<(), DirectoryError> {
    let services = granting(verify_service(200, REFUSED));
    let dir = directory(serde_json::json!({}));
    let alice = credential("alice", "wrong");

    let record = dir.lookup(&alice, &services).await?;

    assert!(record.is_none(), "a refusal must be a miss");
    assert!(
        !dir.verify(None, &alice, &services).await?,
        "a miss never verifies"
    );
    Ok(())
}

#[tokio::test]
async fn unreadable_answers_are_failures_not_misses() {
    for (status, body) in [
        (500, VALID),
        (401, VALID),
        (404, "{}"),
        (200, "[]"),
        (200, r#""valid""#),
        (200, r#"{"roles": ["admin"]}"#),
        (200, r#"{"valid": "true"}"#),
        (200, r#"{"valid": null}"#),
        (200, r#"{"valid": true,"#),
        (200, "not json"),
    ] {
        let services = granting(verify_service(status, body));

        let outcome = directory(serde_json::json!({}))
            .lookup(&credential("alice", "pw"), &services)
            .await;

        assert!(
            matches!(
                outcome,
                Err(DirectoryError::Unavailable(_) | DirectoryError::Malformed(_))
            ),
            "{status} {body:?} must fail rather than answer about the user, got {outcome:?}"
        );
    }
}

#[test]
fn a_cleartext_url_loads_only_with_the_opt_in() {
    let refused = HttpUserDirectory::new(config(serde_json::json!({
        "url": "http://verify.example/v1/basic",
    })))
    .expect_err("http must not load by default");
    assert!(
        refused.contains("allow_cleartext"),
        "the error names the opt-in, got: {refused}"
    );

    let opted_in = HttpUserDirectory::new(config(serde_json::json!({
        "url": "http://verify.example/v1/basic",
        "allow_cleartext": true,
    })));
    assert!(
        opted_in.is_ok(),
        "the opt-in admits http: {:?}",
        opted_in.err()
    );

    let other = HttpUserDirectory::new(config(serde_json::json!({ "url": "ftp://x/" })))
        .expect_err("a non-HTTP scheme never loads");
    assert!(other.contains("https"), "got: {other}");
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let transport = verify_service(307, "");
    let services = granting(Arc::clone(&transport));

    let outcome = directory(serde_json::json!({}))
        .lookup(&credential("alice", "pw"), &services)
        .await;

    assert!(
        matches!(&outcome, Err(DirectoryError::Unavailable(message)) if message.contains("redirect")),
        "a redirect is a failure naming itself, got {outcome:?}"
    );
    assert_eq!(
        transport.call_count(),
        1,
        "the password must not be replayed to the redirect target"
    );
}

#[test]
fn tls_material_is_refused_naming_the_host_transport() {
    for key in ["ca_bundle", "client_cert", "client_key"] {
        let error = HttpUserDirectory::new(config(serde_json::json!({ key: "/etc/ppe/x.pem" })))
            .expect_err("TLS material is not this backend's");
        assert!(
            error.contains("host transport"),
            "`{key}` must say where TLS lives, got: {error}"
        );
    }
}

#[tokio::test]
async fn a_resolved_service_credential_is_sent() -> Result<(), DirectoryError> {
    let transport = verify_service(200, VALID);
    let dir = directory(serde_json::json!({
        "service_auth": { "secret": "verifier_token", "prefix": "Bearer " },
    }));
    dir.initialize(
        &InitExtensions::new().with_secret("verifier_token", SecretRef::fixed("s3rvice")),
    )
    .map_err(DirectoryError::Unavailable)?;

    dir.lookup(
        &credential("alice", "pw"),
        &granting(Arc::clone(&transport)),
    )
    .await?;

    let sent = transport.last_request().expect("a request was sent");
    assert_eq!(
        sent.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer s3rvice"),
        "the service credential rides the configured header"
    );
    Ok(())
}

#[tokio::test]
async fn an_unresolved_service_credential_sends_nothing() {
    let transport = verify_service(200, VALID);
    let dir = directory(serde_json::json!({ "service_auth": { "secret": "verifier_token" } }));

    let outcome = dir
        .lookup(
            &credential("alice", "pw"),
            &granting(Arc::clone(&transport)),
        )
        .await;

    assert!(
        matches!(outcome, Err(DirectoryError::Unavailable(_))),
        "an unresolved credential is unavailable, got {outcome:?}"
    );
    assert_eq!(
        transport.call_count(),
        0,
        "the password must not reach a service PPE could not authenticate to"
    );
}

#[tokio::test]
async fn an_empty_service_credential_sends_nothing() -> Result<(), String> {
    let transport = verify_service(200, VALID);
    let dir = directory(serde_json::json!({ "service_auth": { "secret": "verifier_token" } }));
    dir.initialize(&InitExtensions::new().with_secret("verifier_token", SecretRef::fixed("")))?;

    let outcome = dir
        .lookup(
            &credential("alice", "pw"),
            &granting(Arc::clone(&transport)),
        )
        .await;

    assert!(
        matches!(outcome, Err(DirectoryError::Unavailable(_))),
        "got {outcome:?}"
    );
    assert_eq!(
        transport.call_count(),
        0,
        "an empty credential sends nothing"
    );
    Ok(())
}

#[test]
fn an_ungranted_service_credential_fails_initialization() {
    let dir = directory(serde_json::json!({ "service_auth": { "secret": "verifier_token" } }));

    let error = dir
        .initialize(&InitExtensions::new())
        .expect_err("the grant is missing");

    assert!(
        error.contains("read_secret:verifier_token"),
        "the error names the capability to add, got: {error}"
    );
}

#[test]
fn an_illegal_service_auth_header_fails_at_load() {
    let error = HttpUserDirectory::new(config(serde_json::json!({
        "service_auth": { "secret": "verifier_token", "header": "bad header" },
    })))
    .expect_err("an illegal header name cannot be sent");
    assert!(error.contains("service_auth"), "got: {error}");
}

#[tokio::test]
async fn the_user_id_and_password_arrive_as_separate_fields() -> Result<(), DirectoryError> {
    let transport = verify_service(200, VALID);
    let password = "p\"a:s\\s\u{e9}";

    directory(serde_json::json!({}))
        .lookup(
            &credential("alice", password),
            &granting(Arc::clone(&transport)),
        )
        .await?;

    let sent = transport.last_request().expect("a request was sent");
    let body: serde_json::Value =
        serde_json::from_slice(&sent.body).expect("the body is valid JSON");
    assert_eq!(
        body,
        serde_json::json!({ "user_id": "alice", "password": password }),
        "two fields, escaped, never concatenated"
    );
    Ok(())
}

#[tokio::test]
async fn the_request_field_names_are_configurable() -> Result<(), DirectoryError> {
    let transport = verify_service(200, VALID);

    directory(serde_json::json!({ "user_id_field": "login", "password_field": "secret" }))
        .lookup(
            &credential("alice", "pw"),
            &granting(Arc::clone(&transport)),
        )
        .await?;

    let sent = transport.last_request().expect("a request was sent");
    let body: serde_json::Value = serde_json::from_slice(&sent.body).expect("JSON");
    assert_eq!(
        body,
        serde_json::json!({ "login": "alice", "secret": "pw" })
    );
    Ok(())
}

#[test]
fn colliding_request_field_names_fail_at_load() {
    let error = HttpUserDirectory::new(config(serde_json::json!({ "password_field": "user_id" })))
        .expect_err("one field cannot carry both halves");
    assert!(error.contains("same field"), "got: {error}");
}

#[tokio::test]
async fn transport_failures_are_unavailable_and_do_not_vary_by_user_id() {
    for failure in [
        HttpTransportError::Timeout,
        HttpTransportError::Connect("connection refused".to_owned()),
        HttpTransportError::ResponseTooLarge {
            actual: 70_000,
            limit: 65_536,
        },
    ] {
        let mut messages = Vec::new();
        for (user_id, password) in [("alice", "hunter2"), ("mallory", "letmein")] {
            let transport = Arc::new(FakeTransport::new().fail("verify.example", failure.clone()));

            let outcome = directory(serde_json::json!({}))
                .lookup(&credential(user_id, password), &granting(transport))
                .await;

            let Err(DirectoryError::Unavailable(message)) = outcome else {
                panic!("{failure:?} must be unavailable, got {outcome:?}");
            };
            assert!(
                !message.contains(user_id) && !message.contains(password),
                "a failure names neither half of the credential, got: {message}"
            );
            messages.push(message);
        }
        assert_eq!(
            messages.first(),
            messages.last(),
            "{failure:?} must read the same for every user-id"
        );
    }
}

#[tokio::test]
async fn the_response_body_is_capped() -> Result<(), DirectoryError> {
    let transport = verify_service(200, VALID);

    directory(serde_json::json!({}))
        .lookup(
            &credential("alice", "pw"),
            &granting(Arc::clone(&transport)),
        )
        .await?;

    let sent = transport.last_request().expect("a request was sent");
    assert_eq!(sent.max_response_bytes, 65_536, "a verdict is small");
    Ok(())
}

#[tokio::test]
async fn envelope_and_request_fields_are_stripped_from_the_record() -> Result<(), DirectoryError> {
    let services = granting(verify_service(200, VALID));

    let record = directory(serde_json::json!({}))
        .lookup(&credential("alice", "pw"), &services)
        .await?
        .expect("a valid verdict is a record");

    for stripped in ["valid", "reason", "user_id", "password"] {
        assert!(
            !record.fields.contains_key(stripped),
            "`{stripped}` must not reach the claims"
        );
    }
    assert_eq!(
        record.fields.get("team"),
        Some(&serde_json::json!("platform")),
        "the subject's own attributes are kept"
    );
    Ok(())
}

#[tokio::test]
async fn a_readable_expiry_reaches_the_record() -> Result<(), DirectoryError> {
    let services = granting(verify_service(
        200,
        r#"{"valid": true, "expires_at": "2030-01-01T00:00:00Z"}"#,
    ));

    let record = directory(serde_json::json!({}))
        .lookup(&credential("alice", "pw"), &services)
        .await?
        .expect("a valid verdict is a record");

    assert_eq!(
        record.expires_at.map(|at| at.to_rfc3339()),
        Some("2030-01-01T00:00:00+00:00".to_owned())
    );
    assert!(
        !record.fields.contains_key("expires_at"),
        "the expiry is lifecycle, not a claim"
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_expiry_is_unreadable_rather_than_absent() {
    for expiry in [r#""tomorrow""#, "1735689600", "null"] {
        let body = format!(r#"{{"valid": true, "expires_at": {expiry}}}"#);
        let services = granting(verify_service(200, &body));

        let outcome = directory(serde_json::json!({}))
            .lookup(&credential("alice", "pw"), &services)
            .await;

        assert!(
            matches!(outcome, Err(DirectoryError::Malformed(_))),
            "`expires_at: {expiry}` must not read as never expiring, got {outcome:?}"
        );
    }
}

#[tokio::test]
async fn verifications_beyond_the_cap_are_refused_not_queued() {
    let transport = Arc::new(
        FakeTransport::new()
            .json("verify.example", 200, VALID)
            .with_latency(Duration::from_millis(100)),
    );
    let services = granting(Arc::clone(&transport));
    let dir = directory(serde_json::json!({ "max_concurrent_verifications": 1 }));
    let alice = credential("alice", "pw");

    let (first, second) =
        tokio::join!(dir.lookup(&alice, &services), dir.lookup(&alice, &services));

    let saturated = [&first, &second]
        .iter()
        .filter(|outcome| matches!(outcome, Err(DirectoryError::Saturated)))
        .count();
    assert_eq!(
        saturated, 1,
        "one of two concurrent verifications is refused at a cap of one"
    );
    assert_eq!(
        transport.call_count(),
        1,
        "the refused one never reached the service"
    );
}

#[tokio::test]
async fn the_resolver_projects_a_delegated_record() {
    let resolver = resolver(http_block(serde_json::json!({}))).expect("the resolver builds");

    let result = resolve_over_http(
        &resolver,
        &basic_header("alice", "pw"),
        verify_service(200, VALID),
    )
    .await;

    let subject = result
        .modified_payload
        .as_ref()
        .and_then(|payload| payload.subject.as_ref())
        .expect("a valid verdict resolves a subject");
    assert_eq!(subject.id.as_deref(), Some("alice"));
}

#[tokio::test]
async fn the_resolver_denies_a_refusal_without_the_services_reason() {
    let resolver = resolver(http_block(serde_json::json!({}))).expect("the resolver builds");

    let result = resolve_over_http(
        &resolver,
        &basic_header("alice", "hunter2"),
        verify_service(200, REFUSED),
    )
    .await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::INVALID_CREDENTIALS)
    );
    let reason = &result.violation.as_ref().expect("a denial").reason;
    assert!(
        !reason.contains("no account") && !reason.contains("hunter2"),
        "neither the service's reason nor the password reaches a denial, got: {reason}"
    );
}

#[tokio::test]
async fn the_resolver_denies_a_past_expiry_as_expired() {
    let resolver = resolver(http_block(serde_json::json!({}))).expect("the resolver builds");

    let result = resolve_over_http(
        &resolver,
        &basic_header("alice", "pw"),
        verify_service(
            200,
            r#"{"valid": true, "expires_at": "2020-01-01T00:00:00Z"}"#,
        ),
    )
    .await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::CREDENTIAL_EXPIRED)
    );
}

#[tokio::test]
async fn the_resolver_denies_a_malformed_expiry_as_unavailable() {
    let resolver = resolver(http_block(serde_json::json!({}))).expect("the resolver builds");

    let result = resolve_over_http(
        &resolver,
        &basic_header("alice", "pw"),
        verify_service(200, r#"{"valid": true, "expires_at": "soon"}"#),
    )
    .await;

    assert_eq!(
        denial_code(&result).as_deref(),
        Some(codes::DIRECTORY_UNAVAILABLE)
    );
}

#[tokio::test]
async fn the_resolver_initializes_the_service_credential() {
    let resolver = resolver(http_block(serde_json::json!({
        "service_auth": { "secret": "verifier_token" },
    })))
    .expect("the resolver builds");

    let ungranted = resolver
        .initialize_with(&InitExtensions::new())
        .await
        .expect_err("an ungranted secret fails startup");
    assert!(
        ungranted.to_string().contains("read_secret:verifier_token"),
        "got: {ungranted}"
    );

    resolver
        .initialize_with(
            &InitExtensions::new().with_secret("verifier_token", SecretRef::fixed("t")),
        )
        .await
        .expect("a granted secret initializes");
    let transport = verify_service(200, VALID);
    let result = resolve_over_http(
        &resolver,
        &basic_header("alice", "pw"),
        Arc::clone(&transport),
    )
    .await;

    assert!(result.violation.is_none(), "got {:?}", result.violation);
    assert_eq!(
        transport
            .last_request()
            .and_then(|sent| sent.headers.get("authorization").cloned())
            .and_then(|v| v.to_str().map(str::to_owned).ok()),
        Some("t".to_owned())
    );
}

#[test]
fn the_resolver_rejects_a_cleartext_provider_at_load() {
    let error = resolver(http_block(serde_json::json!({
        "url": "http://verify.example/v1/basic",
    })))
    .expect_err("cleartext needs the opt-in");
    assert!(
        error.contains("basic-auth") && error.contains("allow_cleartext"),
        "the error names the plugin and the fix, got: {error}"
    );
}

#[tokio::test]
async fn a_missing_transport_is_unavailable() {
    let outcome = directory(serde_json::json!({}))
        .lookup(&credential("alice", "pw"), &InitExtensions::new())
        .await;

    assert!(
        matches!(&outcome, Err(DirectoryError::Unavailable(message)) if message.contains("transport")),
        "a host that wired no transport is a deployment fault, got {outcome:?}"
    );
}

#[tokio::test]
async fn a_stored_hash_cannot_verify_against_a_delegating_backend() {
    use praxis_policy_builtins::plugins::identity_basic::{Limits, StoredVerifier, UserRecord};

    let stored = crate::support::argon2_at(8, 1, "pw");
    let verifier = StoredVerifier::hash(&stored, &Limits::default()).expect("the hash admits");
    let record = UserRecord::verifier_only(verifier);

    let outcome = directory(serde_json::json!({}))
        .verify(
            Some(&record),
            &credential("alice", "pw"),
            &InitExtensions::new(),
        )
        .await;

    assert!(
        matches!(outcome, Err(DirectoryError::Malformed(_))),
        "a record this backend never produces is unreadable, got {outcome:?}"
    );
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

/// A backend config with `extra` merged over the default URL.
fn config(extra: serde_json::Value) -> HttpUserConfig {
    let mut block = serde_json::json!({ "url": VERIFY_URL });
    if let (Some(base), serde_json::Value::Object(extra)) = (block.as_object_mut(), extra) {
        base.extend(extra);
    }
    serde_json::from_value(block).expect("the backend config parses")
}

fn directory(extra: serde_json::Value) -> HttpUserDirectory {
    HttpUserDirectory::new(config(extra)).expect("the backend builds")
}

fn credential(
    user_id: &str,
    password: &str,
) -> praxis_policy_builtins::plugins::identity_basic::BasicCredential {
    match extract_and_decode(&basic_header(user_id, password)) {
        Ok(credential) => credential,
        Err(_) => panic!("the fixture credential decodes"),
    }
}
