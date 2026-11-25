// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The cache in front of the delegated-verification backend.

use std::sync::Arc;
use std::time::Duration;

use praxis_policy_builtins::plugins::identity_basic::{
    BasicCredential, CacheConfig, CachingDirectory, CredentialDirectory as _, DirectoryError,
    HttpUserDirectory, codes,
};
use praxis_policy_core::http::HttpResponse;
use praxis_policy_core::http_testing::{FakeTransport, granting};

use crate::support::{
    VERIFY_URL, basic_header, denial_code, extract_and_decode, http_block, resolve_over_http,
    resolver, verify_service,
};

const VALID: &str = r#"{"valid": true, "team": "platform"}"#;
const REFUSED: &str = r#"{"valid": false}"#;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn a_repeated_lookup_is_answered_from_the_cache() -> Result<(), DirectoryError> {
    let transport = verify_service(200, VALID);
    let services = granting(Arc::clone(&transport));
    let cache = cache(serde_json::json!({ "ttl_secs": 60 }));
    let alice = credential("alice", "pw");

    let first = cache.lookup(&alice, &services).await?;
    let second = cache.lookup(&alice, &services).await?;

    assert!(first.is_some() && second.is_some(), "both resolve");
    assert_eq!(transport.call_count(), 1, "the second answer is cached");
    assert_eq!(cache.len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_refusal_outlives_only_its_own_shorter_ttl() -> Result<(), DirectoryError> {
    let transport = Arc::new(
        FakeTransport::new().respond_with("verify.example", |request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let answer = if body["password"] == "pw" {
                VALID
            } else {
                REFUSED
            };
            Ok(HttpResponse::new(200, answer.into()))
        }),
    );
    let services = granting(Arc::clone(&transport));
    let cache = cache(serde_json::json!({ "ttl_secs": 60, "negative_ttl_secs": 1 }));
    let good = credential("alice", "pw");
    let bad = credential("alice", "guess");

    cache.lookup(&good, &services).await?;
    cache.lookup(&bad, &services).await?;
    cache.lookup(&bad, &services).await?;
    assert_eq!(
        transport.call_count(),
        2,
        "a repeated refusal is cached too"
    );
    assert_eq!(cache.negative_len(), 1);

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    cache.lookup(&good, &services).await?;
    cache.lookup(&bad, &services).await?;

    assert_eq!(
        transport.call_count(),
        3,
        "after the negative TTL only the refusal is asked again"
    );
    Ok(())
}

#[tokio::test]
async fn refusals_are_not_cached_without_a_negative_ttl() -> Result<(), DirectoryError> {
    let transport = verify_service(200, REFUSED);
    let services = granting(Arc::clone(&transport));
    let cache = cache(serde_json::json!({ "ttl_secs": 60 }));
    let bad = credential("alice", "guess");

    cache.lookup(&bad, &services).await?;
    cache.lookup(&bad, &services).await?;

    assert_eq!(transport.call_count(), 2, "each refusal asks again");
    assert_eq!(cache.negative_len(), 0);
    Ok(())
}

#[tokio::test]
async fn a_failure_is_never_cached() -> Result<(), DirectoryError> {
    let transport = Arc::new(FakeTransport::new().json("verify.example", 500, "{}").json(
        "verify.example",
        200,
        VALID,
    ));
    let services = granting(Arc::clone(&transport));
    let cache = cache(serde_json::json!({ "ttl_secs": 60, "negative_ttl_secs": 60 }));
    let alice = credential("alice", "pw");

    let failed = cache.lookup(&alice, &services).await;
    assert!(
        matches!(failed, Err(DirectoryError::Unavailable(_))),
        "got {failed:?}"
    );
    let recovered = cache.lookup(&alice, &services).await?;

    assert!(
        recovered.is_some(),
        "the service is asked again and answers"
    );
    assert_eq!(
        cache.len() + cache.negative_len(),
        1,
        "only the answer is held"
    );
    Ok(())
}

#[tokio::test]
async fn a_flood_of_guesses_cannot_evict_a_live_entry() -> Result<(), DirectoryError> {
    let transport = Arc::new(
        FakeTransport::new().respond_with("verify.example", |request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let answer = if body["password"] == "pw" {
                VALID
            } else {
                REFUSED
            };
            Ok(HttpResponse::new(200, answer.into()))
        }),
    );
    let services = granting(Arc::clone(&transport));
    let cache = cache(serde_json::json!({
        "ttl_secs": 60,
        "negative_ttl_secs": 60,
        "max_entries": 10,
        "max_negative_entries": 2,
    }));
    let alice = credential("alice", "pw");

    cache.lookup(&alice, &services).await?;
    for n in 0..5 {
        cache
            .lookup(&credential("alice", &format!("guess{n}")), &services)
            .await?;
    }
    let calls = transport.call_count();
    let still = cache.lookup(&alice, &services).await?;

    assert_eq!(
        cache.negative_len(),
        2,
        "refusals stop at their own ceiling"
    );
    assert!(still.is_some(), "the accepted credential still resolves");
    assert_eq!(
        transport.call_count(),
        calls,
        "and is still answered from the cache"
    );
    Ok(())
}

#[tokio::test]
async fn pairs_that_concatenate_identically_do_not_share_an_entry() -> Result<(), DirectoryError> {
    let transport = Arc::new(
        FakeTransport::new().respond_with("verify.example", |request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
            let answer = if body["user_id"] == "a" {
                VALID
            } else {
                REFUSED
            };
            Ok(HttpResponse::new(200, answer.into()))
        }),
    );
    let services = granting(Arc::clone(&transport));
    let cache = cache(serde_json::json!({ "ttl_secs": 60 }));

    let first = cache.lookup(&credential("a", "bc"), &services).await?;
    let second = cache.lookup(&credential("ab", "c"), &services).await?;

    assert!(first.is_some(), "the service accepts the first pair");
    assert!(
        second.is_none(),
        "the second pair must not be served the first pair's answer"
    );
    assert_eq!(transport.call_count(), 2, "each pair asked the service");
    Ok(())
}

#[tokio::test]
async fn the_cache_holds_no_bare_digest_of_the_credential() -> Result<(), DirectoryError> {
    let services = granting(verify_service(200, VALID));
    let cache = cache(serde_json::json!({ "ttl_secs": 60 }));

    cache
        .lookup(&credential("alice", "hunter2"), &services)
        .await?;

    let printed = format!("{cache:?}");
    for input in ["alice:hunter2", "alicehunter2", "hunter2"] {
        let digest = praxis_policy_core::crypto::sha256(input.as_bytes())
            .map_err(|e| DirectoryError::Unavailable(e.to_string()))?;
        assert!(
            !printed.contains(&format!("{digest:?}")),
            "the cache must not be keyed by an unkeyed digest of {input:?}"
        );
    }
    assert!(
        !printed.contains("hunter2"),
        "nor print the password, got: {printed}"
    );
    Ok(())
}

#[test]
fn a_cache_that_caches_nothing_fails_at_load() {
    for block in [
        serde_json::json!({ "ttl_secs": 0 }),
        serde_json::json!({ "ttl_secs": 60, "max_entries": 0 }),
    ] {
        let config: CacheConfig = serde_json::from_value(block.clone()).expect("parses");
        let error = config.validate().expect_err("caches nothing");
        assert!(error.contains("cache:"), "{block} got: {error}");
    }
}

#[tokio::test]
async fn the_resolver_reuses_a_cached_verdict() {
    let resolver = resolver(http_block(
        serde_json::json!({ "cache": { "ttl_secs": 60 } }),
    ))
    .expect("the resolver builds");
    let transport = verify_service(200, VALID);

    for _ in 0..3 {
        let result = resolve_over_http(
            &resolver,
            &basic_header("alice", "pw"),
            Arc::clone(&transport),
        )
        .await;
        assert!(result.violation.is_none(), "got {:?}", result.violation);
    }

    assert_eq!(transport.call_count(), 1, "one call serves three requests");
}

#[tokio::test]
async fn a_cached_record_past_its_expiry_still_denies() {
    let resolver = resolver(http_block(
        serde_json::json!({ "cache": { "ttl_secs": 60 } }),
    ))
    .expect("the resolver builds");
    let transport = verify_service(
        200,
        r#"{"valid": true, "expires_at": "2020-01-01T00:00:00Z"}"#,
    );

    for _ in 0..2 {
        let result = resolve_over_http(
            &resolver,
            &basic_header("alice", "pw"),
            Arc::clone(&transport),
        )
        .await;
        assert_eq!(
            denial_code(&result).as_deref(),
            Some(codes::CREDENTIAL_EXPIRED),
            "reuse does not skip the expiry check"
        );
    }
}

#[test]
fn the_resolver_rejects_an_empty_cache_at_load() {
    let error = resolver(http_block(
        serde_json::json!({ "cache": { "ttl_secs": 0 } }),
    ))
    .expect_err("a zero TTL caches nothing");
    assert!(error.contains("cache.ttl_secs"), "got: {error}");
}

#[tokio::test]
async fn the_cache_forwards_initialization_and_kind_to_its_backend() {
    let backend: praxis_policy_builtins::plugins::identity_basic::HttpUserConfig =
        serde_json::from_value(serde_json::json!({
            "url": VERIFY_URL,
            "service_auth": { "secret": "verifier_token" },
        }))
        .expect("parses");
    let cache = CachingDirectory::new(
        Arc::new(HttpUserDirectory::new(backend).expect("builds")),
        serde_json::from_value(serde_json::json!({ "ttl_secs": 60 })).expect("parses"),
    )
    .expect("the cache builds");

    assert_eq!(cache.kind(), "http", "the cache reports its backend's kind");
    let error = cache
        .initialize(&praxis_policy_core::host::InitExtensions::new())
        .expect_err("the backend's grant is missing");
    assert!(error.contains("read_secret:verifier_token"), "got: {error}");
}

// -----------------------------------------------------------------------------
// Test Utilities
// -----------------------------------------------------------------------------

fn cache(config: serde_json::Value) -> CachingDirectory {
    let backend: praxis_policy_builtins::plugins::identity_basic::HttpUserConfig =
        serde_json::from_value(serde_json::json!({ "url": VERIFY_URL })).expect("parses");
    let inner = Arc::new(HttpUserDirectory::new(backend).expect("builds"));
    CachingDirectory::new(
        inner,
        serde_json::from_value(config).expect("the cache config parses"),
    )
    .expect("the cache builds")
}

fn credential(user_id: &str, password: &str) -> BasicCredential {
    match extract_and_decode(&basic_header(user_id, password)) {
        Ok(credential) => credential,
        Err(_) => panic!("the fixture credential decodes"),
    }
}
