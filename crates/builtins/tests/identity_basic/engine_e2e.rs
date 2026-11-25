// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! The plugin driven through the real engine rather than by calling the hook
//! handler directly.
//!
//! Every other module in this suite invokes `HookHandler::handle` itself, which
//! skips what a host actually does: registering the plugin for the identity
//! hook, running `initialize`, invoking by hook name, and reading the resolved
//! identity back out with `IdentityPayload::from_pipeline_result`. Each of
//! those is a place the plugin can be wired correctly and still not work --
//! a `mode`/`on_error` pair the engine refuses, a payload the engine does not
//! thread back, a denial the engine drops the challenge from.

use std::sync::Arc;

use praxis_policy_core::executor::PipelineResult;
use praxis_policy_core::hooks::payload::Extensions;
use praxis_policy_core::identity::{IdentityHook, IdentityPayload, TokenSource};
use praxis_policy_core::plugin::PluginConfig;

use praxis_policy_builtins::plugins::identity_basic::{BasicIdentityResolver, KIND};

use crate::support::{
    HtpasswdFile, UserYamlFile, basic_header, bcrypt_line, htpasswd_block, user_file_block,
};

/// The hook name a host invokes identity resolution by.
const HOOK_IDENTITY_RESOLVE: &str = "identity.resolve";

/// Drive one request through a registered, initialized engine.
async fn invoke_through_engine(block: serde_json::Value, header: &str) -> PipelineResult {
    use praxis_policy_core::engine::PolicyEngine;

    let cfg = PluginConfig {
        name: "basic-auth".into(),
        kind: KIND.into(),
        hooks: vec![HOOK_IDENTITY_RESOLVE.to_owned()],
        config: Some(block),
        ..Default::default()
    };
    let resolver = BasicIdentityResolver::new(cfg.clone()).expect("the resolver must construct");

    let engine = Arc::new(PolicyEngine::default());
    engine
        .register_handler_for_names::<IdentityHook, _>(
            Arc::new(resolver),
            cfg,
            &[HOOK_IDENTITY_RESOLVE],
        )
        .expect("the engine must accept this plugin's mode and on_error");
    engine.initialize().await.expect("initialize");

    let payload = IdentityPayload::new("", TokenSource::Basic).with_headers(
        std::collections::HashMap::from([("authorization".to_owned(), header.to_owned())]),
    );
    let (result, _background) = engine
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    result
}

#[tokio::test]
async fn a_correct_password_resolves_a_subject_through_the_engine() {
    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let result = invoke_through_engine(
        htpasswd_block(file.path()),
        &basic_header("alice", "correct horse"),
    )
    .await;

    assert!(
        result.continue_processing,
        "a correct password must resolve rather than deny: violation = {:?}",
        result.violation,
    );

    let identity = IdentityPayload::from_pipeline_result(&result)
        .expect("the engine must thread the resolved payload back to the host");
    let subject = identity
        .subject
        .as_ref()
        .expect("the user role fills the subject slot");
    assert_eq!(
        subject.id.as_deref(),
        Some("alice"),
        "the verified user-id is the anchor a bare `.htpasswd` deployment projects"
    );
    assert!(
        identity.raw_credentials.is_none(),
        "the password must stop at this plugin: nothing downstream may forward a caller's own \
         password to an upstream that never authenticated it"
    );
}

#[tokio::test]
async fn a_wrong_password_denies_with_the_challenge_through_the_engine() {
    use praxis_policy_apl_cmf::constants::DETAIL_HTTP_HEADERS;

    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let result = invoke_through_engine(
        htpasswd_block(file.path()),
        &basic_header("alice", "wrong horse"),
    )
    .await;

    assert!(
        !result.continue_processing,
        "a wrong password must stop the pipeline"
    );
    let violation = result
        .violation
        .as_ref()
        .expect("a denial must carry a violation the host can render");
    assert_eq!(
        violation.code, "auth.invalid_credentials",
        "an unknown user and a wrong password share one code, so neither is an enumeration oracle"
    );
    assert_eq!(
        violation
            .details
            .get(DETAIL_HTTP_HEADERS)
            .and_then(|headers| headers.get("WWW-Authenticate"))
            .and_then(serde_json::Value::as_str),
        Some("Basic realm=\"ops\""),
        "the challenge must survive the engine: RFC 7617 needs it on the 401 for a client to \
         know how to retry"
    );
}

#[tokio::test]
async fn a_declined_scheme_becomes_the_executors_own_unchallenged_denial() {
    use praxis_policy_apl_cmf::constants::DETAIL_HTTP_HEADERS;

    let file = HtpasswdFile::write(&format!("{}\n", bcrypt_line("alice", "correct horse", 4)));
    let result = invoke_through_engine(htpasswd_block(file.path()), "Bearer some.jwt.token").await;

    // The resolver declines rather than denying, so a Basic and a Bearer
    // resolver can share one `Authorization` header. With no other resolver
    // registered the executor then synthesizes the denial -- and that one is
    // its own, not this plugin's: a different code, and no challenge, because
    // a declining plugin has no channel to contribute one. Asserted here
    // because calling the handler directly cannot see it.
    let violation = result
        .violation
        .as_ref()
        .expect("every resolver declining must still deny rather than authenticate nobody");
    assert_eq!(
        violation.code, "auth.unrecognized_credential",
        "the executor's own code, distinct from any this plugin raises"
    );
    assert!(
        !violation.details.contains_key(DETAIL_HTTP_HEADERS),
        "a declining plugin contributes no challenge, so a host wanting one on this path must add \
         it: {:?}",
        violation.details,
    );

    if let Some(identity) = IdentityPayload::from_pipeline_result(&result) {
        assert!(
            identity.subject.is_none(),
            "a declining resolver must not fill a slot it never authenticated"
        );
    }
}

#[tokio::test]
async fn a_yaml_record_projects_its_roles_through_the_engine() {
    let hash = bcrypt_line("u", "correct horse", 4)
        .split_once(':')
        .expect("the fixture line has a separator")
        .1
        .to_owned();
    let file = UserYamlFile::write(&format!(
        "users:
  - username: alice
    password_hash: {hash}
    roles: [admin]
    teams: [platform]
"
    ));
    let mut block = user_file_block(file.path());
    block["record_map"] = serde_json::json!({
        "subject": { "id": "user_id", "roles": "roles", "teams": "teams" },
    });

    let result = invoke_through_engine(block, &basic_header("alice", "correct horse")).await;

    assert!(
        result.continue_processing,
        "a correct password against a YAML record must resolve: violation = {:?}",
        result.violation,
    );
    let identity = IdentityPayload::from_pipeline_result(&result)
        .expect("the engine must thread the resolved payload back to the host");
    let subject = identity
        .subject
        .as_ref()
        .expect("the user role fills the subject slot");
    assert_eq!(subject.id.as_deref(), Some("alice"));
    // The capability `.htpasswd` structurally cannot provide, proven through
    // the engine rather than only at the hook: a record's own attributes
    // reaching the slots a policy is written against.
    assert!(
        subject.roles.contains("admin"),
        "the record's roles must survive the engine's payload threading, got {:?}",
        subject.roles
    );
    assert!(
        subject.teams.contains("platform"),
        "the record's teams must survive it too, got {:?}",
        subject.teams
    );
    assert!(
        identity.raw_credentials.is_none(),
        "the password must stop at this plugin whichever backend verified it"
    );
}

#[tokio::test]
async fn an_expired_yaml_record_denies_through_the_engine() {
    let hash = bcrypt_line("u", "correct horse", 4)
        .split_once(':')
        .expect("the fixture line has a separator")
        .1
        .to_owned();
    let file = UserYamlFile::write(&format!(
        "users:
  - username: alice
    password_hash: {hash}
    expires_at: 2020-01-01T00:00:00Z
"
    ));

    let result = invoke_through_engine(
        user_file_block(file.path()),
        &basic_header("alice", "correct horse"),
    )
    .await;

    assert!(
        !result.continue_processing,
        "an expired record must stop the pipeline even though the password is right"
    );
    let violation = result
        .violation
        .as_ref()
        .expect("a denial must carry a violation the host can render");
    assert_eq!(
        violation.code, "auth.credential_expired",
        "expiry is its own code: the credential was correct and the record is over, which is          a different operator action from a wrong password"
    );
}

/// Drive one request through an engine loaded from a document whose
/// `identity/basic` entry delegates to `transport` and presents the declared
/// `verifier_token`.
async fn invoke_delegated_through_engine(
    transport: Arc<praxis_policy_core::http_testing::FakeTransport>,
    capabilities: &str,
    header: &str,
) -> Result<PipelineResult, String> {
    use praxis_policy_builtins::plugins::identity_basic::BasicIdentityFactory;
    use praxis_policy_core::config::parse_config;
    use praxis_policy_core::engine::PolicyEngine;
    use praxis_policy_core::secrets::SecretProviderRegistry;

    let dir = std::env::temp_dir().join(format!("ppe-basic-http-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("verifier.token"), "s3rvice\n").map_err(|e| e.to_string())?;
    let yaml = format!(
        "
engine_settings:
  dispatch: hooks
secrets:
  providers:
    local: {{ kind: file, base_dir: {dir} }}
  values:
    verifier_token: {{ provider: local, ref: verifier.token }}
plugins:
  - name: ops-basic
    kind: identity/basic
    hooks: [identity.resolve]
    mode: sequential
    capabilities: {capabilities}
    config:
      realm: ops
      credential: {{ kind: header, name: Authorization }}
      provider:
        kind: http
        url: {url}
        service_auth: {{ secret: verifier_token, prefix: 'Bearer ' }}
",
        dir = dir.display(),
        url = crate::support::VERIFY_URL,
    );

    let engine = Arc::new(PolicyEngine::default());
    engine.set_secret_providers(SecretProviderRegistry::with_builtin_backends());
    engine.register_factory(KIND, Box::new(BasicIdentityFactory));
    engine.set_http_transport(transport);
    engine
        .load_config(parse_config(&yaml).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let initialized = engine.initialize().await.map_err(|e| e.to_string());
    std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    initialized?;

    let payload = IdentityPayload::new("", TokenSource::Basic).with_headers(
        std::collections::HashMap::from([("authorization".to_owned(), header.to_owned())]),
    );
    let (result, _background) = engine
        .invoke_named::<IdentityHook>(HOOK_IDENTITY_RESOLVE, payload, Extensions::default(), None)
        .await;
    Ok(result)
}

#[tokio::test]
async fn a_delegated_verdict_resolves_through_the_engine_with_the_service_credential()
-> Result<(), String> {
    let transport = crate::support::verify_service(200, r#"{"valid": true, "team": "platform"}"#);

    let result = invoke_delegated_through_engine(
        Arc::clone(&transport),
        "[perform_http, read_secret:verifier_token]",
        &basic_header("alice", "pw"),
    )
    .await?;

    let identity = IdentityPayload::from_pipeline_result(&result)
        .ok_or_else(|| format!("no identity: {:?}", result.violation))?;
    assert_eq!(
        identity.subject.as_ref().and_then(|s| s.id.as_deref()),
        Some("alice"),
        "the service's verdict resolves the subject"
    );
    let sent = transport.last_request().ok_or("nothing was sent")?;
    assert_eq!(
        sent.headers
            .get("authorization")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer s3rvice"),
        "the declared secret is presented to the service"
    );
    Ok(())
}

#[tokio::test]
async fn a_delegated_refusal_denies_through_the_engine() -> Result<(), String> {
    let transport = crate::support::verify_service(200, r#"{"valid": false}"#);

    let result = invoke_delegated_through_engine(
        transport,
        "[perform_http, read_secret:verifier_token]",
        &basic_header("alice", "wrong"),
    )
    .await?;

    assert!(!result.continue_processing, "a refusal stops the pipeline");
    assert_eq!(
        result.violation.as_ref().map(|v| v.code.as_str()),
        Some("auth.invalid_credentials")
    );
    Ok(())
}

#[tokio::test]
async fn an_ungranted_service_credential_stops_startup() {
    let transport = crate::support::verify_service(200, r#"{"valid": true}"#);

    let error = invoke_delegated_through_engine(
        Arc::clone(&transport),
        "[perform_http]",
        &basic_header("alice", "pw"),
    )
    .await
    .expect_err("startup must fail without the grant");

    assert!(
        error.contains("read_secret:verifier_token"),
        "the error names the grant to add, got: {error}"
    );
    assert_eq!(transport.call_count(), 0, "nothing was sent");
}
