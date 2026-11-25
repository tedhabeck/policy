// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

// Reuse of a delegating directory's answers.
//
// The shape is the api-key cache's: positives and negatives in separate maps
// with separate ceilings, failures never cached, and a full map refusing a new
// entry rather than evicting a live one. It is a parallel implementation
// because that cache is written against `KeyDirectory`.
//
// The key is where it diverges. That cache keys on a bare SHA-256 of the
// credential, which is sound for high-entropy API keys. A bare digest of
// `user:password` sitting in a long-lived map is an offline-crackable verifier
// in the heap or a core dump, so the key here is HMAC-SHA-256 under a random
// per-process secret, over length-prefixed fields so that `("a", "bc")` and
// `("ab", "c")` cannot collide. Do not harmonise the two.
//
// # The positive TTL is the revocation window
//
// A password changed or a user disabled at the service keeps authenticating
// here until its entry expires.
//
// # What negative caching does not buy
//
// The key covers the whole credential, so every new guess is a fresh key and a
// guaranteed miss. Negative entries absorb repeats of one identical guess and
// nothing else. Spray resistance is the failure limiter's job.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use praxis_policy_core::crypto::{hmac_sha256, random_bytes};
use praxis_policy_core::host::{HostServices, InitExtensions};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::BasicCredential;
use super::directory::{CredentialDirectory, DirectoryError, UserRecord};
use super::failure_limit::RecoveryLease;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Domain separator for the cache key, versioned with its derivation.
const DOMAIN: &[u8] = b"ppe.basic.verify-cache.v1";

/// The default ceiling for each of the two maps.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// How long answers are reused, and how many are held.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// How many accepted credentials are held before new ones stop being
    /// cached.
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,

    /// How many refused credentials are held.
    ///
    /// Its own ceiling rather than a share of `max_entries`, so a flood of
    /// guesses cannot displace the credentials in use.
    #[serde(default = "default_max_entries")]
    pub max_negative_entries: usize,

    /// How long a refusal is remembered. Zero, the default, remembers none.
    #[serde(default)]
    pub negative_ttl_secs: u64,

    /// How long an accepted credential is reused.
    ///
    /// **This interval is the revocation window.**
    pub ttl_secs: u64,
}

impl CacheConfig {
    /// Reject settings that cannot mean what they say.
    ///
    /// # Errors
    ///
    /// A zero positive TTL or capacity, which caches nothing. Omitting the
    /// `cache:` block is how caching is turned off.
    pub fn validate(&self) -> Result<(), String> {
        if self.ttl_secs == 0 || self.max_entries == 0 {
            return Err(
                "`cache.ttl_secs` and `cache.max_entries` must be greater than zero. Remove \
                 the `cache:` block to turn caching off"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

/// A directory whose answers are reused for a while.
#[derive(Debug)]
pub struct CachingDirectory {
    inner: Arc<dyn CredentialDirectory>,
    config: CacheConfig,
    key: MacKey,
    started: Instant,
    hits: RwLock<HashMap<[u8; 32], Entry>>,
    misses: RwLock<HashMap<[u8; 32], Entry>>,
}

impl CachingDirectory {
    /// Put `config` in front of `inner`.
    ///
    /// # Errors
    ///
    /// Whatever [`CacheConfig::validate`] rejects, or a crypto backend that
    /// cannot produce the key secret.
    pub fn new(inner: Arc<dyn CredentialDirectory>, config: CacheConfig) -> Result<Self, String> {
        config.validate()?;
        let mut secret = Zeroizing::new([0_u8; 32]);
        random_bytes(secret.as_mut())
            .map_err(|e| format!("could not draw the cache-key secret: {e}"))?;
        Ok(Self {
            inner,
            config,
            key: MacKey(secret),
            started: Instant::now(),
            hits: RwLock::new(HashMap::new()),
            misses: RwLock::new(HashMap::new()),
        })
    }

    /// How many accepted credentials are held.
    pub fn len(&self) -> usize {
        self.hits.read().map_or(0, |map| map.len())
    }

    /// Whether no accepted credential is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many refused credentials are held.
    pub fn negative_len(&self) -> usize {
        self.misses.read().map_or(0, |map| map.len())
    }

    /// The cache key for a credential: a keyed MAC, never the credential.
    fn key_of(&self, credential: &BasicCredential) -> Result<[u8; 32], DirectoryError> {
        credential.password().verify_with(|password| {
            let user_id = credential.user_id().as_bytes();
            let mut input = Zeroizing::new(Vec::with_capacity(
                DOMAIN
                    .len()
                    .saturating_add(16)
                    .saturating_add(user_id.len())
                    .saturating_add(password.len()),
            ));
            input.extend_from_slice(DOMAIN);
            for field in [user_id, password] {
                let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
                input.extend_from_slice(&length.to_be_bytes());
                input.extend_from_slice(field);
            }
            hmac_sha256(self.key.0.as_ref(), &input).map_err(|error| {
                tracing::error!(alarm = "policy_crypto_failure", op = "basic_verify_cache", %error);
                DirectoryError::Unavailable("the cache key could not be derived".to_owned())
            })
        })
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

#[async_trait::async_trait]
impl CredentialDirectory for CachingDirectory {
    async fn lookup(
        &self,
        credential: &BasicCredential,
        services: &dyn HostServices,
    ) -> Result<Option<UserRecord>, DirectoryError> {
        let key = self.key_of(credential)?;
        let now = self.now_ms();

        if let Some(entry) = get(&self.hits, &key, now) {
            return Ok(entry.record);
        }
        if self.config.negative_ttl_secs > 0
            && let Some(entry) = get(&self.misses, &key, now)
        {
            return Ok(entry.record);
        }

        // A failure is returned without being remembered: a blip must not
        // become an outage lasting the TTL.
        let answer = self.inner.lookup(credential, services).await?;

        let (map, capacity, ttl_secs) = match &answer {
            Some(_) => (&self.hits, self.config.max_entries, self.config.ttl_secs),
            None if self.config.negative_ttl_secs > 0 => (
                &self.misses,
                self.config.max_negative_entries,
                self.config.negative_ttl_secs,
            ),
            None => return Ok(answer),
        };
        let entry = Entry {
            record: answer.clone(),
            expires_at_ms: now.saturating_add(ttl_secs.saturating_mul(1000)),
        };
        put(map, capacity, key, entry, now);
        Ok(answer)
    }

    async fn verify(
        &self,
        record: Option<&UserRecord>,
        credential: &BasicCredential,
        services: &dyn HostServices,
    ) -> Result<bool, DirectoryError> {
        self.inner.verify(record, credential, services).await
    }

    async fn verify_holding(
        &self,
        record: Option<&UserRecord>,
        credential: &BasicCredential,
        lease: Option<RecoveryLease>,
        services: &dyn HostServices,
    ) -> Result<bool, DirectoryError> {
        self.inner
            .verify_holding(record, credential, lease, services)
            .await
    }

    fn initialize(&self, ext: &InitExtensions) -> Result<(), String> {
        self.inner.initialize(ext)
    }

    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
}

// -----------------------------------------------------------------------------
// Private types
// -----------------------------------------------------------------------------

/// The per-process MAC key, which never leaves the process and never prints.
struct MacKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MacKey(<elided>)")
    }
}

/// One cached answer.
#[derive(Clone, Debug)]
struct Entry {
    /// `None` for a credential the directory refused.
    record: Option<UserRecord>,
    /// Milliseconds since the cache was built, after which this is stale.
    expires_at_ms: u64,
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn default_max_entries() -> usize {
    DEFAULT_MAX_ENTRIES
}

/// A live entry for `key`, if there is one.
///
/// Expired entries are left for `put` to clear, so a read never takes the
/// write lock.
fn get(map: &RwLock<HashMap<[u8; 32], Entry>>, key: &[u8; 32], now: u64) -> Option<Entry> {
    let guard = map.read().ok()?;
    let entry = guard.get(key)?;
    (entry.expires_at_ms > now).then(|| entry.clone())
}

/// Store `entry`, unless the map is full of live entries.
fn put(
    map: &RwLock<HashMap<[u8; 32], Entry>>,
    capacity: usize,
    key: [u8; 32],
    entry: Entry,
    now: u64,
) {
    let Ok(mut guard) = map.write() else {
        return;
    };
    if guard.len() >= capacity && !guard.contains_key(&key) {
        guard.retain(|_, held| held.expires_at_ms > now);
        if guard.len() >= capacity {
            // Uncached rather than evicting an entry in use, so a flood
            // cannot displace real traffic.
            return;
        }
    }
    guard.insert(key, entry);
}
