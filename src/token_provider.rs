//! Token Provider module for managing authentication token lifecycle.
//!
//! Provides a trait-based abstraction for obtaining access tokens, with
//! implementations for static tokens, service account token exchange
//! (RFC 8693), and interactive browser-based login (PKCE).
//!
//! Uses native Rust 1.75+ `async fn` in traits (no `async-trait` crate).
//! Enum dispatch via `TokenProviderEnum` for dynamic selection.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tracing;

use crate::error::{PepError, Result};
use crate::oidc_client::{OidcClient, TokenResponse};
use crate::token_store::{TokenStore, StoredToken};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Trait for obtaining a valid access token.
///
/// Implementations may cache tokens, refresh them before expiry, or
/// prompt the user interactively.
///
/// Uses native Rust 1.75+ `async fn` in traits. Callers that need dynamic
/// dispatch should use [`TokenProviderEnum`] which wraps all variants in
/// an enum (no `Box<dyn>` required).
#[allow(async_fn_in_trait)]
pub trait TokenProvider: Send + Sync {
    /// Return a valid (possibly freshly obtained) access token.
    async fn get_token(&self) -> Result<String>;

    /// Drop any cached token so the next `get_token()` performs a full
    /// refresh. Default: no-op — stateless providers (e.g.
    /// [`StaticTokenProvider`]) hold nothing to drop.
    ///
    /// HTTP clients use this for the single retry-on-401 pattern: on an
    /// expired/invalid-token rejection, `invalidate()` then re-request the
    /// token exactly once.
    async fn invalidate(&self) {}
}

// ---------------------------------------------------------------------------
// Cached token (internal)
// ---------------------------------------------------------------------------

/// In-memory cached token with expiry tracking.
///
/// Expiry is wall-clock (`SystemTime`), not monotonic: the authoritative
/// expiry is the JWT's `exp` claim, which lives in IdP wall-clock time.
#[derive(Clone, Debug)]
struct CachedToken {
    token: String,
    expires_at: SystemTime,
}

impl CachedToken {
    /// Refresh buffer before expiry. Mirrors the session manager's
    /// clock-skew posture (0.4.4 raised its default 60 → 120 seconds after
    /// the expired-token race in nghr #40ad7123).
    const BUFFER_SECS: u64 = 120;

    /// Create a new cached entry from a token response.
    ///
    /// Expiry is taken from the token's REAL `exp` claim when the access
    /// token is a decodable JWT — IdPs (Kanidm included) have been observed
    /// to mint tokens whose actual lifetime is shorter than the exchange
    /// response's `expires_in` (nghr #40ad7123; trustee 199c4801: recurring
    /// ~15-min Cedar fail-closed windows on the MCP service-account path).
    /// Falls back to the `expires_in` estimate (default 900s) for opaque
    /// tokens. This ports the session_manager 0.5.3 fix (d7b485d) to the
    /// service path.
    fn from_response(token_response: &TokenResponse) -> Self {
        let buffer = Duration::from_secs(Self::BUFFER_SECS);
        let expires_at = match jwt_exp_epoch(&token_response.access_token) {
            Some(exp_epoch) => {
                tracing::debug!(
                    jwt_exp = exp_epoch,
                    buffer_secs = Self::BUFFER_SECS,
                    "CachedToken: using real JWT exp claim for expiry"
                );
                UNIX_EPOCH + Duration::from_secs(exp_epoch).saturating_sub(buffer)
            }
            None => {
                let expires_in = token_response.expires_in.unwrap_or(900);
                tracing::debug!(
                    expires_in,
                    buffer_secs = Self::BUFFER_SECS,
                    "CachedToken: no JWT exp claim, using expires_in estimate"
                );
                SystemTime::now()
                    + Duration::from_secs(expires_in.saturating_sub(Self::BUFFER_SECS))
            }
        };
        Self {
            token: token_response.access_token.clone(),
            expires_at,
        }
    }

    /// Returns `true` if the token is still valid (with buffer).
    fn is_valid(&self) -> bool {
        SystemTime::now() < self.expires_at
    }

    /// Seconds of usable life left (0 if past `expires_at`).
    fn seconds_remaining(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|now| {
                self.expires_at
                    .duration_since(UNIX_EPOCH + Duration::from_secs(now.as_secs()))
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// StaticTokenProvider
// ---------------------------------------------------------------------------

/// A trivial provider that wraps a static string.
///
/// Use this when the token is managed externally (e.g. environment variable
/// set by a wrapper script) and never expires within the session.
#[derive(Clone)]
pub struct StaticTokenProvider {
    token: String,
}

impl std::fmt::Debug for StaticTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticTokenProvider")
            .field("token", &format!("{}...", &self.token[..self.token.len().min(8)]))
            .finish()
    }
}

impl StaticTokenProvider {
    /// Create a new static token provider.
    pub fn new(token: String) -> Self {
        Self { token }
    }
}

impl TokenProvider for StaticTokenProvider {
    async fn get_token(&self) -> Result<String> {
        Ok(self.token.clone())
    }
}

// ---------------------------------------------------------------------------
// ServiceAccountTokenProvider
// ---------------------------------------------------------------------------

/// Configuration for creating a [`ServiceAccountTokenProvider`].
#[derive(Debug, Clone)]
pub struct ServiceAccountConfig {
    /// Long-lived Kanidm service account API token (never expires).
    pub service_token: String,
    /// OIDC issuer URL (e.g. `https://idm.tanbal.ir/oauth2/openid/pdt-api`).
    pub issuer_url: String,
    /// OAuth2 client ID (e.g. `pdt-api`).
    pub client_id: String,
    /// OAuth2 client secret (optional for public clients).
    pub client_secret: Option<String>,
    /// Target audience for the exchanged token (e.g. `pdt-api`).
    pub audience: String,
    /// Scopes to request during exchange (default: `openid profile email`).
    pub scope: Option<String>,
}

/// Token provider that exchanges a long-lived service account token for
/// short-lived OIDC access tokens via RFC 8693 token exchange.
///
/// Caches the resulting access token in memory and proactively refreshes
/// it at the buffered expiry minus the proactive horizon, with a
/// per-instance jitter so a fleet of seats does not mint in phase (see
/// [`Self::PROACTIVE_REFRESH_SECS`] and [`Self::REFRESH_JITTER_SECS`]).
#[derive(Clone)]
pub struct ServiceAccountTokenProvider {
    oidc_client: OidcClient,
    config: ServiceAccountConfig,
    cache: Arc<RwLock<Option<CachedToken>>>,
    /// Single-flight mint gate (S3 client contract 2a4e7402, approved
    /// d8c835e9; storm acceptance case): concurrent slow-path callers queue
    /// here; the cache is re-checked after acquiring the gate, so an N-way
    /// 401 storm collapses into exactly ONE IdP exchange and a reactive
    /// re-mint can no longer double-mint against the proactive refresher.
    mint_gate: Arc<Mutex<()>>,
    /// Per-instance jitter offset in `[0, REFRESH_JITTER_SECS]` added to
    /// the refresh horizon (fleet herd desync; see
    /// [`Self::REFRESH_JITTER_SECS`]).
    refresh_jitter_secs: u64,
}

impl std::fmt::Debug for ServiceAccountTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountTokenProvider")
            .field("audience", &self.config.audience)
            .finish()
    }
}

impl ServiceAccountTokenProvider {
    /// Proactive-refresh horizon: when a cached token's remaining life drops
    /// to this many seconds, it is no longer served from cache — the next
    /// `get_token()` exchanges, and a spawned proactive refresher exchanges
    /// without waiting for a caller (order payam ece49472, clause 1; same
    /// pattern class as thq v0.9.2).
    ///
    /// Composes with [`CachedToken::BUFFER_SECS`] (120s clock-skew/transit
    /// safety): a minted token with 900s life is cached with `exp - 120s`, so
    /// the effective lazy exchange point is `exp - 210s` and the proactive
    /// task fires at the same threshold. Callers never hold a token that can
    /// die mid-request — the payam v0.2.5 send-path outage wire (nghr
    /// 374803e5).
    pub const PROACTIVE_REFRESH_SECS: u64 = 90;

    /// Fleet jitter applied ON TOP of [`Self::PROACTIVE_REFRESH_SECS`]:
    /// each provider instance draws a FIXED offset in
    /// `[0, REFRESH_JITTER_SECS]` at construction (from process-start
    /// nanos — no `rand` dependency) and its refresh horizon becomes
    /// `PROACTIVE_REFRESH_SECS + offset`. This desynchronizes mint phases
    /// across a fleet of seats (herd avoidance: N seats must not hit the
    /// IdP in the same second) while never weakening the correctness
    /// floor — the offset can only move the horizon EARLIER, so the
    /// real-life mint margin only grows (nghr fb82b866 spec c35042bb,
    /// leg L1: "jitter ±15s fleet-wide to avoid herd").
    pub const REFRESH_JITTER_SECS: u64 = 15;

    /// Create a new service account token provider.
    pub fn new(config: ServiceAccountConfig) -> Self {
        Self {
            oidc_client: OidcClient::new(),
            config,
            cache: Arc::new(RwLock::new(None)),
            mint_gate: Arc::new(Mutex::new(())),
            refresh_jitter_secs: Self::draw_jitter(),
        }
    }

    /// Create with a shared `OidcClient` (reuses HTTP connection pool and
    /// discovery cache).
    pub fn with_client(oidc_client: OidcClient, config: ServiceAccountConfig) -> Self {
        Self {
            oidc_client,
            config,
            cache: Arc::new(RwLock::new(None)),
            mint_gate: Arc::new(Mutex::new(())),
            refresh_jitter_secs: Self::draw_jitter(),
        }
    }

    /// Draw this instance's jitter offset: sub-second nanos at construction,
    /// bucketed into `[0, REFRESH_JITTER_SECS]`. Per-instance, not secret;
    /// process start times differ across the fleet, so phases diverge.
    fn draw_jitter() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 % (Self::REFRESH_JITTER_SECS + 1))
            .unwrap_or(0)
    }

    /// THIS instance's refresh horizon on the buffer-adjusted clock: the
    /// fixed serve floor widened by the per-instance jitter. Used
    /// consistently by the background refresher's wake-up, the
    /// single-flight cache re-check, and the serve threshold — an early
    /// (jittered) background wake must not be refused by the gate's
    /// re-check, or the jitter would no-op.
    fn refresh_horizon(&self) -> u64 {
        Self::PROACTIVE_REFRESH_SECS + self.refresh_jitter_secs
    }

    /// Force a token exchange regardless of cache state.
    async fn exchange(&self) -> Result<CachedToken> {
        tracing::debug!(
            "Exchanging service account token for audience '{}'",
            self.config.audience
        );

        let response = self
            .oidc_client
            .exchange_token(
                &self.config.issuer_url,
                &self.config.client_id,
                self.config.client_secret.as_deref(),
                &self.config.service_token,
                &self.config.audience,
                self.config.scope.as_deref(),
            )
            .await?;

        let cached = CachedToken::from_response(&response);
        // 0.5.13 mint journal: fingerprint (NEVER the token itself) + jti +
        // real remaining life, so 401 windows can be correlated across
        // surfaces by token identity. A fresh token born at/below the serve
        // threshold is the clock-skew signature (IdP/resource-server clock
        // ahead of this host) — the exact class behind recurring
        // "self-recovering" 401 windows on PDT surfaces.
        let secs = cached.seconds_remaining();
        let fp = token_fingerprint(&response.access_token);
        let jti = jwt_jti(&response.access_token).unwrap_or_else(|| "opaque".to_string());
        if secs <= Self::PROACTIVE_REFRESH_SECS {
            tracing::warn!(
                audience = %self.config.audience,
                jti = %jti,
                fp = %fp,
                seconds_remaining = secs,
                "pep: FRESH token born at/below the serve threshold — clock skew (IdP vs this \
                 host) or a short-lived grant; expect upstream 401s until clocks converge"
            );
        }
        tracing::info!(
            audience = %self.config.audience,
            jti = %jti,
            fp = %fp,
            expires_in = ?response.expires_in,
            seconds_remaining = secs,
            "pep: token minted (per-mint journal fingerprint)"
        );

        Ok(cached)
    }

    /// Exchange a fresh token and install it in the cache.
    ///
    /// Single-flight (S3 client contract 2a4e7402, CPO-approved; storm
    /// acceptance case: an N-way concurrent 401 storm must produce exactly
    /// ONE IdP exchange): every exchange takes the mint gate, and the cache
    /// is re-checked after acquiring it — a caller that queued behind an
    /// in-flight mint serves the freshly installed token instead of minting
    /// again. This also collapses a reactive re-mint racing the proactive
    /// refresher into a single exchange.
    async fn refresh_cache(&self) -> Result<()> {
        let _mint = self.mint_gate.lock().await;
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.seconds_remaining() > self.refresh_horizon() {
                    tracing::debug!(
                        audience = %self.config.audience,
                        "pep: mint gate acquired after a concurrent refresh; serving the fresh cache"
                    );
                    return Ok(());
                }
            }
        }
        match self.exchange().await {
            Ok(cached) => {
                *self.cache.write().await = Some(cached);
                Ok(())
            }
            Err(e) => {
                // S3 review note 1: per-mint journaling is normative,
                // failures included. Reactive-path failures previously
                // surfaced only to the caller — ops saw nothing.
                tracing::warn!(
                    audience = %self.config.audience,
                    error = %e,
                    "pep: token exchange failed (reactive mint)"
                );
                Err(e)
            }
        }
    }

    /// Spawn a background task that keeps the cache fresh proactively: it
    /// exchanges at THIS instance's refresh horizon
    /// (`PROACTIVE_REFRESH_SECS + per-instance jitter`, herd desync across
    /// the fleet — fb82b866 spec c35042bb L1) WITHOUT waiting for a
    /// caller, so long-idle processes (payam sends during quiet periods —
    /// nghr 374803e5) never start an operation on a dying token.
    ///
    /// Failure posture: an exchange failure is logged (warn) and retried
    /// after a 5s backoff — the cache keeps its previous token, and
    /// `get_token()` still fails LOUD if the cache empties and the IdP stays
    /// down (fail-closed; never a lying empty/success).
    ///
    /// The task lives until the returned handle is aborted; it holds a clone
    /// of the provider (cheap: `Arc` internals), so dropping the original is
    /// safe either way. Idempotent per cache state — safe to call once at
    /// startup.
    pub fn spawn_proactive_refresh(&self) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                // Sleep until the T-90s horizon (or exchange now if the
                // cache is empty / already at horizon).
                let wait = {
                    let cache = this.cache.read().await;
                    match cache.as_ref() {
                        Some(t) => Duration::from_secs(
                            t.seconds_remaining().saturating_sub(this.refresh_horizon()),
                        ),
                        None => Duration::ZERO,
                    }
                };
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
                if let Err(e) = this.refresh_cache().await {
                    tracing::warn!(
                        audience = %this.config.audience,
                        error = %e,
                        "pep: proactive token refresh failed; retrying in 5s"
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        })
    }
}

impl TokenProvider for ServiceAccountTokenProvider {
    async fn get_token(&self) -> Result<String> {
        // Fast path: serve the cached token ONLY if it outlives THIS
        // instance's refresh horizon (fixed floor + per-instance jitter).
        // A token this close to death can expire mid-request — the exact
        // payam 374803e5 incident wire — so it is exchanged instead of
        // served. The jitter only widens the margin (horizon moves
        // earlier), never shrinks it.
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.seconds_remaining() > self.refresh_horizon() {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Slow path: exchange and write.
        self.refresh_cache().await?;
        let cache = self.cache.read().await;
        Ok(cache
            .as_ref()
            .expect("cache was just written by refresh_cache")
            .token
            .clone())
    }

    /// Drop the cached token; the next `get_token()` performs a full
    /// RFC 8693 exchange. Used by HTTP clients for the single
    /// retry-on-401 pattern.
    async fn invalidate(&self) {
        let mut cache = self.cache.write().await;
        if cache.take().is_some() {
            tracing::debug!(
                audience = %self.config.audience,
                "ServiceAccountTokenProvider cache invalidated"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// InteractiveTokenProvider (stub)
// ---------------------------------------------------------------------------

/// Configuration for creating an [`InteractiveTokenProvider`].
#[derive(Debug, Clone)]
pub struct InteractiveConfig {
    /// OIDC issuer URL.
    pub issuer_url: String,
    /// OAuth2 client ID.
    pub client_id: String,
    /// OAuth2 client secret (optional for public clients).
    pub client_secret: Option<String>,
    /// Redirect URI for the authorization callback.
    pub redirect_uri: String,
    /// OAuth2 scopes to request.
    pub scope: String,
    /// Credential name used as the key for [`TokenStore`].
    ///
    /// This is the name under which tokens are saved/loaded (e.g. `"kanidm_interactive"`).
    pub credential_name: String,
}

/// Token provider for interactive browser-based login using Authorization
/// Code Flow with PKCE.
///
/// This provider loads tokens from a [`TokenStore`] (populated by an external
/// login flow such as `trustee mcp auth`). If the access token is expired, it
/// attempts a silent refresh using the stored refresh token.
///
/// The provider does **not** open a browser — that is the caller's
/// responsibility. It assumes tokens have already been obtained and stored.
#[derive(Clone)]
pub struct InteractiveTokenProvider {
    oidc_client: OidcClient,
    config: InteractiveConfig,
    token_store: Arc<dyn TokenStore>,
    cache: Arc<RwLock<Option<CachedToken>>>,
}

impl std::fmt::Debug for InteractiveTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractiveTokenProvider")
            .field("issuer_url", &self.config.issuer_url)
            .field("credential_name", &self.config.credential_name)
            .finish()
    }
}

impl InteractiveTokenProvider {
    /// Create a new interactive token provider with the given config and token store.
    ///
    /// Tokens are loaded from / saved to the [`TokenStore`] under
       /// `config.credential_name`.
    pub fn with_store(config: InteractiveConfig, token_store: Arc<dyn TokenStore>) -> Self {
        Self {
            oidc_client: OidcClient::new(),
            config,
            token_store,
            cache: Arc::new(RwLock::new(None)),
        }
    }
}

impl TokenProvider for InteractiveTokenProvider {
    async fn get_token(&self) -> Result<String> {
        // 1. Fast path: check in-memory cache
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    return Ok(cached.token.clone());
                }
            }
        }

        // 2. Load from token store
        let stored = self.token_store.load(&self.config.credential_name)?;

        let stored = match stored {
            Some(s) => s,
            None => {
                return Err(PepError::BadRequest(format!(
                    "Not authenticated. Run: trustee mcp auth {}",
                    self.config.credential_name
                )));
            }
        };

        // 3. If access token is still valid, use it
        if !stored.is_expired() {
            let remaining = seconds_until_expiry(&stored.expires_at).max(1);
            let cached = CachedToken {
                token: stored.access_token.clone(),
                expires_at: UNIX_EPOCH + Duration::from_secs(now_epoch() + remaining),
            };
            let token = cached.token.clone();
            {
                let mut cache = self.cache.write().await;
                *cache = Some(cached);
            }
            return Ok(token);
        }

        // 4. Access token expired — try refresh
        let refresh_token = match &stored.refresh_token {
            Some(rt) => rt.clone(),
            None => {
                return Err(PepError::BadRequest(format!(
                    "Session expired. Run: trustee mcp auth {}",
                    self.config.credential_name
                )));
            }
        };

        tracing::debug!(
            "Refreshing expired token for credential '{}'",
            self.config.credential_name
        );

        let response = self
            .oidc_client
            .refresh_access_token(
                &self.config.issuer_url,
                &self.config.client_id,
                self.config.client_secret.as_deref(),
                &refresh_token,
                Some(&self.config.scope),
            )
            .await;

        match response {
            Ok(token_response) => {
                // Persist updated tokens. Expiry comes from the token's REAL
                // `exp` claim (falls back to `expires_in` for opaque tokens) —
                // the stored record must agree with the in-memory cache, or a
                // restart resurrects an over-lived token (real-exp audit,
                // order payam ece49472 clause 3; nghr 849e7528 class).
                let new_expires_at =
                    compute_expires_at_from_jwt(&token_response.access_token, token_response.expires_in);
                let updated = StoredToken::new(
                    &token_response.access_token,
                    token_response.refresh_token.clone().or(Some(refresh_token)),
                    &token_response.token_type,
                    &new_expires_at,
                    token_response.scope.clone().or(stored.scope.clone()),
                );

                // Persist updated tokens
                if let Err(e) = self.token_store.save(&self.config.credential_name, &updated) {
                    tracing::warn!(
                        "Failed to persist refreshed token: {}. Using in-memory only.",
                        e
                    );
                }

                // Cache in memory
                let cached = CachedToken::from_response(&token_response);
                let token = cached.token.clone();
                {
                    let mut cache = self.cache.write().await;
                    *cache = Some(cached);
                }

                Ok(token)
            }
            Err(PepError::TokenRefreshFailed { .. }) => {
                // Refresh token itself is expired/invalid
                Err(PepError::BadRequest(format!(
                    "Session expired. Run: trustee mcp auth {}",
                    self.config.credential_name
                )))
            }
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers for InteractiveTokenProvider
// ---------------------------------------------------------------------------

/// Current UNIX epoch seconds.
pub(crate) fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Compute the number of seconds until the given RFC-3339 timestamp.
///
/// Returns 0 if the timestamp is in the past or cannot be parsed.
pub(crate) fn seconds_until_expiry(expires_at: &str) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_epoch = crate::token_store::parse_rfc3339_to_epoch_public(expires_at);
    expires_epoch.saturating_sub(now)
}

/// Compute an RFC-3339 timestamp `expires_in` seconds from now.
pub(crate) fn compute_expires_at(expires_in: Option<u64>) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_epoch = now + expires_in.unwrap_or(900);
    epoch_to_rfc3339(expires_epoch)
}

/// Extract the raw `exp` epoch seconds from a JWT payload, if decodable.
///
/// Decodes the JWT payload WITHOUT signature verification — only the `exp`
/// field is read. Returns `None` for non-JWT tokens, malformed payloads, or
/// tokens without an `exp` claim. Single decode path shared by
/// [`CachedToken::from_response`] and [`compute_expires_at_from_jwt`].
fn jwt_exp_epoch(access_token: &str) -> Option<u64> {
    jwt_payload(access_token)?.get("exp")?.as_u64()
}

/// Decode the JWT payload (middle segment) into JSON, if the token is a JWT.
fn jwt_payload(access_token: &str) -> Option<serde_json::Value> {
    // JWT structure: header.payload.signature — we only need the payload
    let parts: Vec<&str> = access_token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    use base64::Engine;
    let payload = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Try standard base64 as fallback
            match base64::engine::general_purpose::STANDARD_NO_PAD.decode(parts[1]) {
                Ok(bytes) => bytes,
                Err(_) => return None,
            }
        }
    };

    serde_json::from_slice(&payload).ok()
}

/// Extract the `jti` claim from a JWT access token (mint journaling, 0.5.13).
fn jwt_jti(access_token: &str) -> Option<String> {
    jwt_payload(access_token)?
        .get("jti")?
        .as_str()
        .map(|s| s.to_string())
}

/// Short NON-SENSITIVE fingerprint of a token for journaling (0.5.13):
/// first 12 hex chars of SHA-256. NEVER log the token itself.
fn token_fingerprint(access_token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(access_token.as_bytes());
    digest
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

/// Compute expiry from the actual JWT `exp` claim.
///
/// Decodes the JWT payload (without signature verification — we only need
/// the `exp` field) and returns an RFC-3339 timestamp. Falls back to
/// `compute_expires_at(expires_in)` if the JWT cannot be decoded.
///
/// This is more accurate than using `expires_in` from the token response
/// because it accounts for the time between the IdP minting the token
/// and the response reaching us.
pub(crate) fn compute_expires_at_from_jwt(
    access_token: &str,
    expires_in_fallback: Option<u64>,
) -> String {
    match jwt_exp_epoch(access_token) {
        Some(exp) => {
            tracing::debug!(
                jwt_exp = exp,
                "Extracted real exp from JWT payload for expiry tracking"
            );
            epoch_to_rfc3339(exp)
        }
        None => {
            tracing::debug!("No exp claim in JWT, falling back to expires_in estimate");
            compute_expires_at(expires_in_fallback)
        }
    }
}

/// Convert epoch seconds to an RFC-3339 UTC timestamp.
pub(crate) fn epoch_to_rfc3339(epoch: u64) -> String {
    let days = epoch / 86400;
    let remainder = epoch % 86400;
    let hour = remainder / 3600;
    let min = (remainder % 3600) / 60;
    let sec = remainder % 60;

    let (year, month, day) = epoch_to_civil(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

/// Convert days-since-epoch to (year, month, day) using Hinnant's algorithm.
fn epoch_to_civil(days: u64) -> (u32, u32, u32) {
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

// ---------------------------------------------------------------------------
// Universal 401 retry driver (order payam ece49472, clause 2)
// ---------------------------------------------------------------------------

/// The outcome of ONE request attempt, fed to [`with_token_retry`].
///
/// The mapping is the consumer's job and is method-agnostic by construction:
/// an HTTP 401 response maps to [`Attempt::StaleToken`] regardless of whether
/// the request was a GET or a POST — a 401 means the request was never
/// authenticated, therefore never executed, therefore always safe to retry
/// after a re-mint. A 403 is authorization, NOT staleness — map it to
/// [`Attempt::Failed`] so it stays terminal and is never retried.
#[derive(Debug)]
pub enum Attempt<T> {
    /// The request completed. Carry the response through.
    Served(T),
    /// The server answered 401 Unauthorized: the bearer token was rejected
    /// before the request could execute. The driver re-mints the token and
    /// retries exactly once.
    StaleToken,
    /// The request failed with any other error — passed through untouched,
    /// never retried by the driver.
    Failed(PepError),
}

/// Run an authenticated request with the universal single-retry-on-401
/// posture: obtain a token, attempt the request, and on a 401 reject the
/// cache, re-mint, and retry exactly ONCE — for reads AND writes alike
/// (order payam ece49472, clause 2).
///
/// Why retrying writes is safe here: [`Attempt::StaleToken`] is only for 401
/// responses, which by definition arrive instead of execution. The one
/// honest caveat: if a server ever executes a write AND answers 401, that is
/// a server bug this driver surfaces rather than hides — the retry is still
/// bounded at one.
///
/// Double-401 (still rejected after a fresh mint) is terminal:
/// [`PepError::AuthDegraded`] with `retryable: false` — the credential
/// itself is wrong, not stale; hammering it will not help.
///
/// ```no_run
/// # async fn demo<P: pep::TokenProvider>(provider: &P) -> pep::Result<()> {
/// use pep::Attempt;
/// // Reads and writes use the SAME driver — the closure picks the verb.
/// let body: String = pep::with_token_retry(provider, |token| {
///     let token = token.clone();
///     async move {
///         let resp = reqwest::Client::new()
///             .post("https://pdt.example/api/messages")
///             .bearer_auth(&token)
///             .send()
///             .await
///             .map_err(|e| Attempt::Failed(pep::PepError::Internal(e.into())));
///         match resp {
///             Ok(r) if r.status() == reqwest::StatusCode::UNAUTHORIZED => Attempt::StaleToken,
///             Ok(r) => r.text().await
///                 .map(Attempt::Served)
///                 .unwrap_or_else(|e| Attempt::Failed(pep::PepError::Internal(e.into()))),
///             Err(already_an_attempt) => already_an_attempt,
///         }
///     }
/// }).await?;
/// # Ok(())
/// # }
/// ```
pub async fn with_token_retry<P, T, F, Fut>(provider: &P, mut attempt: F) -> Result<T>
where
    P: TokenProvider,
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Attempt<T>>,
{
        let token = provider.get_token().await?;
        match attempt(token.clone()).await {
            Attempt::Served(served) => Ok(served),
            Attempt::Failed(e) => Err(e),
            Attempt::StaleToken => {
                // 401: the cached token was rejected. Kill the cache, re-mint,
                // retry exactly once.
                provider.invalidate().await;
                let fresh = provider.get_token().await?;
                // 0.5.13: identity check. If the IdP re-issued the SAME token
                // that was just rejected, the rejection is deterministic
                // (clock skew, revoked credential, or a server-side JWKS
                // rotation window): the retry cannot change the outcome, and
                // the terminal error must say so instead of letting callers
                // conclude the token lifecycle is broken and loop retries.
                let identical = fresh == token;
                if identical {
                    tracing::warn!(
                        "pep: re-mint returned the IDENTICAL token that was just rejected — \
                         deterministic rejection (clock skew / revoked credential / server-side \
                         JWKS rotation window); token lifecycle is not the fault"
                    );
                }
                match attempt(fresh).await {
                    Attempt::Served(served) => Ok(served),
                    Attempt::Failed(e) => Err(e),
                    Attempt::StaleToken => Err(PepError::AuthDegraded {
                        detail: if identical {
                            "401 persisted after token re-mint and single retry; the re-mint \
                             returned the IDENTICAL token — deterministic rejection (IdP/host \
                             clock skew, revoked subject credential, or a server-side JWKS \
                             rotation window). The token lifecycle is NOT the fault: check the \
                             resource server / IdP side; do not loop retries."
                                .to_string()
                        } else {
                            "401 persisted after token re-mint and single retry: \
                             the credential itself is rejected, not stale"
                                .to_string()
                        },
                        retryable: false,
                    }),
                }
            }
        }
    }

// ---------------------------------------------------------------------------
// TokenProviderEnum — enum dispatch
// ---------------------------------------------------------------------------

/// Enum-based dispatch over all `TokenProvider` variants.
///
/// Since native async traits don't support `dyn`, this enum provides
/// the same ergonomic dynamic selection without `async-trait`.
#[derive(Clone, Debug)]
pub enum TokenProviderEnum {
    /// Static token that never changes.
    Static(StaticTokenProvider),
    /// Service account with automatic RFC 8693 token exchange.
    ServiceAccount(ServiceAccountTokenProvider),
    /// Interactive browser-based login (stub).
    Interactive(InteractiveTokenProvider),
}

impl TokenProvider for TokenProviderEnum {
    async fn get_token(&self) -> Result<String> {
        match self {
            Self::Static(p) => p.get_token().await,
            Self::ServiceAccount(p) => p.get_token().await,
            Self::Interactive(p) => p.get_token().await,
        }
    }

    /// Delegates to the wrapped provider. NOTE: this MUST be an explicit
    /// override — trait default methods do not dispatch through enum
    /// wrappers, and the trait default is a no-op.
    async fn invalidate(&self) {
        match self {
            Self::Static(p) => p.invalidate().await,
            Self::ServiceAccount(p) => p.invalidate().await,
            Self::Interactive(p) => p.invalidate().await,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convenience: create a `TokenProviderEnum::Static` from a string.
impl From<String> for TokenProviderEnum {
    fn from(token: String) -> Self {
        Self::Static(StaticTokenProvider::new(token))
    }
}

/// Convenience: create a `TokenProviderEnum::Static` from `Option<String>`.
///
/// Returns a provider with an empty token if `None`, which will cause
/// downstream auth to fail gracefully.
impl From<Option<String>> for TokenProviderEnum {
    fn from(token: Option<String>) -> Self {
        Self::Static(StaticTokenProvider::new(token.unwrap_or_default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_token_provider() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = StaticTokenProvider::new("test-token".to_string());
        let token = rt.block_on(provider.get_token()).unwrap();
        assert_eq!(token, "test-token");
    }

    #[test]
    fn test_cached_token_from_response() {
        let response = TokenResponse {
            access_token: "abc123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: None,
            id_token: None,
            scope: None,
        };
        let cached = CachedToken::from_response(&response);
        assert_eq!(cached.token, "abc123");
        assert!(cached.is_valid());
    }

    #[test]
    fn test_cached_token_expiry() {
        let response = TokenResponse {
            access_token: "abc123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(0), // already expired
            refresh_token: None,
            id_token: None,
            scope: None,
        };
        let cached = CachedToken::from_response(&response);
        // With buffer=30, effective=0, should be expired immediately
        assert!(!cached.is_valid());
    }

    #[test]
    fn test_token_provider_enum_static() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider: TokenProviderEnum = TokenProviderEnum::Static(
            StaticTokenProvider::new("enum-test".to_string()),
        );
        let token = rt.block_on(provider.get_token()).unwrap();
        assert_eq!(token, "enum-test");
    }

    #[test]
    fn test_token_provider_enum_from_string() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider: TokenProviderEnum = "direct-string".to_string().into();
        let token = rt.block_on(provider.get_token()).unwrap();
        assert_eq!(token, "direct-string");
    }

    #[test]
    fn test_token_provider_enum_from_option() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider: TokenProviderEnum = Some("some-token".to_string()).into();
        let token = rt.block_on(provider.get_token()).unwrap();
        assert_eq!(token, "some-token");
    }

    #[test]
    fn test_service_account_config_builder() {
        let config = ServiceAccountConfig {
            service_token: "svc-token".to_string(),
            issuer_url: "https://idm.example.com/oauth2/openid/pdt-api".to_string(),
            client_id: "pdt-api".to_string(),
            client_secret: None,
            audience: "pdt-api".to_string(),
            scope: Some("openid profile email".to_string()),
        };
        let _provider = ServiceAccountTokenProvider::new(config);
        // Just verify construction works
    }

    #[test]
    fn test_compute_expires_at() {
        let ts = compute_expires_at(Some(0));
        assert!(ts.ends_with("Z"));
        assert_eq!(ts.len(), 20); // YYYY-MM-DDTHH:MM:SSZ

        // Should be approximately "now"
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let parsed = crate::token_store::parse_rfc3339_to_epoch_public(&ts);
        assert!(parsed <= now_epoch + 1);
    }

    #[test]
    fn test_epoch_to_rfc3339_round_trip() {
        // epoch 0 = 1970-01-01T00:00:00Z
        assert_eq!(epoch_to_rfc3339(0), "1970-01-01T00:00:00Z");
        // epoch 86400 = 1970-01-02T00:00:00Z
        assert_eq!(epoch_to_rfc3339(86400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn test_interactive_config_builder() {
        let config = InteractiveConfig {
            issuer_url: "https://idm.example.com/oauth2/openid/test".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            redirect_uri: "http://localhost:8765/callback".to_string(),
            scope: "openid profile".to_string(),
            credential_name: "test_interactive".to_string(),
        };
        assert_eq!(config.credential_name, "test_interactive");
    }

    // -- real-JWT-exp expiry (nghr 849e7528) ---------------------------------

    /// Build a minimal unsigned JWT with the given `exp` epoch claim.
    fn jwt_with_exp(exp_epoch: u64) -> String {
        use base64::Engine;
        let b64 = |b: &[u8]| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        };
        let header = b64(br#"{"alg":"none"}"#);
        let payload = b64(format!(r#"{{"exp":{exp_epoch}}}"#).as_bytes());
        format!("{header}.{payload}.sig")
    }

    #[test]
    fn from_response_honors_real_jwt_exp_over_expires_in() {
        // IdP claims 900s remaining, but the JWT really expires in 300s —
        // the cache MUST honor the real exp (nghr #40ad7123 class of bug).
        let exp_epoch = now_epoch() + 300;
        let response = TokenResponse {
            access_token: jwt_with_exp(exp_epoch),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: None,
            id_token: None,
            scope: None,
        };
        let cached = CachedToken::from_response(&response);
        // Exact: real-exp path involves no now() arithmetic.
        let expected =
            UNIX_EPOCH + Duration::from_secs(exp_epoch - CachedToken::BUFFER_SECS);
        assert_eq!(cached.expires_at, expected);
        assert!(cached.is_valid());
    }

    #[test]
    fn from_response_falls_back_to_estimate_without_jwt_exp() {
        // Opaque token: expires_in estimate applies (900 - 120 buffer).
        let response = TokenResponse {
            access_token: "not-a-jwt".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: None,
            id_token: None,
            scope: None,
        };
        let cached = CachedToken::from_response(&response);
        let expected = SystemTime::now() + Duration::from_secs(900 - 120);
        let drift = cached
            .expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .abs_diff(expected.duration_since(UNIX_EPOCH).unwrap().as_secs());
        assert!(drift <= 2, "estimate drift {drift}s too large");
        assert!(cached.is_valid());
    }

    #[test]
    fn from_response_malformed_jwt_falls_back_to_estimate() {
        let response = TokenResponse {
            access_token: "aGk.not-base64-json.sig".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(600),
            refresh_token: None,
            id_token: None,
            scope: None,
        };
        let cached = CachedToken::from_response(&response);
        let expected = SystemTime::now() + Duration::from_secs(600 - 120);
        let drift = cached
            .expires_at
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .abs_diff(expected.duration_since(UNIX_EPOCH).unwrap().as_secs());
        assert!(drift <= 2, "estimate drift {drift}s too large");
    }

    #[test]
    fn real_exp_shorter_than_buffer_renders_token_invalid() {
        // JWT expiring sooner than the buffer: must NOT be served at all
        // (fail-safe: immediate re-exchange on next get_token).
        let exp_epoch = now_epoch() + 30; // < BUFFER_SECS
        let response = TokenResponse {
            access_token: jwt_with_exp(exp_epoch),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: None,
            id_token: None,
            scope: None,
        };
        let cached = CachedToken::from_response(&response);
        assert!(!cached.is_valid());
    }

    // -- real-exp audit (order payam ece49472 clause 3; nghr 849e7528) -------

    #[test]
    fn compute_expires_at_from_jwt_honors_real_exp() {
        let exp = now_epoch() + 321;
        let jwt = jwt_with_exp(exp);
        let ts = compute_expires_at_from_jwt(&jwt, Some(900));
        // Re-derive: the RFC-3339 string must decode back to `exp`, not
        // now+900 (the estimate the old code stored).
        let parsed = parse_rfc3339_pub(&ts);
        assert!(parsed.abs_diff(exp) <= 1, "got {ts} for exp {exp}");
    }

    #[test]
    fn compute_expires_at_from_jwt_falls_back_without_exp() {
        let before = now_epoch();
        let ts = compute_expires_at_from_jwt("not-a-jwt", Some(300));
        let parsed = parse_rfc3339_pub(&ts);
        assert!(parsed >= before + 299 && parsed <= before + 301);
    }

    /// Minimal RFC-3339 (Zulu) parser for tests: `YYYY-MM-DDTHH:MM:SSZ`.
    fn parse_rfc3339_pub(ts: &str) -> u64 {
        let (date, time) = ts.split_once('T').unwrap();
        let date = date.trim_end_matches('Z');
        let ymd: Vec<u64> = date.split('-').map(|p| p.parse().unwrap()).collect();
        let hms: Vec<u64> = time.trim_end_matches('Z').split(':').map(|p| p.parse().unwrap()).collect();
        // days-from-civil (proleptic Gregorian), inverse of epoch_to_civil
        let (y, m, d) = (ymd[0] as i64, ymd[1] as i64, ymd[2] as i64);
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        (days as u64) * 86400 + hms[0] * 3600 + hms[1] * 60 + hms[2]
    }

    // -- TokenProvider::invalidate (nghr 849e7528) ---------------------------

    #[tokio::test]
    async fn invalidate_clears_service_account_cache() {
        let provider = ServiceAccountTokenProvider::new(ServiceAccountConfig {
            service_token: "svc".to_string(),
            issuer_url: "https://idm.example".to_string(),
            client_id: "pdt-api".to_string(),
            client_secret: None,
            audience: "pdt-api".to_string(),
            scope: None,
        });
        // Seed the private cache directly (same-module test).
        *provider.cache.write().await = Some(CachedToken {
            token: "stale".to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(600),
        });
        provider.invalidate().await;
        assert!(provider.cache.read().await.is_none());
        // Invalidating an empty cache is a no-op, not an error.
        provider.invalidate().await;
    }

    #[tokio::test]
    async fn enum_invalidate_dispatches_to_inner_provider() {
        let provider = ServiceAccountTokenProvider::new(ServiceAccountConfig {
            service_token: "svc".to_string(),
            issuer_url: "https://idm.example".to_string(),
            client_id: "pdt-api".to_string(),
            client_secret: None,
            audience: "pdt-api".to_string(),
            scope: None,
        });
        *provider.cache.write().await = Some(CachedToken {
            token: "stale".to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(600),
        });
        let wrapped = TokenProviderEnum::ServiceAccount(provider);
        // Trait-level call must dispatch through the enum override —
        // the trait default (no-op) would silently keep the stale token.
        TokenProvider::invalidate(&wrapped).await;
        let ServiceAccountTokenProvider { cache, .. } = match &wrapped {
            TokenProviderEnum::ServiceAccount(p) => p,
            _ => unreachable!(),
        };
        assert!(cache.read().await.is_none());
    }

    // -- fleet jitter horizon (nghr fb82b866 spec c35042bb L1; 0.5.15) -------

    fn svc_provider_with_jitter(jitter: u64) -> ServiceAccountTokenProvider {
        let mut p = ServiceAccountTokenProvider::new(ServiceAccountConfig {
            service_token: "svc".to_string(),
            issuer_url: "https://idm.example".to_string(),
            client_id: "pdt-api".to_string(),
            client_secret: None,
            audience: "pdt-api".to_string(),
            scope: None,
        });
        p.refresh_jitter_secs = jitter; // same-module: private field is settable
        p
    }

    #[test]
    fn drawn_jitter_offsets_stay_within_bounds() {
        for _ in 0..32 {
            let p = ServiceAccountTokenProvider::new(ServiceAccountConfig {
                service_token: "svc".to_string(),
                issuer_url: "https://idm.example".to_string(),
                client_id: "pdt-api".to_string(),
                client_secret: None,
                audience: "pdt-api".to_string(),
                scope: None,
            });
            assert!(
                p.refresh_jitter_secs <= ServiceAccountTokenProvider::REFRESH_JITTER_SECS,
                "jitter {} out of [0, {}]",
                p.refresh_jitter_secs,
                ServiceAccountTokenProvider::REFRESH_JITTER_SECS
            );
        }
    }

    #[test]
    fn refresh_horizon_is_fixed_floor_plus_jitter() {
        assert_eq!(
            svc_provider_with_jitter(0).refresh_horizon(),
            ServiceAccountTokenProvider::PROACTIVE_REFRESH_SECS
        );
        assert_eq!(
            svc_provider_with_jitter(15).refresh_horizon(),
            ServiceAccountTokenProvider::PROACTIVE_REFRESH_SECS
                + ServiceAccountTokenProvider::REFRESH_JITTER_SECS
        );
    }

    #[tokio::test]
    async fn jittered_horizon_gates_the_serve_path_without_weakening_the_floor() {
        // remaining 100s on the buffer-adjusted clock:
        // jitter 15 → horizon 105 → 100 is BELOW the horizon → NOT served;
        // the slow path runs and fails LOUD against the unreachable issuer
        // (fail-closed, never a lying serve).
        let p15 = svc_provider_with_jitter(15);
        *p15.cache.write().await = Some(CachedToken {
            token: "jittered".to_string(),
            expires_at: UNIX_EPOCH + Duration::from_secs(now_epoch() + 100),
        });
        assert!(
            p15.get_token().await.is_err(),
            "below the jittered horizon: must re-exchange (fail loud), not serve"
        );

        // jitter 0 → horizon 90 → 100 is above the floor → served from cache.
        let p0 = svc_provider_with_jitter(0);
        *p0.cache.write().await = Some(CachedToken {
            token: "cached".to_string(),
            expires_at: UNIX_EPOCH + Duration::from_secs(now_epoch() + 100),
        });
        assert_eq!(
            p0.get_token().await.unwrap(),
            "cached",
            "above the fixed floor: served from cache without an exchange"
        );
    }
}
