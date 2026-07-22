//! Token Provider module for managing authentication token lifecycle.
//!
//! Provides a trait-based abstraction for obtaining access tokens, with
//! implementations for static tokens, service account token exchange
//! (RFC 8693), and interactive browser-based login (PKCE).
//!
//! Uses native Rust 1.75+ `async fn` in traits (no `async-trait` crate).
//! Enum dispatch via `TokenProviderEnum` for dynamic selection.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
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
}

// ---------------------------------------------------------------------------
// Cached token (internal)
// ---------------------------------------------------------------------------

/// In-memory cached token with expiry tracking.
#[derive(Clone, Debug)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

impl CachedToken {
    /// Create a new cached entry from a token response.
    fn from_response(token_response: &TokenResponse) -> Self {
        let expires_in = token_response.expires_in.unwrap_or(900);
        // Refresh 30 seconds before actual expiry to avoid edge cases
        let buffer_secs = 30;
        let effective_secs = expires_in.saturating_sub(buffer_secs);
        Self {
            token: token_response.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(effective_secs),
        }
    }

    /// Returns `true` if the token is still valid (with buffer).
    fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
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
/// it 30 seconds before expiry.
#[derive(Clone)]
pub struct ServiceAccountTokenProvider {
    oidc_client: OidcClient,
    config: ServiceAccountConfig,
    cache: Arc<RwLock<Option<CachedToken>>>,
}

impl std::fmt::Debug for ServiceAccountTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountTokenProvider")
            .field("audience", &self.config.audience)
            .finish()
    }
}

impl ServiceAccountTokenProvider {
    /// Create a new service account token provider.
    pub fn new(config: ServiceAccountConfig) -> Self {
        Self {
            oidc_client: OidcClient::new(),
            config,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Create with a shared `OidcClient` (reuses HTTP connection pool and
    /// discovery cache).
    pub fn with_client(oidc_client: OidcClient, config: ServiceAccountConfig) -> Self {
        Self {
            oidc_client,
            config,
            cache: Arc::new(RwLock::new(None)),
        }
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

        tracing::info!(
            "Token exchange successful, expires_in={:?}s",
            response.expires_in
        );

        Ok(CachedToken::from_response(&response))
    }
}

impl TokenProvider for ServiceAccountTokenProvider {
    async fn get_token(&self) -> Result<String> {
        // Fast path: check read lock
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Slow path: exchange and write
        let cached = self.exchange().await?;
        let token = cached.token.clone();

        {
            let mut cache = self.cache.write().await;
            *cache = Some(cached);
        }

        Ok(token)
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
            let cached = CachedToken {
                token: stored.access_token.clone(),
                expires_at: Instant::now()
                    + Duration::from_secs(
                        seconds_until_expiry(&stored.expires_at).max(1),
                    ),
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
                // Build updated StoredToken
                let new_expires_at = compute_expires_at(token_response.expires_in);
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

/// Convert epoch seconds to an RFC-3339 UTC timestamp.
fn epoch_to_rfc3339(epoch: u64) -> String {
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
}
