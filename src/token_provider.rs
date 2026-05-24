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
}

/// Token provider for interactive browser-based login using Authorization
/// Code Flow with PKCE.
///
/// **Note:** This is currently a stub. Full implementation requires a local
/// HTTP server to handle the redirect callback.
#[derive(Clone)]
pub struct InteractiveTokenProvider {
    #[allow(dead_code)]
    config: InteractiveConfig,
    #[allow(dead_code)]
    oidc_client: OidcClient,
    cache: Arc<RwLock<Option<CachedToken>>>,
}

impl std::fmt::Debug for InteractiveTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractiveTokenProvider")
            .field("issuer_url", &self.config.issuer_url)
            .finish()
    }
}

impl InteractiveTokenProvider {
    /// Create a new interactive token provider (stub).
    pub fn new(config: InteractiveConfig) -> Self {
        Self {
            oidc_client: OidcClient::new(),
            config,
            cache: Arc::new(RwLock::new(None)),
        }
    }
}

impl TokenProvider for InteractiveTokenProvider {
    async fn get_token(&self) -> Result<String> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref() {
                if cached.is_valid() {
                    return Ok(cached.token.clone());
                }
            }
        }

        // TODO: Implement browser-based PKCE flow
        // 1. Generate code_verifier + code_challenge
        // 2. Build authorization URL
        // 3. Open browser
        // 4. Start local HTTP server to catch redirect
        // 5. Exchange code for tokens
        // 6. Cache result

        Err(PepError::BadRequest(
            "InteractiveTokenProvider: not yet implemented".to_string(),
        ))
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
}
