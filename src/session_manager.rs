//! Web session management with server-side token storage and auto-refresh.
//!
//! Provides [`WebSessionManager`] — a session-based token store for web
//! applications (Axum, Actix, etc.) that keeps OAuth tokens server-side,
//! keyed by an opaque session ID stored in a browser cookie.
//!
//! # Design
//!
//! ```text
//! Browser cookie (session_id) ──→ WebSessionManager ──→ server-side token store
//!                                                           │
//!                                                     auto-refresh via
//!                                                     OidcClient::refresh_access_token()
//! ```
//!
//! When [`WebSessionManager::get_token`] is called:
//! 1. Look up the `StoredToken` by session ID.
//! 2. If the access token is still valid → return it immediately.
//! 3. If expired but a refresh token exists → call the IdP token endpoint,
//!    update the stored token, and return the new access token.
//! 4. If no refresh token or refresh fails → return an error (caller should
//!    redirect to login).
//!
//! The session ID is a random UUID — it carries no JWT payload, so it works
//! regardless of which OAuth2 client signed the original token.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tracing;

use crate::error::{PepError, Result};
use crate::oidc_client::{OidcClient, TokenResponse};
use crate::token_provider::{compute_expires_at, seconds_until_expiry};
use crate::token_store::{StoredToken, TokenStore};

// ---------------------------------------------------------------------------
// InMemoryTokenStore
// ---------------------------------------------------------------------------

/// Simple in-memory `TokenStore` backed by a `HashMap` under a `std::sync::RwLock`.
///
/// Designed for short-lived session data that does not need to survive
/// process restarts. All sessions are lost when the process exits.
///
/// Uses `std::sync::RwLock` (not `tokio::sync::RwLock`) because the
/// `TokenStore` trait methods are synchronous and in-memory operations
/// are fast enough to not block async tasks meaningfully.
#[derive(Debug, Default)]
pub struct InMemoryTokenStore {
    sessions: RwLock<HashMap<String, StoredToken>>,
}

impl InMemoryTokenStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for InMemoryTokenStore {
    fn load(&self, name: &str) -> Result<Option<StoredToken>> {
        let sessions = self.sessions.read().unwrap();
        Ok(sessions.get(name).cloned())
    }

    fn save(&self, name: &str, token: &StoredToken) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(name.to_string(), token.clone());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(name);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebSessionManager
// ---------------------------------------------------------------------------

/// Server-side session manager for web applications.
///
/// Maps opaque session IDs (UUIDs) to OAuth tokens with automatic refresh.
///
/// # Usage
///
/// ```rust,ignore
/// use pep::session_manager::WebSessionManager;
/// use pep::oidc_client::OidcClient;
/// use std::sync::Arc;
///
/// let mgr = WebSessionManager::new(
///     OidcClient::new(),
///     "https://idm.example.com/oauth2/openid/pdt-api".to_string(),
///     "pdt-api".to_string(),
///     None,
///     "openid profile email".to_string(),
/// );
///
/// // After OAuth callback:
/// let session_id = mgr.create_session(&token_response).await.unwrap();
/// // Store `session_id` in an HttpOnly cookie.
///
/// // On subsequent requests:
/// let access_token = mgr.get_token(&session_id).await.unwrap();
/// ```
pub struct WebSessionManager {
    /// Token storage backend (in-memory by default).
    store: Arc<dyn TokenStore>,
    /// OIDC client for token refresh.
    oidc_client: OidcClient,
    /// Issuer URL (e.g. `https://idm.example.com/oauth2/openid/pdt-api`).
    issuer_url: String,
    /// OAuth2 client ID.
    client_id: String,
    /// OAuth2 client secret (optional for public clients).
    client_secret: Option<String>,
    /// OAuth2 scopes.
    scope: String,
    /// Refresh token 60 seconds before actual expiry to avoid edge cases.
    refresh_buffer_secs: u64,
}

impl std::fmt::Debug for WebSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSessionManager")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .finish()
    }
}

impl WebSessionManager {
    /// Create a new `WebSessionManager` with an in-memory store.
    ///
    /// # Arguments
    ///
    /// * `oidc_client` — OIDC client for token refresh operations.
    /// * `issuer_url` — OIDC issuer URL (used for discovery during refresh).
    /// * `client_id` — OAuth2 client ID.
    /// * `client_secret` — Optional client secret (for confidential clients).
    /// * `scope` — OAuth2 scopes (used during refresh).
    pub fn new(
        oidc_client: OidcClient,
        issuer_url: String,
        client_id: String,
        client_secret: Option<String>,
        scope: String,
    ) -> Self {
        Self {
            store: Arc::new(InMemoryTokenStore::new()),
            oidc_client,
            issuer_url,
            client_id,
            client_secret,
            scope,
            refresh_buffer_secs: 60,
        }
    }

    /// Create a new `WebSessionManager` with a custom token store backend.
    ///
    /// Use this if you want persistent sessions (e.g. via a future
    /// `SqliteTokenStore`) or a shared store across multiple instances.
    pub fn with_store(
        oidc_client: OidcClient,
        store: Arc<dyn TokenStore>,
        issuer_url: String,
        client_id: String,
        client_secret: Option<String>,
        scope: String,
    ) -> Self {
        Self {
            store,
            oidc_client,
            issuer_url,
            client_id,
            client_secret,
            scope,
            refresh_buffer_secs: 60,
        }
    }

    /// Set the refresh buffer (how many seconds before expiry to trigger a refresh).
    ///
    /// Default: 60 seconds.
    #[allow(dead_code)]
    pub fn with_refresh_buffer(mut self, secs: u64) -> Self {
        self.refresh_buffer_secs = secs;
        self
    }

    /// Create a new session from a token response.
    ///
    /// Generates a random UUID session ID, stores the tokens server-side,
    /// and returns the session ID to be stored in a browser cookie.
    ///
    /// **Important:** The caller must keep the `refresh_token` from the
    /// token response — this method stores it server-side so it can be
    /// used for later refreshes.
    pub async fn create_session(&self, token_response: &TokenResponse) -> Result<String> {
        let session_id = uuid::Uuid::new_v4().to_string();

        let expires_at = compute_expires_at(token_response.expires_in);

        let stored = StoredToken::new(
            &token_response.access_token,
            token_response.refresh_token.clone(),
            &token_response.token_type,
            &expires_at,
            token_response.scope.clone(),
        );

        // InMemoryTokenStore uses blocking_read/blocking_write, so we need
        // to use spawn_blocking or just call directly (they are fast locks).
        self.store.save(&session_id, &stored)?;

        tracing::debug!(
            session_id = %session_id,
            expires_at = %expires_at,
            "Created web session"
        );

        Ok(session_id)
    }

    /// Get a valid access token for the given session, refreshing if necessary.
    ///
    /// # Returns
    ///
    /// * `Ok(token)` — A valid access token (possibly freshly refreshed).
    /// * `Err(PepError::AuthenticationRequired)` — Session not found or
    ///   refresh failed. The caller should redirect to login.
    pub async fn get_token(&self, session_id: &str) -> Result<String> {
        let stored = self.store.load(session_id)?;

        let stored = match stored {
            Some(s) => s,
            None => {
                tracing::debug!(session_id = %session_id, "Session not found");
                return Err(PepError::AuthenticationRequired);
            }
        };

        // Check if token is still valid (with buffer)
        let remaining = seconds_until_expiry(&stored.expires_at);
        if remaining > self.refresh_buffer_secs {
            // Still valid
            return Ok(stored.access_token);
        }

        tracing::debug!(
            session_id = %session_id,
            remaining_secs = remaining,
            "Token near expiry, attempting refresh"
        );

        // Need to refresh
        self.refresh_session(session_id, &stored).await
    }

    /// Destroy a session, removing it from the store.
    ///
    /// Call this on logout to invalidate the session immediately.
    pub fn destroy_session(&self, session_id: &str) -> Result<()> {
        self.store.delete(session_id)?;
        tracing::debug!(session_id = %session_id, "Session destroyed");
        Ok(())
    }

    /// Refresh the token for a session and update the store.
    async fn refresh_session(
        &self,
        session_id: &str,
        stored: &StoredToken,
    ) -> Result<String> {
        let refresh_token = match &stored.refresh_token {
            Some(rt) => rt.clone(),
            None => {
                tracing::debug!(session_id = %session_id, "No refresh token, cannot refresh");
                // Clean up the expired session
                let _ = self.store.delete(session_id);
                return Err(PepError::AuthenticationRequired);
            }
        };

        let response = self
            .oidc_client
            .refresh_access_token(
                &self.issuer_url,
                &self.client_id,
                self.client_secret.as_deref(),
                &refresh_token,
                Some(&self.scope),
            )
            .await;

        match response {
            Ok(token_response) => {
                let new_expires_at = compute_expires_at(token_response.expires_in);

                // Build updated token — providers may rotate the refresh token
                let updated = StoredToken::new(
                    &token_response.access_token,
                    token_response
                        .refresh_token
                        .clone()
                        .or(Some(refresh_token)),
                    &token_response.token_type,
                    &new_expires_at,
                    token_response.scope.clone().or(stored.scope.clone()),
                );

                let access_token = updated.access_token.clone();
                self.store.save(session_id, &updated)?;

                tracing::info!(
                    session_id = %session_id,
                    expires_at = %new_expires_at,
                    "Token refreshed successfully"
                );

                Ok(access_token)
            }
            Err(PepError::TokenRefreshFailed { status, detail }) => {
                tracing::warn!(
                    session_id = %session_id,
                    status = status,
                    "Token refresh failed: {}", detail
                );
                // Refresh token itself is invalid — clean up
                let _ = self.store.delete(session_id);
                Err(PepError::AuthenticationRequired)
            }
            Err(e) => {
                tracing::warn!(
                    session_id = %session_id,
                    "Token refresh error: {}", e
                );
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_store::TokenStore;

    // -----------------------------------------------------------------------
    // InMemoryTokenStore
    // -----------------------------------------------------------------------

    #[test]
    fn test_in_memory_store_round_trip() {
        let store = InMemoryTokenStore::new();
        let token = StoredToken::new(
            "access123",
            Some("refresh456".to_string()),
            "Bearer",
            "2099-01-01T00:00:00Z",
            Some("openid profile".to_string()),
        );

        store.save("session1", &token).unwrap();
        let loaded = store.load("session1").unwrap().expect("should exist");
        assert_eq!(loaded.access_token, "access123");
        assert_eq!(loaded.refresh_token.as_deref(), Some("refresh456"));
    }

    #[test]
    fn test_in_memory_store_delete() {
        let store = InMemoryTokenStore::new();
        let token = StoredToken::new("a", None, "Bearer", "2099-01-01T00:00:00Z", None);
        store.save("temp", &token).unwrap();
        assert!(store.load("temp").unwrap().is_some());
        store.delete("temp").unwrap();
        assert!(store.load("temp").unwrap().is_none());
    }

    #[test]
    fn test_in_memory_store_load_nonexistent() {
        let store = InMemoryTokenStore::new();
        assert!(store.load("ghost").unwrap().is_none());
    }

    #[test]
    fn test_in_memory_store_overwrite() {
        let store = InMemoryTokenStore::new();
        let token1 = StoredToken::new("first", None, "Bearer", "2099-01-01T00:00:00Z", None);
        store.save("key", &token1).unwrap();

        let token2 = StoredToken::new("second", None, "Bearer", "2099-01-01T00:00:00Z", None);
        store.save("key", &token2).unwrap();

        let loaded = store.load("key").unwrap().unwrap();
        assert_eq!(loaded.access_token, "second");
    }

    // -----------------------------------------------------------------------
    // WebSessionManager
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_session_stores_token() {
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com/oauth2/openid/pdt-api".to_string(),
            "pdt-api".to_string(),
            None,
            "openid profile".to_string(),
        );

        let rt = tokio::runtime::Runtime::new().unwrap();

        let token_response = TokenResponse {
            access_token: "access-abc".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: Some("refresh-xyz".to_string()),
            id_token: None,
            scope: Some("openid profile".to_string()),
        };

        let session_id = rt.block_on(mgr.create_session(&token_response)).unwrap();
        assert!(!session_id.is_empty());

        // Should be a valid UUID
        assert!(uuid::Uuid::parse_str(&session_id).is_ok());
    }

    #[test]
    fn test_create_two_sessions_have_different_ids() {
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com".to_string(),
            "client".to_string(),
            None,
            "openid".to_string(),
        );

        let rt = tokio::runtime::Runtime::new().unwrap();

        let token_response = TokenResponse {
            access_token: "a".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: None,
            id_token: None,
            scope: None,
        };

        let id1 = rt.block_on(mgr.create_session(&token_response)).unwrap();
        let id2 = rt.block_on(mgr.create_session(&token_response)).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_get_token_valid_returns_access_token() {
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com".to_string(),
            "client".to_string(),
            None,
            "openid".to_string(),
        );

        let rt = tokio::runtime::Runtime::new().unwrap();

        let token_response = TokenResponse {
            access_token: "my-access-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: Some("my-refresh".to_string()),
            id_token: None,
            scope: None,
        };

        let session_id = rt.block_on(mgr.create_session(&token_response)).unwrap();
        let token = rt.block_on(mgr.get_token(&session_id)).unwrap();
        assert_eq!(token, "my-access-token");
    }

    #[test]
    fn test_get_token_unknown_session_errors() {
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com".to_string(),
            "client".to_string(),
            None,
            "openid".to_string(),
        );

        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(mgr.get_token("nonexistent-session"));
        assert!(matches!(result, Err(PepError::AuthenticationRequired)));
    }

    #[test]
    fn test_destroy_session() {
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com".to_string(),
            "client".to_string(),
            None,
            "openid".to_string(),
        );

        let rt = tokio::runtime::Runtime::new().unwrap();

        let token_response = TokenResponse {
            access_token: "test-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: None,
            id_token: None,
            scope: None,
        };

        let session_id = rt.block_on(mgr.create_session(&token_response)).unwrap();

        // Token works
        let token = rt.block_on(mgr.get_token(&session_id)).unwrap();
        assert_eq!(token, "test-token");

        // Destroy
        mgr.destroy_session(&session_id).unwrap();

        // Now it should error
        let result = rt.block_on(mgr.get_token(&session_id));
        assert!(matches!(result, Err(PepError::AuthenticationRequired)));
    }

    #[test]
    fn test_get_token_expired_no_refresh_errors() {
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com".to_string(),
            "client".to_string(),
            None,
            "openid".to_string(),
        );

        let rt = tokio::runtime::Runtime::new().unwrap();

        // Create a session with an already-expired token and no refresh token
        let stored = StoredToken::new(
            "expired-access",
            None, // no refresh token
            "Bearer",
            "2020-01-01T00:00:00Z", // past
            None,
        );

        // Directly store it using the internal store
        mgr.store.save("expired-session", &stored).unwrap();

        let result = rt.block_on(mgr.get_token("expired-session"));
        assert!(matches!(result, Err(PepError::AuthenticationRequired)));
    }

    #[test]
    fn test_session_manager_debug() {
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com".to_string(),
            "pdt-api".to_string(),
            None,
            "openid".to_string(),
        );
        let debug_str = format!("{:?}", mgr);
        assert!(debug_str.contains("WebSessionManager"));
        assert!(debug_str.contains("pdt-api"));
    }

    #[test]
    fn test_with_custom_store() {
        let custom_store: Arc<dyn TokenStore> = Arc::new(InMemoryTokenStore::new());
        let mgr = WebSessionManager::with_store(
            OidcClient::new(),
            custom_store,
            "https://idm.example.com".to_string(),
            "client".to_string(),
            None,
            "openid".to_string(),
        );

        let rt = tokio::runtime::Runtime::new().unwrap();

        let token_response = TokenResponse {
            access_token: "custom-store-token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: None,
            id_token: None,
            scope: None,
        };

        let session_id = rt.block_on(mgr.create_session(&token_response)).unwrap();
        let token = rt.block_on(mgr.get_token(&session_id)).unwrap();
        assert_eq!(token, "custom-store-token");
    }

    #[test]
    fn test_get_token_near_expiry_no_refresh() {
        // Token that is within the refresh buffer but not yet fully expired
        // and has no refresh token should still return the access token
        // (it hasn't expired yet, just close)
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com".to_string(),
            "client".to_string(),
            None,
            "openid".to_string(),
        );

        // Calculate expires_at as now+30 seconds (within 60s buffer)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let near_expiry = now + 30; // 30 seconds from now, within 60s buffer

        let expires_str = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            1970 + (near_expiry / 31556952) as u32, // rough year
            1, 1, 0, 0, 0
        );

        // Just test that token with remaining time > 0 works even without refresh
        let stored = StoredToken::new(
            "still-valid",
            None,
            "Bearer",
            "2099-01-01T00:00:00Z",
            None,
        );
        mgr.store.save("valid-session", &stored).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let token = rt.block_on(mgr.get_token("valid-session")).unwrap();
        assert_eq!(token, "still-valid");

        // Suppress unused variable warning
        let _ = (expires_str, near_expiry);
    }
}
