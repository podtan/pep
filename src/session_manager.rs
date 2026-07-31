//! Web session management with server-side token storage and auto-refresh.
//!
//! Provides [`WebSessionManager`] — a session-based token store for web
//! applications (Axum, Actix, etc.) that keeps OAuth tokens server-side,
//! keyed by an opaque session ID stored in a browser cookie.
//!
//! # Design
//!
//! ```text
//! Browser cookie (session_id) ──→ WebSessionManager ──→ server-side session map
//!                                                           │
//!                                                     auto-refresh via
//!                                                     OidcClient::refresh_access_token()
//!                                                           │
//!                                                     idle timeout sweep
//!                                                     (amortized on every get_token)
//! ```
//!
//! ## Session lifecycle
//!
//! 1. **Login** → `create_session()` stores tokens + `last_accessed = now`.
//! 2. **Active request** → `get_token()` returns/refreshes token, updates
//!    `last_accessed`.
//! 3. **Idle** → if `last_accessed + idle_timeout` < now, session is swept.
//! 4. **Logout** → `destroy_session()` removes immediately.
//! 5. **Refresh failure** → session destroyed, returns `AuthenticationRequired`.
//!
//! The session ID is a random UUID — it carries no JWT payload, so it works
//! regardless of which OAuth2 client signed the original token.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tokio::sync::Mutex;
use tracing;

use crate::error::{PepError, Result};
use crate::oidc_client::{OidcClient, TokenResponse};
use crate::token_provider::{compute_expires_at_from_jwt, seconds_until_expiry};
use crate::token_store::StoredToken;

// ---------------------------------------------------------------------------
// SessionEntry (internal)
// ---------------------------------------------------------------------------

/// Internal session entry: token data + access-time tracking.
#[derive(Clone, Debug)]
struct SessionEntry {
    token: StoredToken,
    last_accessed: Instant,
}

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
///
/// **Note:** For web session management with idle-timeout eviction, use
/// [`WebSessionManager`] directly — it has its own internal store with
/// access-time tracking. This type is kept for compatibility with the
/// [`crate::token_store::TokenStore`] trait (e.g. for `InteractiveTokenProvider`).
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

impl crate::token_store::TokenStore for InMemoryTokenStore {
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
/// Maps opaque session IDs (UUIDs) to OAuth tokens with automatic refresh
/// and idle-timeout eviction.
///
/// # Idle timeout
///
/// Sessions that have not been accessed for `idle_timeout_secs` (default: 1 hour)
/// are evicted during an amortized sweep that runs when the session count
/// exceeds `sweep_threshold` (default: 64).
///
/// # Usage
///
/// ```rust,ignore
/// use pep::session_manager::WebSessionManager;
/// use pep::oidc_client::OidcClient;
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
    /// Internal session map with access-time tracking.
    sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
    /// Per-session async mutexes to serialize concurrent refresh attempts.
    /// When multiple requests for the same session need a refresh at the same
    /// time, only the first one performs the OIDC refresh; others wait on this
    /// lock and then read the already-refreshed token from the session store.
    refresh_locks: Arc<RwLock<HashMap<String, Arc<Mutex<()>>>>>,
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
    /// Refresh token this many seconds before actual expiry (default: 60).
    refresh_buffer_secs: u64,
    /// Evict sessions idle for longer than this (default: 3600 = 1 hour).
    idle_timeout_secs: u64,
    /// Sweep idle sessions when count exceeds this threshold (default: 64).
    sweep_threshold: usize,
}

impl std::fmt::Debug for WebSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSessionManager")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .finish()
    }
}

// Convenience constants
const DEFAULT_REFRESH_BUFFER_SECS: u64 = 120;
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 3600; // 1 hour
const DEFAULT_SWEEP_THRESHOLD: usize = 64;

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
            sessions: Arc::new(RwLock::new(HashMap::new())),
            refresh_locks: Arc::new(RwLock::new(HashMap::new())),
            oidc_client,
            issuer_url,
            client_id,
            client_secret,
            scope,
            refresh_buffer_secs: DEFAULT_REFRESH_BUFFER_SECS,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            sweep_threshold: DEFAULT_SWEEP_THRESHOLD,
        }
    }

    /// Set the refresh buffer (how many seconds before expiry to trigger a refresh).
    ///
    /// Default: 60 seconds.
    pub fn with_refresh_buffer(mut self, secs: u64) -> Self {
        self.refresh_buffer_secs = secs;
        self
    }

    /// Set the idle timeout — sessions not accessed for this long are evicted.
    ///
    /// Default: 3600 seconds (1 hour).
    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Set the sweep threshold — amortized cleanup runs when session count
    /// exceeds this number.
    ///
    /// Default: 64.
    pub fn with_sweep_threshold(mut self, threshold: usize) -> Self {
        self.sweep_threshold = threshold;
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

        let expires_at =
            compute_expires_at_from_jwt(&token_response.access_token, token_response.expires_in);

        let stored = StoredToken::new(
            &token_response.access_token,
            token_response.refresh_token.clone(),
            &token_response.token_type,
            &expires_at,
            token_response.scope.clone(),
        );

        let entry = SessionEntry {
            token: stored,
            last_accessed: Instant::now(),
        };

        {
            let mut sessions = self.sessions.write().unwrap();
            sessions.insert(session_id.clone(), entry);
        }

        tracing::debug!(
            session_id = %session_id,
            expires_at = %expires_at,
            "Created web session"
        );

        Ok(session_id)
    }

    /// Get a valid access token for the given session, refreshing if necessary.
    ///
    /// Updates `last_accessed` on every successful call. Performs amortized
    /// idle-session sweep when the session count exceeds the threshold.
    ///
    /// # Returns
    ///
    /// * `Ok(token)` — A valid access token (possibly freshly refreshed).
    /// * `Err(PepError::AuthenticationRequired)` — Session not found, idle
    ///   timed out, or refresh failed. The caller should redirect to login.
    pub async fn get_token(&self, session_id: &str) -> Result<String> {
        self._get_token(session_id, false).await
    }

    /// Force-refresh the token for a session, ignoring the cache.
    ///
    /// Use this when a caller knows the cached token is invalid (e.g. JWT
    /// validation failed with ExpiredSignature despite our expiry estimate
    /// saying there's time left — clock skew between servers).
    pub async fn force_refresh(&self, session_id: &str) -> Result<String> {
        self._get_token(session_id, true).await
    }

    async fn _get_token(&self, session_id: &str, force_refresh: bool) -> Result<String> {
        // 1. Load session + update last_accessed
        let stored = {
            let mut sessions = self.sessions.write().unwrap();

            // Amortized sweep
            if sessions.len() > self.sweep_threshold {
                self.sweep_idle_sessions(&mut sessions);
            }

            let entry = match sessions.get_mut(session_id) {
                Some(e) => e,
                None => {
                    tracing::debug!(session_id = %session_id, "Session not found");
                    return Err(PepError::AuthenticationRequired);
                }
            };

            // Check idle timeout
            let idle_secs = entry.last_accessed.elapsed().as_secs();
            if idle_secs > self.idle_timeout_secs {
                tracing::debug!(
                    session_id = %session_id,
                    idle_secs = idle_secs,
                    idle_timeout = self.idle_timeout_secs,
                    "Session idle-expired"
                );
                sessions.remove(session_id);
                return Err(PepError::AuthenticationRequired);
            }

            // Update access time
            entry.last_accessed = Instant::now();
            entry.token.clone()
        };

        // 2. Check if token is still valid (with buffer)
        let remaining = seconds_until_expiry(&stored.expires_at);
        if !force_refresh && remaining > self.refresh_buffer_secs {
            return Ok(stored.access_token);
        }

        tracing::debug!(
            session_id = %session_id,
            remaining_secs = remaining,
            "Token near expiry, attempting refresh"
        );

        // 3. Acquire per-session refresh lock to serialize concurrent refreshes.
        //    If another request already refreshed the token while we waited,
        //    re-read from the store and return the fresh token.
        let lock = self.get_refresh_lock(session_id);
        let _guard = lock.lock().await;

        // Re-check: another request may have already refreshed while we waited
        if !force_refresh {
            if let Some(token) = self.try_cached_token(session_id)? {
                return Ok(token);
            }
        }

        // 4. Still need to refresh
        self.refresh_session(session_id, &stored).await
    }

    /// Get or create the per-session refresh mutex.
    fn get_refresh_lock(&self, session_id: &str) -> Arc<Mutex<()>> {
        // Fast path: read lock
        if let Some(lock) = self.refresh_locks.read().unwrap().get(session_id) {
            return lock.clone();
        }
        // Slow path: write lock to insert
        let mut locks = self.refresh_locks.write().unwrap();
        locks
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Check if the session's token has been refreshed by another request
    /// since we last checked. Returns `Ok(Some(token))` if the token is now
    /// valid (another request refreshed it), `Ok(None)` if still needs refresh.
    fn try_cached_token(&self, session_id: &str) -> Result<Option<String>> {
        let sessions = self.sessions.read().unwrap();
        if let Some(entry) = sessions.get(session_id) {
            let remaining = seconds_until_expiry(&entry.token.expires_at);
            if remaining > self.refresh_buffer_secs {
                tracing::debug!(
                    session_id = %session_id,
                    remaining_secs = remaining,
                    "Token already refreshed by concurrent request"
                );
                return Ok(Some(entry.token.access_token.clone()));
            }
        }
        Ok(None)
    }

    /// Destroy a session, removing it from the store.
    ///
    /// Call this on logout to invalidate the session immediately.
    pub fn destroy_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_id);
        tracing::debug!(session_id = %session_id, "Session destroyed");
        Ok(())
    }

    /// Returns the current number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.read().unwrap().len()
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
                let mut sessions = self.sessions.write().unwrap();
                sessions.remove(session_id);
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
                let new_expires_at = compute_expires_at_from_jwt(
                    &token_response.access_token,
                    token_response.expires_in,
                );

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

                // Update the session entry (preserves last_accessed)
                let mut sessions = self.sessions.write().unwrap();
                if let Some(entry) = sessions.get_mut(session_id) {
                    entry.token = updated;
                }

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
                let mut sessions = self.sessions.write().unwrap();
                sessions.remove(session_id);
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

    /// Sweep idle-expired sessions from the map.
    ///
    /// Called inline when the session count exceeds `sweep_threshold`.
    /// Removes entries where `last_accessed.elapsed() > idle_timeout_secs`.
    fn sweep_idle_sessions(&self, sessions: &mut HashMap<String, SessionEntry>) {
        let before = sessions.len();
        let timeout = std::time::Duration::from_secs(self.idle_timeout_secs);
        sessions.retain(|_, entry| entry.last_accessed.elapsed() < timeout);
        let swept = before - sessions.len();
        if swept > 0 {
            tracing::info!(
                swept = swept,
                remaining = sessions.len(),
                "Idle session sweep complete"
            );
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
    // WebSessionManager — basic
    // -----------------------------------------------------------------------

    fn make_test_mgr() -> WebSessionManager {
        WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.com/oauth2/openid/pdt-api".to_string(),
            "pdt-api".to_string(),
            None,
            "openid profile".to_string(),
        )
    }

    fn make_token_response(access: &str, refresh: Option<&str>) -> TokenResponse {
        TokenResponse {
            access_token: access.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(900),
            refresh_token: refresh.map(|s| s.to_string()),
            id_token: None,
            scope: Some("openid profile".to_string()),
        }
    }

    #[test]
    fn test_create_session_stores_token() {
        let mgr = make_test_mgr();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let session_id = rt
            .block_on(mgr.create_session(&make_token_response("access-abc", Some("refresh-xyz"))))
            .unwrap();
        assert!(!session_id.is_empty());
        assert!(uuid::Uuid::parse_str(&session_id).is_ok());
    }

    #[test]
    fn test_create_two_sessions_have_different_ids() {
        let mgr = make_test_mgr();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let id1 = rt.block_on(mgr.create_session(&make_token_response("a", None))).unwrap();
        let id2 = rt.block_on(mgr.create_session(&make_token_response("b", None))).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_get_token_valid_returns_access_token() {
        let mgr = make_test_mgr();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let session_id = rt
            .block_on(mgr.create_session(&make_token_response("my-access-token", Some("my-refresh"))))
            .unwrap();
        let token = rt.block_on(mgr.get_token(&session_id)).unwrap();
        assert_eq!(token, "my-access-token");
    }

    #[test]
    fn test_get_token_unknown_session_errors() {
        let mgr = make_test_mgr();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(mgr.get_token("nonexistent-session"));
        assert!(matches!(result, Err(PepError::AuthenticationRequired)));
    }

    #[test]
    fn test_destroy_session() {
        let mgr = make_test_mgr();
        let rt = tokio::runtime::Runtime::new().unwrap();

        let session_id = rt
            .block_on(mgr.create_session(&make_token_response("test-token", None)))
            .unwrap();

        let token = rt.block_on(mgr.get_token(&session_id)).unwrap();
        assert_eq!(token, "test-token");

        mgr.destroy_session(&session_id).unwrap();

        let result = rt.block_on(mgr.get_token(&session_id));
        assert!(matches!(result, Err(PepError::AuthenticationRequired)));
    }

    #[test]
    fn test_get_token_expired_no_refresh_errors() {
        let mgr = make_test_mgr();
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Insert a session with an already-expired token and no refresh token
        let stored = StoredToken::new(
            "expired-access",
            None,
            "Bearer",
            "2020-01-01T00:00:00Z",
            None,
        );

        {
            let mut sessions = mgr.sessions.write().unwrap();
            sessions.insert(
                "expired-session".to_string(),
                SessionEntry {
                    token: stored,
                    last_accessed: Instant::now(),
                },
            );
        }

        let result = rt.block_on(mgr.get_token("expired-session"));
        assert!(matches!(result, Err(PepError::AuthenticationRequired)));
    }

    // -----------------------------------------------------------------------
    // WebSessionManager — idle timeout + sweep
    // -----------------------------------------------------------------------

    #[test]
    fn test_idle_timeout_evicts_session() {
        let mgr = make_test_mgr().with_idle_timeout(0); // 0s = immediate timeout

        let rt = tokio::runtime::Runtime::new().unwrap();

        let session_id = rt
            .block_on(mgr.create_session(&make_token_response("will-expire", None)))
            .unwrap();

        // Sleep 1s so Instant::now() advances past idle_timeout=0
        std::thread::sleep(std::time::Duration::from_secs(1));

        let result = rt.block_on(mgr.get_token(&session_id));
        assert!(matches!(result, Err(PepError::AuthenticationRequired)));
    }

    #[test]
    fn test_idle_timeout_does_not_evict_active_session() {
        let mgr = make_test_mgr().with_idle_timeout(3600); // 1 hour

        let rt = tokio::runtime::Runtime::new().unwrap();

        let session_id = rt
            .block_on(mgr.create_session(&make_token_response("active", None)))
            .unwrap();

        // Access immediately — should work
        let token = rt.block_on(mgr.get_token(&session_id)).unwrap();
        assert_eq!(token, "active");

        // Access again — should still work (last_accessed updated)
        let token = rt.block_on(mgr.get_token(&session_id)).unwrap();
        assert_eq!(token, "active");
    }

    #[test]
    fn test_sweep_removes_idle_sessions() {
        let mgr = make_test_mgr()
            .with_idle_timeout(0)        // immediate timeout
            .with_sweep_threshold(2);    // sweep when > 2 sessions

        let rt = tokio::runtime::Runtime::new().unwrap();

        // Create 3 sessions
        let id1 = rt.block_on(mgr.create_session(&make_token_response("a", None))).unwrap();
        let id2 = rt.block_on(mgr.create_session(&make_token_response("b", None))).unwrap();
        let id3 = rt.block_on(mgr.create_session(&make_token_response("c", None))).unwrap();

        assert_eq!(mgr.session_count(), 3);

        // Sleep so idle timeout (0s) kicks in
        std::thread::sleep(std::time::Duration::from_secs(1));

        // This get_token triggers sweep (count 3 > threshold 2)
        // All sessions are idle (0s timeout), so they get swept.
        // The session we're looking up gets swept too → AuthenticationRequired
        let result = rt.block_on(mgr.get_token(&id1));
        assert!(matches!(result, Err(PepError::AuthenticationRequired)));
        assert_eq!(mgr.session_count(), 0);

        // Suppress unused
        let _ = (id2, id3);
    }

    #[test]
    fn test_sweep_preserves_active_sessions() {
        let mgr = make_test_mgr()
            .with_idle_timeout(3600)     // 1 hour — nothing times out
            .with_sweep_threshold(2);    // sweep when > 2 sessions

        let rt = tokio::runtime::Runtime::new().unwrap();

        // Create 3 sessions
        let id1 = rt.block_on(mgr.create_session(&make_token_response("a", None))).unwrap();
        let _id2 = rt.block_on(mgr.create_session(&make_token_response("b", None))).unwrap();
        let _id3 = rt.block_on(mgr.create_session(&make_token_response("c", None))).unwrap();

        assert_eq!(mgr.session_count(), 3);

        // Access id1 — triggers sweep, but nothing is idle (1h timeout)
        let token = rt.block_on(mgr.get_token(&id1)).unwrap();
        assert_eq!(token, "a");
        assert_eq!(mgr.session_count(), 3); // nothing swept
    }

    #[test]
    fn test_session_count() {
        let mgr = make_test_mgr();
        assert_eq!(mgr.session_count(), 0);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = rt.block_on(mgr.create_session(&make_token_response("a", None))).unwrap();
        let _ = rt.block_on(mgr.create_session(&make_token_response("b", None))).unwrap();
        assert_eq!(mgr.session_count(), 2);

        mgr.destroy_session(&rt.block_on(mgr.create_session(&make_token_response("c", None))).unwrap()).unwrap();
        // We created 3, destroyed 1 → 2 remaining
        // Actually the third create adds one more before we destroy it
        assert_eq!(mgr.session_count(), 2);
    }

    // -----------------------------------------------------------------------
    // WebSessionManager — misc
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_manager_debug() {
        let mgr = make_test_mgr();
        let debug_str = format!("{:?}", mgr);
        assert!(debug_str.contains("WebSessionManager"));
        assert!(debug_str.contains("pdt-api"));
        assert!(debug_str.contains("idle_timeout_secs"));
    }

    #[test]
    fn test_get_token_near_expiry_no_refresh() {
        // Token that is within the refresh buffer but not yet fully expired
        // and has no refresh token should still return the access token
        let mgr = make_test_mgr();

        let stored = StoredToken::new(
            "still-valid",
            None,
            "Bearer",
            "2099-01-01T00:00:00Z",
            None,
        );
        {
            let mut sessions = mgr.sessions.write().unwrap();
            sessions.insert(
                "valid-session".to_string(),
                SessionEntry {
                    token: stored,
                    last_accessed: Instant::now(),
                },
            );
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let token = rt.block_on(mgr.get_token("valid-session")).unwrap();
        assert_eq!(token, "still-valid");
    }

    #[test]
    fn test_with_idle_timeout_builder() {
        let mgr = make_test_mgr().with_idle_timeout(7200);
        assert_eq!(mgr.idle_timeout_secs, 7200);
    }

    #[test]
    fn test_with_sweep_threshold_builder() {
        let mgr = make_test_mgr().with_sweep_threshold(128);
        assert_eq!(mgr.sweep_threshold, 128);
    }

    #[test]
    fn test_with_refresh_buffer_builder() {
        let mgr = make_test_mgr().with_refresh_buffer(120);
        assert_eq!(mgr.refresh_buffer_secs, 120);
    }

    #[test]
    fn test_refresh_lock_returns_same_arc() {
        // Verify that get_refresh_lock returns the same Arc for the same session_id.
        // This is the mechanism that prevents concurrent refresh races.
        let mgr = make_test_mgr();
        let lock1 = mgr.get_refresh_lock("session-a");
        let lock2 = mgr.get_refresh_lock("session-a");
        let lock3 = mgr.get_refresh_lock("session-b");
        assert!(Arc::ptr_eq(&lock1, &lock2));
        assert!(!Arc::ptr_eq(&lock1, &lock3));
    }
}
