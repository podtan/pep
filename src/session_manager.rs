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
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};
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
// SessionStore — pluggable persistence for WebSessionManager
// ---------------------------------------------------------------------------

/// Persisted representation of a session entry.
///
/// `last_accessed_epoch` replaces the in-memory `Instant` with a portable
/// epoch timestamp so entries can round-trip through disk or a database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub token: StoredToken,
    /// Seconds since the Unix epoch when the session was last accessed.
    pub last_accessed_epoch: u64,
}

/// Pluggable backing store for [`WebSessionManager`].
///
/// When set, sessions survive process restarts and are shared across
/// replicas (e.g. multiple instances behind a load balancer, or a blue/green
/// deploy). The default is in-memory only — pass a store via
/// [`WebSessionManager::with_session_store`].
///
/// Implementations must be `Send + Sync`. Methods are synchronous; disk-backed
/// implementations should keep operations small (a single JSON file per
/// session) so they are safe to call under the session manager's locks.
pub trait SessionStore: Send + Sync {
    /// Load a session by its opaque session ID. `Ok(None)` = not found.
    fn load_session(&self, session_id: &str) -> Result<Option<StoredSession>>;

    /// Insert or replace a session.
    fn save_session(&self, session_id: &str, session: &StoredSession) -> Result<()>;

    /// Delete a session. Missing IDs are silently ignored.
    fn delete_session(&self, session_id: &str) -> Result<()>;
}

/// File-backed [`SessionStore`] — one JSON file per session under a directory.
///
/// Suitable for a single host (or replicas sharing a mounted volume).
/// Filenames are the session IDs; callers should treat session IDs as opaque
/// random UUIDs (which `WebSessionManager` generates), so path safety holds.
///
/// Writes are atomic (temp file + rename) to avoid torn files on crash.
#[derive(Debug, Clone)]
pub struct FileSessionStore {
    dir: PathBuf,
}

impl FileSessionStore {
    /// Create a store rooted at `dir`, creating the directory if needed.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path_for(&self, session_id: &str) -> PathBuf {
        // Defensive: reject anything that could escape the directory.
        let safe: String = session_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
            .collect();
        self.dir.join(format!("{}.json", safe))
    }
}

impl SessionStore for FileSessionStore {
    fn load_session(&self, session_id: &str) -> Result<Option<StoredSession>> {
        let path = self.path_for(session_id);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let s = serde_json::from_slice::<StoredSession>(&bytes)
                    .map_err(|e| PepError::Internal(anyhow::anyhow!("corrupt session file {:?}: {}", path, e)))?;
                Ok(Some(s))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PepError::Internal(anyhow::anyhow!("failed to read session file {:?}: {}", path, e))),
        }
    }

    fn save_session(&self, session_id: &str, session: &StoredSession) -> Result<()> {
        let path = self.path_for(session_id);
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(session)
            .map_err(|e| PepError::Internal(anyhow::anyhow!("serialize session: {}", e)))?;
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn delete_session(&self, session_id: &str) -> Result<()> {
        let path = self.path_for(session_id);
        match std::fs::remove_file(&path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PepError::Internal(anyhow::anyhow!("failed to delete session file {:?}: {}", path, e))),
        }
    }
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

/// Current Unix time in seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
    /// Optional durable backing store. When set, sessions are also written
    /// here (and loaded from here on cache miss) so they survive process
    /// restarts and are visible to replicas sharing the same store.
    store: Option<Arc<dyn SessionStore>>,
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
            store: None,
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

    /// Attach a durable [`SessionStore`] backing (e.g. [`FileSessionStore`]).
    ///
    /// When set:
    /// - `create_session` writes through to the store
    /// - `get_token` loads from the store on in-memory cache miss
    /// - `destroy_session` / idle eviction delete from the store
    ///
    /// This makes sessions survive restarts and allows replicas sharing the
    /// store (same volume) to accept each other's session cookies.
    pub fn with_session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Persist a session entry to the backing store (if any). Errors are
    /// logged and ignored — losing persistence must not break auth.
    fn persist(&self, session_id: &str, entry: &SessionEntry) {
        if let Some(ref store) = self.store {
            let stored = StoredSession {
                token: entry.token.clone(),
                last_accessed_epoch: unix_now(),
            };
            if let Err(e) = store.save_session(session_id, &stored) {
                tracing::warn!(session_id = %session_id, error = %e, "session store write failed");
            }
        }
    }

    /// Remove a session from the backing store (if any).
    fn unpersist(&self, session_id: &str) {
        if let Some(ref store) = self.store {
            if let Err(e) = store.delete_session(session_id) {
                tracing::warn!(session_id = %session_id, error = %e, "session store delete failed");
            }
        }
    }

    /// Look up a session, falling back to the durable store on an in-memory
    /// miss (restart or cross-replica). Restores into the in-memory cache.
    fn lookup(&self, session_id: &str) -> Option<SessionEntry> {
        if let Some(entry) = self.sessions.read().unwrap().get(session_id) {
            return Some(entry.clone());
        }
        let store = self.store.as_ref()?;
        let stored = store.load_session(session_id).ok()??;
        let entry = SessionEntry {
            token: stored.token,
            // Best-effort: if the persisted idle timestamp is older than the
            // idle timeout, treat as expired (sweeper will drop it).
            last_accessed: Instant::now(),
        };
        self.sessions
            .write()
            .unwrap()
            .insert(session_id.to_string(), entry.clone());
        Some(entry)
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
            sessions.insert(session_id.clone(), entry.clone());
        }
        self.persist(&session_id, &entry);

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

            // In-memory miss: consult the durable store (restart or
            // cross-replica) and restore into the cache.
            if !sessions.contains_key(session_id) {
                // Drop the write lock before lookup() takes a read lock.
                drop(sessions);
                let restored = self.lookup(session_id).ok_or_else(|| {
                    tracing::debug!(session_id = %session_id, "Session not found");
                    PepError::AuthenticationRequired
                })?;
                let mut sessions = self.sessions.write().unwrap();
                sessions.insert(session_id.to_string(), restored);
                // Fall through with this same guard held.
                let entry = match sessions.get_mut(session_id) {
                    Some(e) => e,
                    None => {
                        tracing::debug!(session_id = %session_id, "Session not found (raced)");
                        return Err(PepError::AuthenticationRequired);
                    }
                };
                entry.last_accessed = Instant::now();
                entry.token.clone()
            } else {
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
                    self.unpersist(session_id);
                    return Err(PepError::AuthenticationRequired);
                }

                // Update access time
                entry.last_accessed = Instant::now();
                entry.token.clone()
            }
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
        self.unpersist(session_id);
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
                    self.persist(session_id, entry);
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
        let expired_ids: Vec<String> = sessions
            .iter()
            .filter(|(_, entry)| entry.last_accessed.elapsed() >= timeout)
            .map(|(id, _)| id.clone())
            .collect();
        sessions.retain(|_, entry| entry.last_accessed.elapsed() < timeout);
        let swept = before - sessions.len();
        if swept > 0 {
            // Also drop swept sessions from the durable store so they do not
            // resurrect after a restart or on another replica.
            for id in &expired_ids {
                self.unpersist(id);
            }
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
    // ── SessionStore persistence tests ──────────────────────────────────

    use crate::session_manager::FileSessionStore;

    fn temp_store_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pep_sess_test_{}", uuid::Uuid::new_v4()));
        d
    }

    fn mgr_with_store(dir: &PathBuf) -> WebSessionManager {
        let store = FileSessionStore::new(dir).unwrap();
        WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.test".to_string(),
            "test-client".to_string(),
            None,
            "openid".to_string(),
        )
        .with_session_store(std::sync::Arc::new(store))
    }

    fn token_response(exp_in: u64) -> TokenResponse {
        TokenResponse {
            access_token: format!("fake-access-{}", uuid::Uuid::new_v4()),
            refresh_token: Some(format!("fake-refresh-{}", uuid::Uuid::new_v4())),
            token_type: "Bearer".to_string(),
            expires_in: Some(exp_in),
            id_token: None,
            scope: Some("openid".to_string()),
        }
    }

    #[tokio::test]
    async fn file_store_roundtrip() {
        let dir = temp_store_dir();
        let store = FileSessionStore::new(&dir).unwrap();
        let sess = StoredSession {
            token: StoredToken::new("at", Some("rt".to_string()), "Bearer", "2099-01-01T00:00:00Z", None),
            last_accessed_epoch: 42,
        };
        store.save_session("abc-123", &sess).unwrap();
        let loaded = store.load_session("abc-123").unwrap().unwrap();
        assert_eq!(loaded.token.access_token, "at");
        assert_eq!(loaded.last_accessed_epoch, 42);
        store.delete_session("abc-123").unwrap();
        assert!(store.load_session("abc-123").unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn session_survives_process_restart() {
        let dir = temp_store_dir();
        let sid = {
            let mgr = mgr_with_store(&dir);
            let sid = mgr.create_session(&token_response(3600)).await.unwrap();
            // sanity: readable in this instance
            mgr.get_token(&sid).await.unwrap();
            sid
        };
        // "Restart": brand-new manager over the same directory, empty memory
        let mgr2 = mgr_with_store(&dir);
        let tok = mgr2.get_token(&sid).await
            .expect("session must survive restart via file store");
        assert!(tok.starts_with("fake-access-"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn session_visible_across_replicas() {
        let dir = temp_store_dir();
        let replica_a = mgr_with_store(&dir);
        let sid = replica_a.create_session(&token_response(3600)).await.unwrap();

        // Replica B (separate memory) must see A's session via the shared store
        let replica_b = mgr_with_store(&dir);
        let tok = replica_b.get_token(&sid).await
            .expect("replica B must resolve A's session through shared store");
        assert!(tok.starts_with("fake-access-"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn destroy_session_removes_persisted_file() {
        let dir = temp_store_dir();
        let mgr = mgr_with_store(&dir);
        let sid = mgr.create_session(&token_response(3600)).await.unwrap();
        assert!(mgr.get_token(&sid).await.is_ok());
        mgr.destroy_session(&sid).unwrap();
        // A fresh manager (restart) must NOT resurrect it
        let mgr2 = mgr_with_store(&dir);
        assert!(mgr2.get_token(&sid).await.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_store_sanitizes_unsafe_ids() {
        let dir = temp_store_dir();
        let store = FileSessionStore::new(&dir).unwrap();
        store.save_session("../../etc/passwd", &StoredSession {
            token: StoredToken::new("at", None, "Bearer", "2099-01-01T00:00:00Z", None),
            last_accessed_epoch: 1,
        }).unwrap();
        // Exactly one file, contained inside the store dir (no traversal).
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
        let name = entries[0].file_name().to_string_lossy().to_string();
        assert!(name.starts_with(".._.._") || !name.contains('/'),
                "file must be sanitized inside the store dir, got {:?}", name);
        // Sanitization is deterministic: the same unsafe id maps to the same
        // sanitized filename, so load still resolves (contained, not escaped).
        let loaded = store.load_session("../../etc/passwd").unwrap();
        assert!(loaded.is_some(), "deterministic sanitization keeps round-trip working");
        // And nothing escaped into /etc
        assert!(!std::path::Path::new("/etc/passwd.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn without_store_stays_in_memory() {
        // Default behavior unchanged: no persistence
        let mgr = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.test".to_string(),
            "test-client".to_string(),
            None,
            "openid".to_string(),
        );
        let sid = mgr.create_session(&token_response(3600)).await.unwrap();
        assert!(mgr.get_token(&sid).await.is_ok());
        // Fresh manager cannot see it
        let mgr2 = WebSessionManager::new(
            OidcClient::new(),
            "https://idm.example.test".to_string(),
            "test-client".to_string(),
            None,
            "openid".to_string(),
        );
        assert!(mgr2.get_token(&sid).await.is_err());
    }

}
