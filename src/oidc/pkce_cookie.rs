//! Stateless PKCE state management using HMAC-signed cookies.
//!
//! Provides a [`PkceCookieManager`] that replaces in-memory state stores for
//! multi-instance deployments. The PKCE state and verifier are encoded into a
//! signed cookie value, eliminating the need for shared server-side state.
//!
//! ## Format
//!
//! The cookie value is four dot-separated base64url segments:
//!
//! ```text
//! base64url(state).base64url(verifier).base64url(expiry_unix).base64url(hmac_sha256)
//! ```
//!
//! The HMAC covers `state.verifier.expiry` (the first three segments joined by `.`).
//!
//! ## Security
//!
//! - **Integrity**: HMAC-SHA256 signature prevents tampering.
//! - **Binding**: The verifier is cryptographically bound to the `state` parameter.
//! - **Expiry**: A Unix timestamp is embedded; expired entries are rejected.
//! - **No confidentiality**: The PKCE verifier is sent in plaintext to the token
//!   endpoint, so encryption is unnecessary. HMAC provides all needed guarantees.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::client::OidcClient;

type HmacSha256 = Hmac<Sha256>;

/// Default TTL for PKCE state (10 minutes).
const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// Stateless PKCE state manager using HMAC-signed cookies.
///
/// Replaces in-memory state stores for multi-instance / load-balanced
/// deployments. Any instance can create the login redirect, and any other
/// instance can handle the callback.
#[derive(Clone)]
pub struct PkceCookieManager {
    /// HMAC-SHA256 signing key (32+ bytes recommended).
    secret: Arc<Vec<u8>>,
    /// Cookie name, e.g. `"torpi_pkce_state"`.
    cookie_name: Arc<String>,
    /// How long a PKCE cookie remains valid.
    ttl: Duration,
}

/// Result of [`PkceCookieManager::create`].
///
/// Set `cookie_value` as an `HttpOnly; SameSite=Lax` cookie with `Max-Age`
/// equal to the manager's TTL.
pub struct PkceSession {
    /// Random OIDC `state` parameter — include in the authorization URL.
    pub state: String,
    /// PKCE code verifier — kept inside the cookie, not sent to the browser
    /// as a separate value.
    pub verifier: String,
    /// Signed, self-contained value for the cookie.
    ///
    /// Format: `base64url(state).base64url(verifier).base64url(expiry).base64url(hmac)`
    pub cookie_value: String,
}

impl PkceCookieManager {
    /// Create a new manager with a custom TTL.
    ///
    /// # Panics
    /// Panics if `secret` is empty.
    pub fn new(secret: &[u8], cookie_name: &str, ttl: Duration) -> Self {
        assert!(!secret.is_empty(), "PKCE cookie secret must not be empty");
        Self {
            secret: Arc::new(secret.to_vec()),
            cookie_name: Arc::new(cookie_name.to_string()),
            ttl,
        }
    }

    /// Create a new manager with the default TTL of 10 minutes.
    ///
    /// # Panics
    /// Panics if `secret` is empty.
    pub fn with_default_ttl(secret: &[u8], cookie_name: &str) -> Self {
        Self::new(secret, cookie_name, DEFAULT_TTL)
    }

    /// Return the configured cookie name.
    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    /// Return the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Generate a fresh PKCE session: random `state`, random `verifier`, and
    /// a signed `cookie_value` that encodes both plus an expiry timestamp.
    ///
    /// The caller should:
    /// 1. Compute `code_challenge = OidcClient::generate_code_challenge(&session.verifier)`.
    /// 2. Redirect to the IdP with `state` and `code_challenge` in the URL.
    /// 3. Set a `Set-Cookie` header with name `cookie_name` and value
    ///    `session.cookie_value` (`HttpOnly; SameSite=Lax; Max-Age=<ttl>`).
    pub fn create(&self) -> PkceSession {
        let state = OidcClient::generate_state();
        let verifier = OidcClient::generate_code_verifier();

        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.ttl.as_secs();

        let cookie_value = self.sign(&state, &verifier, expiry);

        PkceSession {
            state,
            verifier,
            cookie_value,
        }
    }

    /// Validate a cookie value and return the PKCE verifier.
    ///
    /// Returns `None` if:
    /// - The format is invalid (wrong number of segments, bad base64).
    /// - The HMAC signature does not match.
    /// - The expiry timestamp has passed.
    /// - `expected_state` does not match the state embedded in the cookie.
    ///
    /// The caller should clear the cookie after calling this (single-use).
    pub fn verify(&self, cookie_value: &str, expected_state: &str) -> Option<String> {
        let (state, verifier, expiry) = self.verify_internal(cookie_value)?;

        // Check state matches the value returned by the IdP
        if state != expected_state {
            tracing::warn!("PKCE cookie state mismatch: expected {}, got {}", expected_state, state);
            return None;
        }

        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_secs();
        if now >= expiry {
            tracing::debug!("PKCE cookie expired (expiry={}, now={})", expiry, now);
            return None;
        }

        Some(verifier)
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// Sign `state`, `verifier`, and `expiry` into a single cookie value.
    fn sign(&self, state: &str, verifier: &str, expiry: u64) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let state_b64 = b64.encode(state);
        let verifier_b64 = b64.encode(verifier);
        let expiry_b64 = b64.encode(expiry.to_string());

        // The message covered by the HMAC is the first three segments
        // joined by dots.
        let message = format!("{}.{}.{}", state_b64, verifier_b64, expiry_b64);

        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC accepts any key length");
        mac.update(message.as_bytes());
        let mac_bytes = mac.finalize().into_bytes();
        let mac_b64 = b64.encode(mac_bytes);

        format!("{}.{}", message, mac_b64)
    }

    /// Validate signature and return (state, verifier, expiry) without
    /// checking state-match or expiry — those are checked by the caller.
    fn verify_internal(&self, cookie_value: &str) -> Option<(String, String, u64)> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let parts: Vec<&str> = cookie_value.split('.').collect();
        if parts.len() != 4 {
            tracing::debug!("PKCE cookie has {} segments, expected 4", parts.len());
            return None;
        }

        let [state_b64, verifier_b64, expiry_b64, mac_b64] = [parts[0], parts[1], parts[2], parts[3]];

        // Verify HMAC
        let message = format!("{}.{}.{}", state_b64, verifier_b64, expiry_b64);

        let mut mac = HmacSha256::new_from_slice(&self.secret).ok()?;
        mac.update(message.as_bytes());
        let expected_mac = mac.finalize().into_bytes();

        let provided_mac = b64.decode(mac_b64).ok()?;

        if expected_mac.as_slice() != provided_mac.as_slice() {
            tracing::warn!("PKCE cookie HMAC verification failed");
            return None;
        }

        // Decode fields
        let state = String::from_utf8(b64.decode(state_b64).ok()?).ok()?;
        let verifier = String::from_utf8(b64.decode(verifier_b64).ok()?).ok()?;
        let expiry_str = String::from_utf8(b64.decode(expiry_b64).ok()?).ok()?;
        let expiry: u64 = expiry_str.parse().ok()?;

        Some((state, verifier, expiry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-key-at-least-32-bytes!!";

    fn make_manager() -> PkceCookieManager {
        PkceCookieManager::with_default_ttl(TEST_SECRET, "test_pkce")
    }

    #[test]
    fn test_create_and_verify() {
        let mgr = make_manager();
        let session = mgr.create();

        // Should verify successfully
        let verifier = mgr.verify(&session.cookie_value, &session.state);
        assert!(verifier.is_some());
        assert_eq!(verifier.unwrap(), session.verifier);
    }

    #[test]
    fn test_state_mismatch() {
        let mgr = make_manager();
        let session = mgr.create();

        let verifier = mgr.verify(&session.cookie_value, "wrong-state");
        assert!(verifier.is_none());
    }

    #[test]
    fn test_tampered_cookie() {
        let mgr = make_manager();
        let session = mgr.create();

        // Tamper with the cookie value
        let tampered = format!("{}.tampered", &session.cookie_value);
        let verifier = mgr.verify(&tampered, &session.state);
        assert!(verifier.is_none());
    }

    #[test]
    fn test_tampered_state() {
        let mgr = make_manager();
        let session = mgr.create();

        // Tamper with state in the cookie by re-signing with a different secret
        let evil_mgr = PkceCookieManager::with_default_ttl(b"evil-different-secret-key!!!!", "test_pkce");
        let evil_session = evil_mgr.create();

        // Evil cookie should fail verification under the real manager
        let verifier = mgr.verify(&evil_session.cookie_value, &evil_session.state);
        assert!(verifier.is_none());
    }

    #[test]
    fn test_expired() {
        let mgr = PkceCookieManager::new(TEST_SECRET, "test_pkce", Duration::from_secs(0));

        let session = mgr.create();
        // Wait a tiny bit to ensure expiry
        std::thread::sleep(Duration::from_millis(10));

        let verifier = mgr.verify(&session.cookie_value, &session.state);
        assert!(verifier.is_none());
    }

    #[test]
    fn test_malformed_cookie() {
        let mgr = make_manager();

        // Too few segments
        assert!(mgr.verify("abc", "state").is_none());
        // Too many segments
        assert!(mgr.verify("a.b.c.d.e", "state").is_none());
        // Empty
        assert!(mgr.verify("", "state").is_none());
    }

    #[test]
    fn test_different_managers_same_secret() {
        // Two managers with the same secret should be interchangeable
        let mgr1 = PkceCookieManager::with_default_ttl(TEST_SECRET, "test_pkce");
        let mgr2 = PkceCookieManager::with_default_ttl(TEST_SECRET, "test_pkce");

        let session = mgr1.create();
        let verifier = mgr2.verify(&session.cookie_value, &session.state);
        assert!(verifier.is_some());
    }

    #[test]
    fn test_different_managers_different_secret() {
        let mgr1 = PkceCookieManager::with_default_ttl(b"secret-one-aaaaaaaaaaaaaaaaaaaa", "test_pkce");
        let mgr2 = PkceCookieManager::with_default_ttl(b"secret-two-bbbbbbbbbbbbbbbbbbbb", "test_pkce");

        let session = mgr1.create();
        let verifier = mgr2.verify(&session.cookie_value, &session.state);
        assert!(verifier.is_none());
    }

    #[test]
    fn test_cookie_name_accessor() {
        let mgr = PkceCookieManager::with_default_ttl(TEST_SECRET, "my_cookie_name");
        assert_eq!(mgr.cookie_name(), "my_cookie_name");
    }

    #[test]
    fn test_ttl_accessor() {
        let mgr = PkceCookieManager::new(TEST_SECRET, "test_pkce", Duration::from_secs(120));
        assert_eq!(mgr.ttl(), Duration::from_secs(120));
    }

    #[test]
    fn test_unique_sessions() {
        let mgr = make_manager();
        let s1 = mgr.create();
        let s2 = mgr.create();
        assert_ne!(s1.state, s2.state);
        assert_ne!(s1.verifier, s2.verifier);
        assert_ne!(s1.cookie_value, s2.cookie_value);
    }
}
