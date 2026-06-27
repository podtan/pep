//! Token storage for persistent OAuth tokens.
//!
//! Provides a trait-based abstraction for storing, loading, and deleting
//! OAuth tokens (access + refresh) on behalf of interactive token providers.
//!
//! The default implementation [`FileTokenStore`] writes per-credential
//! JSON files to `~/.{agent_name}/tokens/` with strict `0600` permissions.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{PepError, Result};

// ---------------------------------------------------------------------------
// StoredToken
// ---------------------------------------------------------------------------

/// Serializable representation of an OAuth token pair.
///
/// Written to / read from disk by [`TokenStore`] implementations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    /// The access token used for API calls.
    pub access_token: String,
    /// Optional refresh token for obtaining new access tokens.
    pub refresh_token: Option<String>,
    /// Token type (usually `"Bearer"`).
    pub token_type: String,
    /// ISO-8601 (RFC-3339) UTC timestamp when the access token expires.
    pub expires_at: String,
    /// Granted scopes (space-separated).
    pub scope: Option<String>,
}

impl StoredToken {
    /// Create a new `StoredToken` from the given fields.
    pub fn new(
        access_token: impl Into<String>,
        refresh_token: Option<String>,
        token_type: impl Into<String>,
        expires_at: impl Into<String>,
        scope: Option<String>,
    ) -> Self {
        Self {
            access_token: access_token.into(),
            refresh_token,
            token_type: token_type.into(),
            expires_at: expires_at.into(),
            scope,
        }
    }

    /// Returns `true` if the token's `expires_at` is in the past.
    ///
    /// Uses a simple string comparison on RFC-3339 timestamps, which works
    /// correctly for UTC timestamps in the same format (e.g. `2026-06-27T08:30:00Z`).
    pub fn is_expired(&self) -> bool {
        let now = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        };
        // Parse expires_at as RFC-3339 → epoch seconds
        let expires_epoch = parse_rfc3339_to_epoch(&self.expires_at).unwrap_or(0);
        now >= expires_epoch
    }

    /// Whether this token can be refreshed (has a refresh token).
    pub fn can_refresh(&self) -> bool {
        self.refresh_token.is_some()
    }
}

/// Naive RFC-3339 parser that returns epoch seconds.
///
/// Handles the common format `YYYY-MM-DDTHH:MM:SSZ` (and with fractional seconds).
fn parse_rfc3339_to_epoch(ts: &str) -> Option<u64> {
    // Expected format: 2026-06-27T08:30:00Z  or  2026-06-27T08:30:00.123Z
    if ts.len() < 20 {
        return None;
    }
    let year: u32 = ts.get(0..4)?.parse().ok()?;
    let month: u32 = ts.get(5..7)?.parse().ok()?;
    let day: u32 = ts.get(8..10)?.parse().ok()?;
    let hour: u32 = ts.get(11..13)?.parse().ok()?;
    let min: u32 = ts.get(14..16)?.parse().ok()?;
    let sec: u32 = ts.get(17..19)?.parse().ok()?;

    Some(civil_to_epoch(year, month, day, hour, min, sec))
}

/// Public wrapper for [`parse_rfc3339_to_epoch`] for use by other modules.
pub(crate) fn parse_rfc3339_to_epoch_public(ts: &str) -> u64 {
    parse_rfc3339_to_epoch(ts).unwrap_or(0)
}

/// Convert civil (calendar) time to Unix epoch seconds.
///
/// Uses the well-known Howard Hinnant algorithm. Works for any date
/// after 1970-01-01.
fn civil_to_epoch(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> u64 {
    let y = if month <= 2 { year - 1 } else { year } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let doy = ((153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1) as u64;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe as i64 - 719468;
    let total_seconds = days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    if total_seconds < 0 {
        0
    } else {
        total_seconds as u64
    }
}

// ---------------------------------------------------------------------------
// TokenStore trait
// ---------------------------------------------------------------------------

/// Abstraction for persistent OAuth token storage.
///
/// Implementations must be `Send + Sync` so they can be shared across
/// async tasks.
pub trait TokenStore: Send + Sync {
    /// Load a stored token by credential name.
    ///
    /// Returns `Ok(None)` if no token is stored.
    fn load(&self, name: &str) -> Result<Option<StoredToken>>;

    /// Persist a token for the given credential name.
    fn save(&self, name: &str, token: &StoredToken) -> Result<()>;

    /// Delete a stored token.  Missing files are silently ignored.
    fn delete(&self, name: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// FileTokenStore
// ---------------------------------------------------------------------------

/// File-based token store.
///
/// Stores each credential's token as a separate JSON file at:
/// `~/.{agent_name}/tokens/{name}.json`
///
/// - Files are created with `0600` (owner-only) permissions.
/// - The parent directory is created with `0700` permissions.
/// - The agent name is used (not the server name) because multiple servers
///   can share the same credential.
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    base_dir: PathBuf,
}

impl FileTokenStore {
    /// Create a `FileTokenStore` rooted at `~/.{agent_name}/tokens/`.
    ///
    /// Falls back to `~/.trustee/tokens/` if `agent_name` is empty.
    pub fn new(agent_name: &str) -> Self {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());

        let name = if agent_name.is_empty() {
            "trustee"
        } else {
            agent_name
        };

        let base_dir = PathBuf::from(home)
            .join(format!(".{}", name))
            .join("tokens");

        Self { base_dir }
    }

    /// Create a `FileTokenStore` rooted at an explicit directory (for testing).
    pub fn with_base_dir(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Returns the full path for a given credential name.
    fn token_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(format!("{}.json", sanitize_name(name)))
    }

    /// Ensure the base directory exists with secure permissions.
    fn ensure_dir(&self) -> Result<()> {
        if !self.base_dir.exists() {
            std::fs::create_dir_all(&self.base_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&self.base_dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
    }
}

impl TokenStore for FileTokenStore {
    fn load(&self, name: &str) -> Result<Option<StoredToken>> {
        let path = self.token_path(name);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)?;
        let token: StoredToken =
            serde_json::from_str(&data).map_err(PepError::Serialization)?;
        Ok(Some(token))
    }

    fn save(&self, name: &str, token: &StoredToken) -> Result<()> {
        self.ensure_dir()?;
        let path = self.token_path(name);
        let json = serde_json::to_string_pretty(token).map_err(PepError::Serialization)?;
        std::fs::write(&path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::debug!(name = %name, path = %path.display(), "Token saved to file store");
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        let path = self.token_path(name);
        if path.exists() {
            std::fs::remove_file(&path)?;
            tracing::debug!(name = %name, "Token deleted from file store");
        }
        Ok(())
    }
}

/// Sanitize a credential name so it's safe to use as a filename.
///
/// Replaces path separators and other problematic characters with `_`.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "pep-token-store-test-{}",
            uuid::Uuid::new_v4()
        ));
        let store = FileTokenStore::with_base_dir(&tmp);

        let token = StoredToken::new(
            "access123",
            Some("refresh456".to_string()),
            "Bearer",
            "2026-06-27T08:30:00Z",
            Some("openid profile".to_string()),
        );

        store.save("test_cred", &token).unwrap();

        let loaded = store.load("test_cred").unwrap().expect("should exist");
        assert_eq!(loaded.access_token, "access123");
        assert_eq!(loaded.refresh_token.as_deref(), Some("refresh456"));
        assert_eq!(loaded.token_type, "Bearer");
        assert_eq!(loaded.expires_at, "2026-06-27T08:30:00Z");

        // Cleanup
        store.delete("test_cred").unwrap();
        assert!(store.load("test_cred").unwrap().is_none());

        // remove temp dir
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_load_nonexistent() {
        let tmp = std::env::temp_dir().join(format!(
            "pep-token-store-test-{}",
            uuid::Uuid::new_v4()
        ));
        let store = FileTokenStore::with_base_dir(&tmp);
        let result = store.load("does_not_exist").unwrap();
        assert!(result.is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_delete_nonexistent() {
        let tmp = std::env::temp_dir().join(format!(
            "pep-token-store-test-{}",
            uuid::Uuid::new_v4()
        ));
        let store = FileTokenStore::with_base_dir(&tmp);
        // Should not error
        store.delete("ghost").unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_is_expired_future() {
        let token = StoredToken::new(
            "abc",
            None,
            "Bearer",
            "2099-01-01T00:00:00Z",
            None,
        );
        assert!(!token.is_expired());
    }

    #[test]
    fn test_is_expired_past() {
        let token = StoredToken::new(
            "abc",
            None,
            "Bearer",
            "2020-01-01T00:00:00Z",
            None,
        );
        assert!(token.is_expired());
    }

    #[test]
    fn test_can_refresh() {
        let with_refresh = StoredToken::new("a", Some("r".into()), "Bearer", "2099-01-01T00:00:00Z", None);
        let without_refresh = StoredToken::new("a", None, "Bearer", "2099-01-01T00:00:00Z", None);
        assert!(with_refresh.can_refresh());
        assert!(!without_refresh.can_refresh());
    }

    #[test]
    fn test_sanitize_name() {
        assert_eq!(sanitize_name("kanidm_pdt"), "kanidm_pdt");
        assert_eq!(sanitize_name("../etc/passwd"), ".._etc_passwd");
        assert_eq!(sanitize_name("hello world"), "hello_world");
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!(
            "pep-token-store-test-{}",
            uuid::Uuid::new_v4()
        ));
        let store = FileTokenStore::with_base_dir(&tmp);

        let token = StoredToken::new("a", None, "Bearer", "2099-01-01T00:00:00Z", None);
        store.save("perms_test", &token).unwrap();

        let path = store.token_path("perms_test");
        let perms = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(perms & 0o777, 0o600);

        let dir_perms = std::fs::metadata(&tmp).unwrap().permissions().mode();
        assert_eq!(dir_perms & 0o777, 0o700);

        store.delete("perms_test").unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_rfc3339_parser() {
        assert_eq!(parse_rfc3339_to_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_to_epoch("1970-01-01T00:00:01Z"), Some(1));
        assert_eq!(parse_rfc3339_to_epoch("1970-01-02T00:00:00Z"), Some(86400));
        // Invalid input
        assert_eq!(parse_rfc3339_to_epoch("garbage"), None);
    }
}
