//! PDT-backed roles resolver — drop the groups-claim dependency.
//!
//! Task 4c57b9c5 (workstream ffe7f9cc, IdP decouple). Kanidm 1.11.0's
//! service-account claim projection is broken upstream (nghr 6c8efe55:
//! `groups`/`role` arrive null at emission despite matching scopes), so no
//! authorization decision may depend on a token `groups` claim anymore.
//! Roles are PDT *data*, keyed by the token's stable `sub` (spec of record
//! PDT 2fea489c; binding consumer contract on the beb8041d thread):
//!
//! - **One query, sub-keyed**: `GET {base}/api/roles/{sub}` returns both
//!   role families (workspace membership + user global role) in a single
//!   answer — TTL-cache-friendly.
//! - **Roles are OPAQUE STRINGS**: this resolver never inspects, validates,
//!   or enumerates role content. Vocabulary changes on the PDT side cannot
//!   break the crate.
//! - **Empty ≠ unreachable**: a known *or* unknown sub with zero roles
//!   answers `200` with least-privilege defaults (empty membership, no
//!   global role) — that is an authoritative "authorize nothing", NOT an
//!   error. Only transport failure / timeout / 5xx is
//!   [`PdtRolesError::Unreachable`] — the consumer MUST deny (fail closed)
//!   on that arm, never fail open.
//! - **TTL-honest**: the answer carries no time-of-check data; freshness
//!   is this crate's short-TTL cache (default 30s), keyed by `sub` so the
//!   whole answer caches atomically.
//!
//! The input is the validated token's `sub` string alone. Nothing in this
//! module reads a `groups` claim — the contract is "a service-account token
//! with NO groups claim authorizes correctly from PDT roles alone"
//! (pinned by `tests/pdt_roles.rs`).
//!
//! ```no_run
//! # async fn demo() -> Result<(), pep::PepError> {
//! use pep::roles::{PdtRolesClient, PdtRolesError};
//!
//! let pdt = PdtRolesClient::new("http://pdt.internal:8080");
//!
//! // `sub` comes from the VALIDATED JWT (pep validated it against the
//! // configured issuer — pluggable IdP, not hard-wired to tanbal's).
//! # let sub = "8f0b…";
//! match pdt.resolve_roles(sub).await {
//!     Ok(roles) => {
//!         // Feed `roles` to your policy layer (Cedar attrs, role gates…).
//!         // Empty membership / no global role = least privilege: deny-all.
//!     }
//!     Err(e) if e.is_unreachable() => {
//!         // PDT down / timeout / 5xx → DENY. Never fail open.
//!     }
//!     Err(_) => {
//!         // Malformed sub (never validated) → DENY.
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing;

// ---------------------------------------------------------------------------
// Answers (opaque strings throughout)
// ---------------------------------------------------------------------------

/// A workspace-membership row from PDT. `role` is an **opaque string** —
/// the resolver never inspects its content (rider point: opaque roles).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct WorkspaceMembership {
    pub workspace_id: String,
    pub role: String,
}

/// The full PDT roles answer for one `sub`: global role (if any) plus
/// workspace memberships. Least-privilege defaults (empty membership, no
/// global role) mean "authorize nothing" — that is data, not an error.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct PdtRoles {
    pub sub: String,
    #[serde(default)]
    pub global_role: Option<String>,
    #[serde(default)]
    pub membership: Vec<WorkspaceMembership>,
}

impl PdtRoles {
    /// Least-privilege empty answer: no global role, no memberships.
    ///
    /// Used when PDT authoritatively answers "this principal has no roles"
    /// (200 with defaults, or a 404 from a non-conforming PDT — journaled).
    pub fn least_privilege(sub: impl Into<String>) -> Self {
        Self { sub: sub.into(), global_role: None, membership: Vec::new() }
    }

    /// True when the answer carries no authority at all (consumer will deny
    /// everything policy-gated). Diagnostics helper — never load-bearing.
    pub fn is_empty_authority(&self) -> bool {
        self.global_role.is_none() && self.membership.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Errors — fail-closed by construction
// ---------------------------------------------------------------------------

/// Resolver failure. Every variant means **DENY**: consumers must treat any
/// `Err` as "no authorization data available" (fail closed), never as
/// "proceed without roles".
#[derive(Debug, Clone)]
pub enum PdtRolesError {
    /// PDT unreachable (transport failure, timeout, 5xx, or any non-200
    /// response). Retryable in principle — but the caller MUST deny while
    /// it lasts. This is the "unreachable" arm of the empty≠unreachable
    /// contract; it is deliberately NOT collapsed into an empty answer.
    Unreachable { detail: String },
    /// The `sub` is not a safe path segment (empty, or contains characters
    /// outside the stable-sub allowlist). The request was never sent.
    InvalidSub { detail: String },
}

impl PdtRolesError {
    /// True for the transport/unreachable arm (deny, may retry later).
    pub fn is_unreachable(&self) -> bool {
        matches!(self, PdtRolesError::Unreachable { .. })
    }
}

impl std::fmt::Display for PdtRolesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PdtRolesError::Unreachable { detail } => write!(f, "PDT roles unreachable (fail closed): {detail}"),
            PdtRolesError::InvalidSub { detail } => write!(f, "invalid sub for PDT roles lookup: {detail}"),
        }
    }
}

impl std::error::Error for PdtRolesError {}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Default cache TTL. Short by contract ("short-TTL cache"); roles change
/// rarely but authority changes must propagate promptly. Callers tune via
/// [`PdtRolesClient::with_ttl`].
pub const DEFAULT_ROLES_TTL: Duration = Duration::from_secs(30);

/// Request timeout. A hung PDT is an unreachable PDT (deny), not a stalled
/// request path.
pub const DEFAULT_ROLES_TIMEOUT: Duration = Duration::from_secs(5);

/// Sub allowlist: PDT stable subs are UUIDs / agent service ids — plain
/// ASCII ids. Anything outside this set never reaches the wire (loud
/// `InvalidSub`, deny) rather than being URL-guessed.
fn sub_is_safe(sub: &str) -> bool {
    !sub.is_empty()
        && sub.len() <= 256
        && sub.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[derive(Clone)]
struct CachedRoles {
    roles: PdtRoles,
    fetched_at: Instant,
}

/// PDT roles resolver with a per-`sub` short-TTL cache.
///
/// Cloneable (shared cache + HTTP pool). One sub-keyed query returns both
/// role families; the whole answer caches atomically per the binding
/// contract.
#[derive(Clone)]
pub struct PdtRolesClient {
    base_url: String,
    http: reqwest::Client,
    ttl: Duration,
    cache: Arc<RwLock<HashMap<String, CachedRoles>>>,
}

impl std::fmt::Debug for PdtRolesClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdtRolesClient")
            .field("base_url", &self.base_url)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl PdtRolesClient {
    /// Resolver for a PDT base URL, e.g. `"http://pdt.internal:8080"`.
    /// Query path: `GET {base}/api/roles/{sub}` (spec 2fea489c).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(DEFAULT_ROLES_TIMEOUT)
                .build()
                .expect("reqwest client with default TLS backend"),
            ttl: DEFAULT_ROLES_TTL,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Override the cache TTL (short-TTL cache contract; 30s default).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Inject a pre-built `reqwest::Client` (shared connection pool).
    pub fn with_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Resolve PDT roles for a validated `sub` — both role families in one
    /// sub-keyed query, served from the TTL cache when fresh.
    ///
    /// - `Ok(roles)` with empty membership + no global role = least
    ///   privilege (authorize nothing). That is an authoritative empty,
    ///   NOT an error.
    /// - `Err(Unreachable)` = PDT down / timeout / 5xx / non-200 → DENY.
    /// - `Err(InvalidSub)` = sub failed the allowlist → DENY.
    pub async fn resolve_roles(&self, sub: &str) -> Result<PdtRoles, PdtRolesError> {
        if !sub_is_safe(sub) {
            return Err(PdtRolesError::InvalidSub {
                detail: format!(
                    "sub must be non-empty ASCII [A-Za-z0-9._-] (len ≤ 256); got len {}",
                    sub.len()
                ),
            });
        }

        // TTL cache: serve when fresh (whole answer cached atomically).
        {
            let cache = self.cache.read().await;
            if let Some(hit) = cache.get(sub) {
                if hit.fetched_at.elapsed() < self.ttl {
                    return Ok(hit.roles.clone());
                }
            }
        }

        let roles = self.fetch(sub).await?;

        // Store (single-writer per key is fine: last fetch wins within TTL).
        {
            let mut cache = self.cache.write().await;
            cache.insert(sub.to_string(), CachedRoles { roles: roles.clone(), fetched_at: Instant::now() });
        }
        Ok(roles)
    }

    /// Drop the cached answer for `sub` (e.g. after an explicit
    /// role-revocation signal). Next resolve does a full fetch.
    pub async fn invalidate(&self, sub: &str) {
        self.cache.write().await.remove(sub);
    }

    async fn fetch(&self, sub: &str) -> Result<PdtRoles, PdtRolesError> {
        let url = format!("{}/api/roles/{}", self.base_url, sub);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| PdtRolesError::Unreachable { detail: format!("transport: {e}") })?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            // Non-conforming / older PDT answering 404 for a known-or-unknown
            // zero-role principal. Authoritative "no roles" shape → least
            // privilege (deny-by-empty), journaled so ops sees the contract
            // drift. NOT Unreachable: retrying cannot change this answer.
            tracing::warn!(
                sub,
                url = %url,
                "pdt_roles: 404 from PDT — treating as least-privilege empty (expected 200-with-defaults per spec 2fea489c)"
            );
            return Ok(PdtRoles::least_privilege(sub));
        }
        if !status.is_success() {
            return Err(PdtRolesError::Unreachable {
                detail: format!("PDT answered HTTP {}", status.as_u16()),
            });
        }

        let roles: PdtRoles = resp.json().await.map_err(|e| PdtRolesError::Unreachable {
            detail: format!("PDT 200 body did not parse as the roles contract: {e}"),
        })?;

        if roles.sub != sub {
            // Contract: the answer is keyed by the requested sub. A mismatch
            // is a misbehaving PDT — refuse to bind another principal's
            // authority (fail closed, loud).
            return Err(PdtRolesError::Unreachable {
                detail: format!(
                    "PDT answer sub mismatch: requested {sub}, answer carries {}",
                    roles.sub
                ),
            });
        }
        Ok(roles)
    }
}

// ---------------------------------------------------------------------------
// Unit tests (wire tests with a mock PDT live in tests/pdt_roles.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn least_privilege_default_is_empty_authority() {
        let roles = PdtRoles::least_privilege("svc-1");
        assert_eq!(roles.sub, "svc-1");
        assert!(roles.global_role.is_none());
        assert!(roles.membership.is_empty());
        assert!(roles.is_empty_authority());
    }

    #[test]
    fn deserialization_applies_least_privilege_defaults() {
        // 200-with-defaults shape: no membership key, null global_role.
        let roles: PdtRoles = serde_json::from_str(r#"{"sub":"svc-1","global_role":null}"#)
            .expect("defaults must deserialize");
        assert!(roles.is_empty_authority());

        // Full shape parses with opaque strings untouched.
        let roles: PdtRoles = serde_json::from_str(
            r#"{"sub":"u1","global_role":"admin","membership":[{"workspace_id":"ws-a","role":"ws_admin"}]}"#,
        )
        .expect("full contract parses");
        assert_eq!(roles.global_role.as_deref(), Some("admin"));
        assert_eq!(roles.membership.len(), 1);
        assert_eq!(roles.membership[0].role, "ws_admin");
    }

    #[test]
    fn sub_allowlist_rejects_path_escape_and_empty() {
        assert!(sub_is_safe("8f0b6c1e-2d3a-4b5c-9e0f-1a2b3c4d5e6f"));
        assert!(sub_is_safe("agent.service_1"));
        assert!(!sub_is_safe(""));
        assert!(!sub_is_safe("../etc/passwd"));
        assert!(!sub_is_safe("a b"));
        assert!(!sub_is_safe("a/b"));
        assert!(!sub_is_safe("a%2Fb"));
    }

    #[test]
    fn error_classifiers() {
        let e = PdtRolesError::Unreachable { detail: "x".into() };
        assert!(e.is_unreachable());
        let e = PdtRolesError::InvalidSub { detail: "x".into() };
        assert!(!e.is_unreachable());
    }
}
