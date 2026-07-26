//! Policy store client for fetching Cedar policies from a remote HTTP endpoint.
//!
//! This enables centralized policy management: a "policy server" (e.g. PDT)
//! serves policies, and services (PDT, NGHR, Torpi) fetch them at startup
//! and on reload.
//!
//! # Wire format
//!
//! The policy store endpoint must return JSON matching [`PolicyStoreResponse`]:
//!
//! ```json
//! {
//!   "policy": "permit(principal, action == Action::\"View\", resource);",
//!   "schema": "entity User = { ... }; action View appliesTo { ... };",
//!   "version": "2024-01-15T10:30:00Z"
//! }
//! ```

use serde::{Deserialize, Serialize};

use super::error::{CedarError, CedarResult};

/// Response from a policy store HTTP endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStoreResponse {
    /// Cedar policy text (one or more `permit`/`forbid` statements).
    #[serde(default)]
    pub policy: String,

    /// Cedar schema text (entity and action declarations).
    #[serde(default)]
    pub schema: String,

    /// Optional version identifier (timestamp, git SHA, etc.) for change detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Client for fetching Cedar policies from a remote HTTP endpoint.
#[derive(Debug, Clone)]
pub struct PolicyStoreClient {
    http: reqwest::Client,
    url: String,
    token: Option<String>,
}

impl PolicyStoreClient {
    /// Create a new policy store client.
    ///
    /// - `url`: Full URL of the policy store endpoint (e.g. `http://localhost:8080/api/cedar/policies`)
    /// - `token`: Optional Bearer token for authentication to the endpoint.
    pub fn new(url: impl Into<String>, token: Option<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            url: url.into(),
            token,
        }
    }

    /// Fetch policies from the remote endpoint.
    ///
    /// Returns an error if the endpoint is unreachable or returns invalid JSON.
    pub async fn fetch(&self) -> CedarResult<PolicyStoreResponse> {
        let mut req = self.http.get(&self.url);
        if let Some(ref token) = self.token {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| CedarError::Config(format!("Policy store fetch failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(CedarError::Config(format!(
                "Policy store returned HTTP {}",
                resp.status()
            )));
        }

        resp.json::<PolicyStoreResponse>()
            .await
            .map_err(|e| CedarError::Config(format!("Policy store JSON parse failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_store_response_deserialize() {
        let json = r#"{
            "policy": "permit(principal, action, resource);",
            "schema": "entity User;",
            "version": "v1"
        }"#;
        let resp: PolicyStoreResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.policy, "permit(principal, action, resource);");
        assert_eq!(resp.schema, "entity User;");
        assert_eq!(resp.version, Some("v1".to_string()));
    }

    #[test]
    fn test_policy_store_response_defaults() {
        let json = r#"{}"#;
        let resp: PolicyStoreResponse = serde_json::from_str(json).unwrap();
        assert!(resp.policy.is_empty());
        assert!(resp.schema.is_empty());
        assert!(resp.version.is_none());
    }
}
