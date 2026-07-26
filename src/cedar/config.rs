//! Cedar authorization configuration for PEP
//!
//! This module provides configuration structures for the Cedar ABAC
//! authorization engine, supporting TOML-based configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Cedar authorization configuration
///
/// Supports three policy sources, tried in order:
/// 1. **Embedded** — compiled into the binary via `include_str!`, passed as `embedded_policy`
/// 2. **Policy store URL** — fetched from a remote HTTP endpoint (e.g. PDT `/api/cedar/policies`)
/// 3. **Filesystem** — loaded from `policy_path` on disk (traditional)
///
/// Higher-priority sources override lower ones. If no source is available, initialization fails.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarConfig {
    /// Path to the Cedar policy file (`.cedar` or `.txt`)
    ///
    /// Can be a directory — all `.cedar` files within are loaded recursively.
    /// Set to a non-existent path to skip filesystem loading.
    pub policy_path: PathBuf,

    /// Path to the Cedar schema file (`.cedarschema`)
    #[serde(default)]
    pub schema_path: Option<PathBuf>,

    /// Path to the Cedar entities JSON file (optional — entities can be built dynamically)
    #[serde(default)]
    pub entities_path: Option<PathBuf>,

    /// Default decision when no policy matches (default: Deny)
    #[serde(default)]
    pub default_decision: DefaultDecision,

    /// Whether to validate policies against the schema on load
    #[serde(default = "default_true")]
    pub validate_on_load: bool,

    /// URL of a remote policy store endpoint (e.g. `https://pdt.example.com/api/cedar/policies`).
    ///
    /// When set, policies are fetched from this URL at startup (and on reload).
    /// The endpoint must return a `PolicyStoreResponse` JSON body.
    /// Falls back to `embedded_policy` or `policy_path` if the fetch fails.
    #[serde(default, skip_serializing)]
    pub policy_store_url: Option<String>,

    /// Optional Bearer token for authenticating to the policy store endpoint.
    #[serde(default, skip_serializing)]
    pub policy_store_token: Option<String>,

    /// Embedded policy text (compiled into the binary via `include_str!`).
    ///
    /// When set, used as the default if no filesystem or remote source is available.
    #[serde(skip)]
    pub embedded_policy: Option<&'static str>,

    /// Embedded schema text (compiled into the binary via `include_str!`).
    ///
    /// When set, used as the default if `schema_path` is not provided.
    #[serde(skip)]
    pub embedded_schema: Option<&'static str>,
}

/// Default decision when no policy matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultDecision {
    /// Deny access when no policy matches (default, secure-by-default)
    #[default]
    Deny,
    /// Allow access when no policy matches (dangerous — only for development)
    Allow,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_decision_values() {
        assert_eq!(DefaultDecision::Deny, DefaultDecision::default());
        assert_ne!(DefaultDecision::Allow, DefaultDecision::Deny);
    }

    #[test]
    fn test_cedar_config_construction() {
        let config = CedarConfig {
            policy_path: PathBuf::from("/etc/pep/policies.cedar"),
            schema_path: Some(PathBuf::from("/etc/pep/schema.cedarschema")),
            entities_path: None,
            default_decision: DefaultDecision::Deny,
            validate_on_load: true,
            policy_store_url: None,
            policy_store_token: None,
            embedded_policy: None,
            embedded_schema: None,
        };
        assert_eq!(config.policy_path, PathBuf::from("/etc/pep/policies.cedar"));
        assert!(config.schema_path.is_some());
        assert!(config.entities_path.is_none());
        assert_eq!(config.default_decision, DefaultDecision::Deny);
        assert!(config.validate_on_load);
    }

    #[test]
    fn test_cedar_config_allow_default() {
        let config = CedarConfig {
            policy_path: PathBuf::from("policies.cedar"),
            schema_path: None,
            entities_path: None,
            default_decision: DefaultDecision::Allow,
            validate_on_load: false,
            policy_store_url: None,
            policy_store_token: None,
            embedded_policy: None,
            embedded_schema: None,
        };
        assert_eq!(config.default_decision, DefaultDecision::Allow);
        assert!(!config.validate_on_load);
    }
}
