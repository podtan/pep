//! Cedar authorization configuration for PEP
//!
//! This module provides configuration structures for the Cedar ABAC
//! authorization engine, supporting TOML-based configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Cedar authorization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarConfig {
    /// Path to the Cedar policy file (`.cedar` or `.txt`)
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
        };
        assert_eq!(config.default_decision, DefaultDecision::Allow);
        assert!(!config.validate_on_load);
    }
}
