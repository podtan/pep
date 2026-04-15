//! Cedar-based ABAC authorizer for fine-grained access control
//!
//! This module provides the core `CedarAuthorizer` which loads Cedar policies,
//! builds entities from JWT claims and resource information, and evaluates
//! authorization decisions.
//!
//! # Example
//!
//! ```rust,ignore
//! use pep::cedar::{CedarAuthorizer, CedarConfig};
//!
//! let config = CedarConfig::default();
//! let authorizer = CedarAuthorizer::new(config)?;
//!
//! let request = Request::new(
//!     principal_uid,
//!     action_uid,
//!     resource_uid,
//!     Context::empty(),
//!     None,
//! )?;
//!
//! let response = authorizer.is_allowed(&request);
//! assert!(response.allowed());
//! ```

use cedar_policy::{Authorizer, Decision, Entities, PolicySet, Request, Response, Schema, Validator, ValidationMode};
use std::path::Path;
use std::sync::Arc;

use super::config::CedarConfig;
use super::error::{CedarError, CedarResult};
use super::schema;

/// Authorization response wrapping Cedar's native response
#[derive(Debug, Clone)]
pub struct CedarResponse {
    /// Whether the request is allowed
    allowed: bool,
    /// Policy IDs that contributed to the decision
    matched_policies: Vec<String>,
    /// Whether there were evaluation errors
    has_errors: bool,
    /// Error messages if any
    errors: Vec<String>,
}

impl CedarResponse {
    /// Whether the authorization request was allowed
    pub fn allowed(&self) -> bool {
        self.allowed
    }

    /// Policy IDs that contributed to the decision
    pub fn matched_policies(&self) -> &[String] {
        &self.matched_policies
    }

    /// Whether there were evaluation errors
    pub fn has_errors(&self) -> bool {
        self.has_errors
    }

    /// Error messages from evaluation
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

impl From<Response> for CedarResponse {
    fn from(response: Response) -> Self {
        let allowed = response.decision() == Decision::Allow;
        let matched_policies = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();
        let has_errors = !errors.is_empty();

        CedarResponse {
            allowed,
            matched_policies,
            has_errors,
            errors,
        }
    }
}

/// Cedar-based ABAC authorizer
///
/// Loads Cedar policies from files or inline strings and evaluates
/// authorization requests against them.
pub struct CedarAuthorizer {
    authorizer: Authorizer,
    policies: Arc<PolicySet>,
    entities: Arc<Entities>,
}

impl CedarAuthorizer {
    /// Create a new CedarAuthorizer with the given configuration
    ///
    /// Loads policies from the configured policy source and initializes
    /// the Cedar authorizer engine. If `schema_path` is set and
    /// `validate_on_load` is true, policies are validated against the schema.
    pub fn new(config: CedarConfig) -> CedarResult<Self> {
        let schema = Self::load_schema(&config)?;
        let policies = Self::load_policies(&config, schema.as_ref())?;
        let entities = Entities::empty();

        Ok(Self {
            authorizer: Authorizer::new(),
            policies: Arc::new(policies),
            entities: Arc::new(entities),
        })
    }

    /// Create a new CedarAuthorizer with pre-loaded entities
    pub fn with_entities(config: CedarConfig, entities: Entities) -> CedarResult<Self> {
        let schema = Self::load_schema(&config)?;
        let policies = Self::load_policies(&config, schema.as_ref())?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policies: Arc::new(policies),
            entities: Arc::new(entities),
        })
    }

    /// Create a new CedarAuthorizer from a policy string (useful for testing)
    pub fn from_policy_str(policy_str: &str) -> CedarResult<Self> {
        let policies: PolicySet = policy_str
            .parse()
            .map_err(|e| CedarError::PolicyLoad(format!("Failed to parse policy: {}", e)))?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policies: Arc::new(policies),
            entities: Arc::new(Entities::empty()),
        })
    }

    /// Evaluate whether a request is allowed
    ///
    /// Takes a Cedar `Request` and evaluates it against the loaded policies
    /// and entities.
    pub fn is_allowed(&self, request: &Request) -> CedarResponse {
        let response = self
            .authorizer
            .is_authorized(request, &self.policies, &self.entities);
        CedarResponse::from(response)
    }

    /// Evaluate with custom entities (for per-request entity building)
    pub fn is_allowed_with_entities(
        &self,
        request: &Request,
        entities: &Entities,
    ) -> CedarResponse {
        let response = self
            .authorizer
            .is_authorized(request, &self.policies, entities);
        CedarResponse::from(response)
    }

    /// Reload policies from the configured source
    pub fn reload_policies(&mut self, config: &CedarConfig) -> CedarResult<()> {
        let schema = Self::load_schema(config)?;
        let policies = Self::load_policies(config, schema.as_ref())?;
        self.policies = Arc::new(policies);
        Ok(())
    }

    /// Get a reference to the current policy set
    pub fn policies(&self) -> &PolicySet {
        &self.policies
    }

    /// Get a reference to the current entities
    pub fn entities(&self) -> &Entities {
        &self.entities
    }

    /// Load schema from config if schema_path is set
    fn load_schema(config: &CedarConfig) -> CedarResult<Option<Schema>> {
        if let Some(ref schema_path) = config.schema_path {
            let schema = schema::load_schema(schema_path)?;
            Ok(Some(schema))
        } else {
            Ok(None)
        }
    }

    /// Load policies from the configuration, optionally validating against a schema
    fn load_policies(config: &CedarConfig, schema: Option<&Schema>) -> CedarResult<PolicySet> {
        let mut policy_set = PolicySet::new();
        let policy_path = &config.policy_path;
        let path = Path::new(policy_path);

        if path.is_dir() {
            Self::load_policies_from_dir(&mut policy_set, path)?;
        } else if path.exists() {
            let content = std::fs::read_to_string(path).map_err(|e| {
                CedarError::PolicyLoad(format!("Failed to read policy file {:?}: {}", path, e))
            })?;
            let file_stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");
            let policy_id = cedar_policy::PolicyId::new(format!("file_{}", file_stem));
            let policy = cedar_policy::Policy::parse(Some(policy_id), &content).map_err(|e| {
                CedarError::PolicyLoad(format!("Failed to parse policy file {:?}: {}", path, e))
            })?;
            policy_set.add(policy).map_err(|e| {
                CedarError::PolicyLoad(format!("Failed to add policy from {:?}: {}", path, e))
            })?;
        } else {
            return Err(CedarError::PolicyLoad(format!(
                "Policy path does not exist: {:?}",
                path
            )));
        }

        // Validate policies against schema if both are available
        if let (Some(schema), true) = (schema, config.validate_on_load) {
            let validator = Validator::new(schema.clone());
            let validation = validator.validate(&policy_set, ValidationMode::default());
            if !validation.validation_passed() {
                let errors: Vec<String> = validation
                    .validation_errors()
                    .map(|e| e.to_string())
                    .collect();
                return Err(CedarError::Validation(format!(
                    "Policy validation failed:\n{}",
                    errors.join("\n")
                )));
            }
        }

        Ok(policy_set)
    }

    /// Recursively load .cedar policy files from a directory
    fn load_policies_from_dir(policy_set: &mut PolicySet, dir: &Path) -> CedarResult<()> {
        let entries = std::fs::read_dir(dir)
            .map_err(|e| CedarError::PolicyLoad(format!("Failed to read policy directory: {}", e)))?;

        let mut count = 0usize;
        for entry in entries {
            let entry = entry
                .map_err(|e| CedarError::PolicyLoad(format!("Failed to read directory entry: {}", e)))?;
            let path = entry.path();

            if path.is_dir() {
                Self::load_policies_from_dir(policy_set, &path)?;
            } else if path.extension().map_or(false, |ext| ext == "cedar") {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| CedarError::PolicyLoad(format!("Failed to read policy file {:?}: {}", path, e)))?;

                let file_stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");

                let policy_id = cedar_policy::PolicyId::new(format!("file_{}_{}", file_stem, count));
                let policy = cedar_policy::Policy::parse(Some(policy_id), &content)
                    .map_err(|e| {
                        CedarError::PolicyLoad(format!(
                            "Failed to parse policy file {:?}: {}",
                            path, e
                        ))
                    })?;
                policy_set
                    .add(policy)
                    .map_err(|e| CedarError::PolicyLoad(format!("Failed to add policy from {:?}: {}", path, e)))?;
                count += 1;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::{Context, EntityUid};

    fn parse_uid(s: &str) -> EntityUid {
        s.parse().unwrap()
    }

    #[test]
    fn test_basic_permit() {
        let policy = r#"
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource == File::"doc1"
            );
        "#;

        let authorizer = CedarAuthorizer::from_policy_str(policy).unwrap();

        let request = Request::new(
            parse_uid(r#"User::"alice""#),
            parse_uid(r#"Action::"view""#),
            parse_uid(r#"File::"doc1""#),
            Context::empty(),
            None,
        )
        .unwrap();

        let response = authorizer.is_allowed(&request);
        assert!(response.allowed());
    }

    #[test]
    fn test_basic_deny() {
        let policy = r#"
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource == File::"doc1"
            );
        "#;

        let authorizer = CedarAuthorizer::from_policy_str(policy).unwrap();

        let request = Request::new(
            parse_uid(r#"User::"bob""#),
            parse_uid(r#"Action::"view""#),
            parse_uid(r#"File::"doc1""#),
            Context::empty(),
            None,
        )
        .unwrap();

        let response = authorizer.is_allowed(&request);
        assert!(!response.allowed());
    }

    #[test]
    fn test_forbid_overrides_permit() {
        let policy = r#"
            permit(
                principal,
                action == Action::"view",
                resource
            );
            forbid(
                principal == User::"bob",
                action == Action::"view",
                resource
            );
        "#;

        let authorizer = CedarAuthorizer::from_policy_str(policy).unwrap();

        // Alice should be allowed (permit, no forbid)
        let request = Request::new(
            parse_uid(r#"User::"alice""#),
            parse_uid(r#"Action::"view""#),
            parse_uid(r#"File::"doc1""#),
            Context::empty(),
            None,
        )
        .unwrap();
        assert!(authorizer.is_allowed(&request).allowed());

        // Bob should be denied (forbid overrides permit)
        let request = Request::new(
            parse_uid(r#"User::"bob""#),
            parse_uid(r#"Action::"view""#),
            parse_uid(r#"File::"doc1""#),
            Context::empty(),
            None,
        )
        .unwrap();
        assert!(!authorizer.is_allowed(&request).allowed());
    }

    #[test]
    fn test_role_based_policy() {
        let policy = r#"
            permit(
                principal in Group::"Admins",
                action == Action::"delete",
                resource == Project::"*"
            );
        "#;

        let authorizer = CedarAuthorizer::from_policy_str(policy).unwrap();

        let request = Request::new(
            parse_uid(r#"User::"alice""#),
            parse_uid(r#"Action::"delete""#),
            parse_uid(r#"Project::"my-project""#),
            Context::empty(),
            None,
        )
        .unwrap();

        // Without entity hierarchy, "in" won't match
        let response = authorizer.is_allowed(&request);
        assert!(!response.allowed());
    }

    #[test]
    fn test_context_based_policy() {
        let policy = r#"
            permit(
                principal,
                action == Action::"view",
                resource
            ) when {
                context.status == "active"
            };
        "#;

        let authorizer = CedarAuthorizer::from_policy_str(policy).unwrap();

        // With matching context
        let context_json = serde_json::json!({"status": "active"});
        let context = Context::from_json_value(context_json, None).unwrap();
        let request = Request::new(
            parse_uid(r#"User::"alice""#),
            parse_uid(r#"Action::"view""#),
            parse_uid(r#"Task::"task-1""#),
            context,
            None,
        )
        .unwrap();

        let response = authorizer.is_allowed(&request);
        assert!(response.allowed());
    }

    #[test]
    fn test_invalid_policy_fails() {
        let result = CedarAuthorizer::from_policy_str("invalid policy syntax!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_response_properties() {
        let policy = r#"
            permit(
                principal == User::"alice",
                action == Action::"view",
                resource
            );
        "#;

        let authorizer = CedarAuthorizer::from_policy_str(policy).unwrap();

        let request = Request::new(
            parse_uid(r#"User::"alice""#),
            parse_uid(r#"Action::"view""#),
            parse_uid(r#"File::"doc1""#),
            Context::empty(),
            None,
        )
        .unwrap();

        let response = authorizer.is_allowed(&request);
        assert!(response.allowed());
        assert!(!response.has_errors());
    }
}
