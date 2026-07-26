//! Cedar-based ABAC authorizer for fine-grained access control
//!
//! This module provides the core `CedarAuthorizer` which loads Cedar policies,
//! builds entities from JWT claims and resource information, and evaluates
//! authorization decisions.
//!
//! # Policy Sources
//!
//! `CedarAuthorizer` supports three policy sources, tried in priority order:
//!
//! 1. **Policy store URL** (remote HTTP endpoint) — for centralized management
//! 2. **Filesystem** (file or directory at `policy_path`) — traditional loading
//! 3. **Embedded** (`include_str!` compiled into the binary) — as a fallback default
//!
//! The schema can also come from any of these sources. If an embedded policy is
//! provided but no embedded schema, the schema is loaded from `schema_path` or
//! the policy store response.
//!
//! # Example: Embedded defaults with optional remote override
//!
//! ```rust,ignore
//! use pep::cedar::{CedarAuthorizer, CedarConfig};
//!
//! let config = CedarConfig {
//!     policy_path: "./policies".into(),                    // filesystem fallback
//!     schema_path: Some("./policies/schema.cedarschema".into()),
//!     embedded_policy: Some(include_str!("../policies/rbac.cedar")),
//!     embedded_schema: Some(include_str!("../policies/schema.cedarschema")),
//!     policy_store_url: Some("http://localhost:8080/api/cedar/policies".into()),
//!     ..Default::default()
//! };
//! let authorizer = CedarAuthorizer::new(config)?;
//! ```

use cedar_policy::{Authorizer, Decision, Entities, PolicySet, Request, Response, Schema, Validator, ValidationMode};
use std::path::Path;
use std::str::FromStr;
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
    schema: Option<Arc<Schema>>,
    entities: Arc<Entities>,
}

impl CedarAuthorizer {
    /// Create a new CedarAuthorizer with the given configuration.
    ///
    /// This is a **synchronous** constructor — it tries filesystem and embedded
    /// sources only. Use [`CedarAuthorizer::new_with_policy_store`] for remote
    /// policy store support.
    ///
    /// # Source priority
    /// 1. Filesystem (`policy_path`) — if the file/dir exists
    /// 2. Embedded (`embedded_policy` / `embedded_schema`) — compiled-in fallback
    pub fn new(config: CedarConfig) -> CedarResult<Self> {
        let schema = Self::resolve_schema_sync(&config)?;
        let policies = Self::resolve_policies_sync(&config, schema.as_ref())?;
        let entities = Entities::empty();

        Ok(Self {
            authorizer: Authorizer::new(),
            policies: Arc::new(policies),
            schema: schema.map(Arc::new),
            entities: Arc::new(entities),
        })
    }

    /// Create a new CedarAuthorizer, fetching policies from a remote policy store.
    ///
    /// This is an **async** constructor that tries sources in this order:
    /// 1. Policy store URL (`policy_store_url`) — fetched via HTTP
    /// 2. Filesystem (`policy_path`) — if the file/dir exists
    /// 3. Embedded (`embedded_policy` / `embedded_schema`) — compiled-in fallback
    ///
    /// If the policy store is unreachable, falls back to filesystem or embedded.
    pub async fn new_with_policy_store(config: CedarConfig) -> CedarResult<Self> {
        // Try policy store first
        if let Some(ref url) = config.policy_store_url {
            let client = super::policy_store::PolicyStoreClient::new(
                url.clone(),
                config.policy_store_token.clone(),
            );
            match client.fetch().await {
                Ok(store_resp) => {
                    tracing::info!(
                        "Loaded policies from policy store at {} (version: {:?})",
                        url,
                        store_resp.version
                    );

                    let schema = if !store_resp.schema.is_empty() {
                        Some(schema::parse_schema(&store_resp.schema)?)
                    } else {
                        Self::resolve_schema_sync(&config)?
                    };

                    let policies =
                        Self::parse_policy_str(&store_resp.policy)?;
                    Self::validate_if_enabled(&policies, schema.as_ref(), &config)?;

                    let entities = Entities::empty();
                    return Ok(Self {
                        authorizer: Authorizer::new(),
                        policies: Arc::new(policies),
                        schema: schema.map(Arc::new),
                        entities: Arc::new(entities),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        "Policy store fetch failed, falling back to filesystem/embedded: {}",
                        e
                    );
                }
            }
        }

        // Fall back to sync constructor
        Self::new(config)
    }

    /// Create a new CedarAuthorizer with pre-loaded entities
    pub fn with_entities(config: CedarConfig, entities: Entities) -> CedarResult<Self> {
        let schema = Self::resolve_schema_sync(&config)?;
        let policies = Self::resolve_policies_sync(&config, schema.as_ref())?;

        Ok(Self {
            authorizer: Authorizer::new(),
            policies: Arc::new(policies),
            schema: schema.map(Arc::new),
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
            schema: None,
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

    /// Reload policies from the policy store, or filesystem if no store is configured.
    ///
    /// Validates new policies before swapping. If validation fails, the old
    /// policies remain in effect.
    pub async fn reload_from_store(&mut self, config: &CedarConfig) -> CedarResult<()> {
        if let Some(ref url) = config.policy_store_url {
            let client = super::policy_store::PolicyStoreClient::new(
                url.clone(),
                config.policy_store_token.clone(),
            );
            let store_resp = client.fetch().await?;
            let schema = if !store_resp.schema.is_empty() {
                Some(schema::parse_schema(&store_resp.schema)?)
            } else {
                self.schema.as_ref().map(|s| Schema::clone(s))
            };
            let policies = Self::parse_policy_str(&store_resp.policy)?;
            Self::validate_if_enabled(&policies, schema.as_ref(), config)?;

            self.policies = Arc::new(policies);
            if let Some(s) = schema {
                self.schema = Some(Arc::new(s));
            }
            tracing::info!("Reloaded policies from store (version: {:?})", store_resp.version);
            return Ok(());
        }

        // Fall back to filesystem reload
        self.reload_policies(config)
    }

    /// Reload policies from the configured filesystem source
    pub fn reload_policies(&mut self, config: &CedarConfig) -> CedarResult<()> {
        let schema = Self::resolve_schema_sync(config)?;
        let policies = Self::resolve_policies_sync(config, schema.as_ref())?;
        self.policies = Arc::new(policies);
        if let Some(s) = schema {
            self.schema = Some(Arc::new(s));
        }
        Ok(())
    }

    /// Get a reference to the current policy set
    pub fn policies(&self) -> &PolicySet {
        &self.policies
    }

    /// Get a reference to the current schema (if loaded)
    pub fn schema(&self) -> Option<&Schema> {
        self.schema.as_deref()
    }

    /// Get a reference to the current entities
    pub fn entities(&self) -> &Entities {
        &self.entities
    }

    // ── Internal helpers ────────────────────��──────────────────────────

    /// Resolve schema from embedded string, filesystem, or none.
    fn resolve_schema_sync(config: &CedarConfig) -> CedarResult<Option<Schema>> {
        // Try embedded schema first (compiled-in)
        if let Some(embedded) = config.embedded_schema {
            return Ok(Some(schema::parse_schema(embedded)?));
        }

        // Fall back to filesystem
        if let Some(ref schema_path) = config.schema_path {
            if schema_path.exists() {
                return Ok(Some(schema::load_schema(schema_path)?));
            }
        }

        Ok(None)
    }

    /// Resolve policies from filesystem or embedded string.
    fn resolve_policies_sync(
        config: &CedarConfig,
        schema: Option<&Schema>,
    ) -> CedarResult<PolicySet> {
        // Try filesystem first
        let path = Path::new(&config.policy_path);
        if path.is_dir() || path.exists() {
            let mut policy_set = PolicySet::new();
            if path.is_dir() {
                Self::load_policies_from_dir(&mut policy_set, path)?;
            } else {
                Self::load_policies_from_file(&mut policy_set, path)?;
            }
            Self::validate_if_enabled(&policy_set, schema, config)?;
            return Ok(policy_set);
        }

        // Fall back to embedded policy
        if let Some(embedded) = config.embedded_policy {
            let policies = Self::parse_policy_str(embedded)?;
            Self::validate_if_enabled(&policies, schema, config)?;
            return Ok(policies);
        }

        Err(CedarError::PolicyLoad(format!(
            "No policy source available: path {:?} does not exist and no embedded policy provided",
            config.policy_path
        )))
    }

    /// Parse a policy string into a PolicySet.
    fn parse_policy_str(policy_str: &str) -> CedarResult<PolicySet> {
        policy_str
            .parse()
            .map_err(|e| CedarError::PolicyLoad(format!("Failed to parse policy: {}", e)))
    }

    /// Validate a policy set against a schema if validation is enabled.
    fn validate_if_enabled(
        policies: &PolicySet,
        schema: Option<&Schema>,
        config: &CedarConfig,
    ) -> CedarResult<()> {
        if let (Some(schema), true) = (schema, config.validate_on_load) {
            let validator = Validator::new(schema.clone());
            let validation = validator.validate(policies, ValidationMode::default());
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
        Ok(())
    }

    /// Load policies from a single file.
    fn load_policies_from_file(policy_set: &mut PolicySet, path: &Path) -> CedarResult<()> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            CedarError::PolicyLoad(format!("Failed to read policy file {:?}: {}", path, e))
        })?;
        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        let source = PolicySet::from_str(&content).map_err(|e| {
            CedarError::PolicyLoad(format!("Failed to parse policy file {:?}: {}", path, e))
        })?;
        for policy in source.policies() {
            let new_id = cedar_policy::PolicyId::new(format!(
                "file_{}_{}",
                file_stem,
                policy.id().to_string().trim_start_matches("policy")
            ));
            let text = policy.to_string();
            let reparsed = cedar_policy::Policy::parse(Some(new_id), &text).map_err(|e| {
                CedarError::PolicyLoad(format!("Failed to re-parse policy from {:?}: {}", path, e))
            })?;
            policy_set.add(reparsed).map_err(|e| {
                CedarError::PolicyLoad(format!("Failed to add policy from {:?}: {}", path, e))
            })?;
        }
        Ok(())
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
            } else if path.extension().is_some_and(|ext| ext == "cedar") {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| CedarError::PolicyLoad(format!("Failed to read policy file {:?}: {}", path, e)))?;

                // Parse the entire file as a PolicySet (supports multiple policies per file).
                let file_policy_set: PolicySet = content.parse().map_err(|e| {
                    CedarError::PolicyLoad(format!(
                        "Failed to parse policy file {:?}: {}",
                        path, e
                    ))
                })?;

                for policy in file_policy_set.policies() {
                    let new_id = cedar_policy::PolicyId::new(format!(
                        "file_{}_{}",
                        path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown"),
                        count
                    ));
                    let re_parsed = cedar_policy::Policy::parse(Some(new_id), policy.to_string().as_str())
                        .map_err(|e| CedarError::PolicyLoad(format!(
                            "Failed to re-parse policy {} from {:?}: {}",
                            policy.id(), path, e
                        )))?;
                    policy_set
                        .add(re_parsed)
                        .map_err(|e| CedarError::PolicyLoad(format!("Failed to add policy from {:?}: {}", path, e)))?;
                    count += 1;
                }
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

    #[test]
    fn test_embedded_policy_loading() {
        let policy = r#"
            permit(
                principal,
                action == Action::"View",
                resource
            );
        "#;
        let schema_str = r#"
            entity User;
            entity File;
            action View appliesTo { principal: [User], resource: [File] };
        "#;

        let config = CedarConfig {
            policy_path: "/nonexistent".into(),
            schema_path: None,
            entities_path: None,
            default_decision: super::super::config::DefaultDecision::Deny,
            validate_on_load: true,
            policy_store_url: None,
            policy_store_token: None,
            embedded_policy: Some(policy),
            embedded_schema: Some(schema_str),
        };

        let authorizer = CedarAuthorizer::new(config).unwrap();

        let request = Request::new(
            parse_uid(r#"User::"alice""#),
            parse_uid(r#"Action::"View""#),
            parse_uid(r#"File::"doc1""#),
            Context::empty(),
            None,
        )
        .unwrap();

        assert!(authorizer.is_allowed(&request).allowed());
    }

    #[test]
    fn test_no_policy_source_fails() {
        let config = CedarConfig {
            policy_path: "/nonexistent".into(),
            schema_path: None,
            entities_path: None,
            default_decision: super::super::config::DefaultDecision::Deny,
            validate_on_load: true,
            policy_store_url: None,
            policy_store_token: None,
            embedded_policy: None,
            embedded_schema: None,
        };

        let result = CedarAuthorizer::new(config);
        assert!(result.is_err());
    }
}
