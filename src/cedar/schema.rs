//! Cedar schema loading utilities
//!
//! This module provides functions to load Cedar schemas from `.cedarschema` files.
//! Each service defines its own schema — PEP does **not** hardcode any entity types.
//!
//! # Example
//!
//! ```rust,ignore
//! use pep::cedar::schema::load_schema;
//!
//! let schema = load_schema("policies/schema.cedarschema")?;
//!
//! // Or parse from a string
//! let schema = parse_schema(&schema_str)?;
//! ```

use cedar_policy::Schema;
use std::path::Path;

use super::error::{CedarError, CedarResult};

/// Load a Cedar schema from a `.cedarschema` file on disk.
///
/// Supports both Cedar's native schema syntax and JSON schema format.
pub fn load_schema(path: impl AsRef<Path>) -> CedarResult<Schema> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path).map_err(|e| {
        CedarError::SchemaParse(format!("Failed to read schema file {:?}: {}", path, e))
    })?;

    parse_schema(&content).map_err(|e| {
        CedarError::SchemaParse(format!(
            "Failed to parse schema file {:?}: {}",
            path, e
        ))
    })
}

/// Parse a Cedar schema from a string.
///
/// Accepts both Cedar native syntax and JSON format.
pub fn parse_schema(src: &str) -> CedarResult<Schema> {
    src.parse()
        .map_err(|e| CedarError::SchemaParse(format!("{}", e)))
}

/// Validate that a policy set conforms to a schema.
///
/// Returns `Ok(())` if validation passes with no errors.
/// Returns `Err` with all validation errors if any are found.
pub fn validate_policies(
    schema: &Schema,
    policies: &cedar_policy::PolicySet,
) -> CedarResult<()> {
    let validator = cedar_policy::Validator::new(schema.clone());
    let result = validator.validate(policies, cedar_policy::ValidationMode::default());

    if result.validation_passed() {
        Ok(())
    } else {
        let errors: Vec<String> = result
            .validation_errors()
            .map(|e| format!("{}", e))
            .collect();
        let warnings: Vec<String> = result
            .validation_warnings()
            .map(|w| format!("{}", w))
            .collect();

        let mut msg = String::new();
        if !errors.is_empty() {
            msg.push_str(&format!("Errors:\n{}", errors.join("\n")));
        }
        if !warnings.is_empty() {
            if !msg.is_empty() {
                msg.push_str("\n");
            }
            msg.push_str(&format!("Warnings:\n{}", warnings.join("\n")));
        }

        Err(CedarError::Validation(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_schema() {
        let schema_str = r#"
            entity User = {
                email?: String,
                role?: String,
            };

            entity Document = {
                status: String,
                owner?: String,
            };

            action View, Edit, Delete appliesTo {
                principal: [User],
                resource: [Document],
            };
        "#;
        let schema = parse_schema(schema_str).expect("Schema should parse");
        drop(schema);
    }

    #[test]
    fn test_parse_namespaced_schema() {
        let schema_str = r#"
            namespace MyService {
                entity User = {
                    email?: String,
                };

                entity Resource = {
                    name: String,
                };

                action View appliesTo {
                    principal: [User],
                    resource: [Resource],
                };
            }
        "#;
        let schema = parse_schema(schema_str).expect("Namespaced schema should parse");
        drop(schema);
    }

    #[test]
    fn test_parse_minimal_schema() {
        // Minimal valid schema — just an entity, no actions
        let schema_str = r#"
            entity User;
        "#;
        let schema = parse_schema(schema_str).expect("Minimal schema should parse");
        drop(schema);
    }

    #[test]
    fn test_parse_invalid_schema_fails() {
        let result = parse_schema("this is not a valid schema!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_policies_against_schema() {
        let schema_str = r#"
            entity User = {
                role?: String,
            };
            entity Doc = {};
            action View appliesTo {
                principal: [User],
                resource: [Doc],
            };
        "#;
        let schema = parse_schema(schema_str).unwrap();

        let policy_str = r#"
            permit(
                principal == User::"alice",
                action == Action::"View",
                resource == Doc::"doc1"
            );
        "#;
        let policies: cedar_policy::PolicySet = policy_str.parse().unwrap();

        // Should validate successfully
        assert!(validate_policies(&schema, &policies).is_ok());
    }

    #[test]
    fn test_load_nonexistent_schema_fails() {
        let result = load_schema("/nonexistent/path/schema.cedarschema");
        assert!(result.is_err());
    }
}
