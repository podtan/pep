//! # Cedar ABAC Module for PEP
//!
//! This module integrates AWS Cedar as a fine-grained, attribute-based access
//! control (ABAC) engine into the PEP library. It provides:
//!
//! - **`CedarAuthorizer`**: Loads Cedar policies and evaluates authorization requests
//! - **`CedarConfig`**: TOML-based configuration for policy paths and settings
//! - **`SchemaLoader`**: Loads Cedar schemas from `.cedarschema` files
//! - **Entity building**: Converts `JwtClaims` and resource metadata into Cedar entities
//!
//! Cedar sits after PEP's JWT authentication layer:
//!
//! ```text
//! Request → PEP (JWT validation) → Cedar (authorization) → Handler (data)
//!           "Who are you?"          "Can you do this?"        "Here's the data"
//! ```
//!
//! Each service defines its **own** schema in a `.cedarschema` file — PEP does not
//! bake any domain-specific entity types into the library.
//!
//! # Example
//!
//! ```rust,ignore
//! use pep::cedar::{CedarAuthorizer, CedarConfig, ResourceInfo, build_principal_uid, build_action_uid};
//! use pep::oidc::types::JwtClaims;
//! use cedar_policy::{Request, Context};
//!
//! let config = CedarConfig {
//!     policy_path: "./policies".into(),
//!     schema_path: Some("./policies/schema.cedarschema".into()),
//!     ..Default::default()
//! };
//! let authorizer = CedarAuthorizer::new(config)?;
//!
//! let principal = build_principal_uid(&claims)?;
//! let action = build_action_uid("view")?;
//! let resource = ResourceInfo::new("Task", "task-123").to_cedar_uid()?;
//!
//! let request = Request::new(principal, action, resource, Context::empty(), None)?;
//! let response = authorizer.is_allowed(&request);
//! assert!(response.allowed());
//! ```

pub mod authorizer;
pub mod config;
pub mod entity;
pub mod error;
pub mod schema;

pub use authorizer::CedarAuthorizer;
pub use config::CedarConfig;
pub use entity::{ResourceInfo, build_principal_uid, build_principal_entity, build_action_uid};
pub use error::CedarError;
pub use schema::{load_schema, parse_schema, validate_policies};
