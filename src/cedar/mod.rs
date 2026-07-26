//! # Cedar ABAC Module for PEP
//!
//! This module integrates AWS Cedar as a fine-grained, attribute-based access
//! control (ABAC) engine into the PEP library. It provides:
//!
//! - **`CedarAuthorizer`**: Loads Cedar policies and evaluates authorization requests
//! - **`CedarConfig`**: TOML-based configuration for policy paths and settings
//! - **`PolicyStoreClient`**: Fetches policies from a remote HTTP endpoint
//! - **`PolicyStoreResponse`**: Wire format for the policy store API
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
//! # Policy Sources
//!
//! `CedarAuthorizer` supports three policy sources, tried in priority order:
//!
//! 1. **Policy store URL** — fetched from a remote HTTP endpoint (e.g. PDT `/api/cedar/policies`)
//! 2. **Filesystem** — loaded from `policy_path` on disk
//! 3. **Embedded** — compiled into the binary via `include_str!` as a default
//!
//! # Example: Embedded defaults with remote policy store
//!
//! ```rust,ignore
//! use pep::cedar::{CedarAuthorizer, CedarConfig};
//!
//! let config = CedarConfig {
//!     policy_path: "./policies".into(),  // filesystem fallback
//!     embedded_policy: Some(include_str!("../policies/rbac.cedar")),
//!     embedded_schema: Some(include_str!("../policies/schema.cedarschema")),
//!     policy_store_url: Some("http://localhost:8080/api/cedar/policies".into()),
//!     ..Default::default()
//! };
//! let authorizer = CedarAuthorizer::new_with_policy_store(config).await?;
//! ```

pub mod authorizer;
pub mod config;
pub mod entity;
pub mod error;
pub mod policy_store;
pub mod schema;

pub use authorizer::CedarAuthorizer;
pub use config::{CedarConfig, DefaultDecision};
pub use entity::{ResourceInfo, build_principal_uid, build_principal_entity, build_action_uid};
pub use error::CedarError;
pub use policy_store::{PolicyStoreClient, PolicyStoreResponse};
pub use schema::{load_schema, parse_schema, validate_policies};
