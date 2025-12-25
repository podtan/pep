//! Authorization helpers and middleware for role and scope verification
//!
//! This module provides utilities for implementing role-based access control (RBAC)
//! and scope-based authorization in Axum applications using PEP.
//!
//! # Features
//!
//! - `JwtClaims` extension methods for checking roles and scopes
//! - `RequireRole` middleware layer for RBAC
//! - `RequireScope` middleware layer for scope-based authorization
//! - Composable middleware for complex authorization rules
//!
//! # Example
//!
//! ```ignore
//! use axum::Router;
//! use pep::auth::{RequireRole, RequireScope};
//! use tower::ServiceBuilder;
//!
//! let app = Router::new()
//!     .route("/admin", get(admin_handler))
//!     .layer(ServiceBuilder::new()
//!         .layer(RequireRole::new(vec!["admin".to_string()]))
//!     );
//! ```

pub mod error;
pub mod middleware;
pub mod claims;

pub use error::AuthorizationError;
pub use middleware::{RequireRole, RequireScope};

// Re-export JwtClaims extension methods through the oidc module
pub use crate::oidc::types::JwtClaims;
