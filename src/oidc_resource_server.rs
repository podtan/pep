//! OIDC resource server functionality
//!
//! This module provides JWT validation and resource server protection
//! for APIs that need to validate OIDC-issued tokens.

pub use crate::oidc::resource_server::*;
pub use crate::oidc::types::{JwtClaims, ResourceServerConfig, JwtValidationOptions};