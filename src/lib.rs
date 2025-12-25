//! # PEP - Policy Enforcement Point
//!
//! A Rust library for OIDC authentication and authorization, providing both
//! client-side authentication flows and resource server protection.
//!
//! ## Features
//!
//! - `oidc-client`: OIDC client functionality for web applications
//! - `oidc-resource-server`: JWT validation middleware for API protection
//! - `oidc`: Enables both client and resource server features
//! - `axum`: Axum web framework integration (extractors, bearer token helpers)
//!
//! ## Example (Resource Server with Axum)
//!
//! ```rust,ignore
//! use pep::axum::{JwtClaimsExtractor, extract_bearer_token};
//! use pep::oidc_resource_server::ResourceServerClient;
//!
//! async fn protected_handler(claims: JwtClaimsExtractor) -> String {
//!     format!("Hello, {}!", claims.sub)
//! }
//! ```
//!
//! ## Example (Development Mode)
//!
//! ```rust
//! use pep::DevConfig;
//!
//! let dev = DevConfig::enabled();
//! let claims = dev.create_dev_claims();
//! assert_eq!(claims.iss, "dev");
//! ```

pub mod error;
pub use error::{PepError, Result};

// Internal oidc module - always available when any oidc feature is enabled
#[cfg(any(feature = "oidc", feature = "oidc-client", feature = "oidc-resource-server"))]
pub mod oidc;

// Axum integration module
#[cfg(feature = "axum")]
pub mod axum_integration;

#[cfg(feature = "axum")]
pub use axum_integration as axum;

// Configuration parsing module
#[cfg(feature = "config")]
pub mod config;

// Re-export config types when feature is enabled
#[cfg(feature = "config")]
pub use config::{PepConfig, OidcConfig, OidcDevConfig, load_config};

// Re-export modules at crate root for convenience
#[cfg(feature = "oidc-client")]
pub mod oidc_client;

#[cfg(feature = "oidc-resource-server")]
pub mod oidc_resource_server;

// Re-export commonly used types at crate root
#[cfg(any(feature = "oidc", feature = "oidc-client", feature = "oidc-resource-server"))]
pub use crate::oidc::types::{JwtClaims, OidcDiscoveryDocument, DevConfig};

#[cfg(any(feature = "oidc", feature = "oidc-client"))]
pub use crate::oidc::types::OidcClientConfig;

#[cfg(any(feature = "oidc", feature = "oidc-resource-server"))]
pub use crate::oidc::types::{JwtValidationOptions, ResourceServerConfig, CachedJwks};

// Re-export axum types at crate root when feature is enabled
#[cfg(feature = "axum")]
pub use axum_integration::{JwtClaimsExtractor, extract_bearer_token};

#[cfg(test)]
mod tests {
    use crate::error::PepError;

    #[cfg(feature = "oidc-resource-server")]
    #[test]
    fn test_error_creation() {
        let error = PepError::BadRequest("test error".to_string());
        assert_eq!(error.status_code(), http::StatusCode::BAD_REQUEST);
    }

    #[cfg(feature = "oidc-resource-server")]
    #[tokio::test]
    async fn test_resource_server_creation() {
        let _client = crate::oidc_resource_server::ResourceServerClient::new();
        // Just test that it can be created
        assert!(true);
    }

    #[cfg(feature = "oidc-client")]
    #[test]
    fn test_oidc_client_creation() {
        let _client = crate::oidc_client::OidcClient::new();
        // Just test that it can be created
        assert!(true);
    }

    #[cfg(feature = "oidc-client")]
    #[test]
    fn test_code_verifier_generation() {
        let verifier = crate::oidc_client::OidcClient::generate_code_verifier();
        assert_eq!(verifier.len(), 64);
    }

    #[cfg(feature = "oidc-client")]
    #[test]
    fn test_state_generation() {
        let state1 = crate::oidc_client::OidcClient::generate_state();
        let state2 = crate::oidc_client::OidcClient::generate_state();
        assert_ne!(state1, state2); // Should be unique
        assert_eq!(state1.len(), 36); // UUID v4 length
    }
}