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
//! - `authorization`: Authorization helpers and middleware for role and scope verification
//! - `config`: Standardized configuration parsing from TOML files
//! - `rfc9728`: RFC 9728 Protected Resource Metadata support
//! - `cedar`: AWS Cedar ABAC policy engine for fine-grained authorization
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
//! ```ignore
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

// Axum integration module - requires both axum and oidc features
#[cfg(all(feature = "axum", any(feature = "oidc", feature = "oidc-client", feature = "oidc-resource-server")))]
pub mod axum_integration;

#[cfg(all(feature = "axum", any(feature = "oidc", feature = "oidc-client", feature = "oidc-resource-server")))]
pub use axum_integration as axum;

// Configuration parsing module
#[cfg(feature = "config")]
pub mod config;

// Re-export config types when feature is enabled
#[cfg(all(feature = "config", feature = "cedar"))]
pub use config::PepConfig; // re-exports CedarConfig via PepConfig::cedar
#[cfg(feature = "config")]
pub use config::{OidcConfig, OidcDevConfig, load_config};

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
pub use crate::oidc::types::{JwtValidationOptions, ResourceServerConfig, CachedJwks, CachedDiscoveryRaw};
#[cfg(any(feature = "oidc", feature = "oidc-resource-server"))]
pub use crate::oidc::resource_server::{CachedUserInfo, UserInfoCache};

// Re-export axum types at crate root when feature is enabled
#[cfg(all(feature = "axum", any(feature = "oidc", feature = "oidc-client", feature = "oidc-resource-server")))]
pub use axum_integration::{JwtClaimsExtractor, extract_bearer_token};

// Authorization helpers and middleware module
#[cfg(feature = "authorization")]
pub mod auth;

// Re-export authorization types when feature is enabled
#[cfg(feature = "authorization")]
pub use auth::{AuthorizationError, RequireRole, RequireScope};

// RFC 9728: Protected Resource Metadata
#[cfg(feature = "rfc9728")]
pub mod rfc9728;

// Re-export RFC 9728 types when feature is enabled
#[cfg(feature = "rfc9728")]
pub use rfc9728::{ProtectedResourceMetadata, PrmConfig, prm_handler, prm_route};

// Cedar ABAC authorization module
#[cfg(feature = "cedar")]
pub mod cedar;

// Re-export cedar types when feature is enabled
#[cfg(feature = "cedar")]
pub use cedar::{CedarAuthorizer, CedarConfig, CedarError, DefaultDecision, PolicyStoreClient, PolicyStoreResponse};

// Token provider module for client-side token lifecycle management
#[cfg(feature = "token-provider")]
pub mod token_provider;

// Token store module for persistent token storage (interactive auth)
#[cfg(feature = "token-provider")]
pub mod token_store;

// OAuth callback server module (interactive auth)
#[cfg(feature = "token-provider")]
pub mod oauth_callback;

// Re-export token provider types
#[cfg(feature = "token-provider")]
pub use token_provider::{
    TokenProvider, TokenProviderEnum,
    StaticTokenProvider, ServiceAccountTokenProvider, ServiceAccountConfig,
    InteractiveConfig, InteractiveTokenProvider,
};

// Re-export token store types
#[cfg(feature = "token-provider")]
pub use token_store::{TokenStore, FileTokenStore, MemoryTokenStore, StoredToken};

// Web session manager module (server-side session token management)
#[cfg(feature = "token-provider")]
pub mod session_manager;

// Re-export session manager types
#[cfg(feature = "token-provider")]
pub use session_manager::{WebSessionManager, InMemoryTokenStore, SessionStore, FileSessionStore, StoredSession};

// Re-export OAuth callback server types
#[cfg(feature = "token-provider")]
pub use oauth_callback::{CallbackServer, AuthorizationCode};

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