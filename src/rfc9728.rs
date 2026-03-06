//! RFC 9728: OAuth 2.0 Protected Resource Metadata
//!
//! This module implements RFC 9728, allowing resource servers to publish
//! metadata about their authentication requirements at a well-known endpoint.
//!
//! # Example
//!
//! ```rust,ignore
//! use pep::rfc9728::{ProtectedResourceMetadata, PrmConfig};
//! use axum::Router;
//!
//! let config = PrmConfig {
//!     resource: "https://api.example.com".to_string(),
//!     authorization_servers: vec!["https://idm.example.com".to_string()],
//!     scopes_supported: vec!["openid".to_string(), "profile".to_string()],
//!     ..Default::default()
//! };
//!
//! let app = Router::new()
//!     .route("/.well-known/oauth-protected-resource", axum::routing::get(
//!         pep::rfc9728::prm_handler
//!     ))
//!     .with_state(config);
//! ```

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

/// Protected Resource Metadata (RFC 9728)
///
/// This struct represents the metadata document that a resource server
/// publishes to inform clients about its authentication requirements.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtectedResourceMetadata {
    /// REQUIRED. The protected resource's resource identifier URL.
    pub resource: String,

    /// OPTIONAL. List of OAuth authorization server issuer identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<String>>,

    /// OPTIONAL. URL of the protected resource's JWK Set document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// RECOMMENDED. List of scope values supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// OPTIONAL. List of supported bearer token methods.
    /// Values: "header", "body", "query"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_methods_supported: Option<Vec<String>>,

    /// OPTIONAL. List of JWS signing algorithms supported for signing resource responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Human-readable name of the protected resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_name: Option<String>,

    /// OPTIONAL. URL of documentation for developers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_documentation: Option<String>,

    /// OPTIONAL. URL of policy information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_policy_uri: Option<String>,

    /// OPTIONAL. URL of terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_tos_uri: Option<String>,

    /// OPTIONAL. Boolean indicating support for mutual-TLS client certificate-bound access tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_certificate_bound_access_tokens: Option<bool>,

    /// OPTIONAL. List of authorization details type values supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details_types_supported: Option<Vec<String>>,

    /// OPTIONAL. List of JWS alg values supported for validating DPoP proof JWTs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_signing_alg_values_supported: Option<Vec<String>>,

    /// OPTIONAL. Boolean specifying whether DPoP-bound access tokens are required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_bound_access_tokens_required: Option<bool>,
}

/// Configuration for Protected Resource Metadata
///
/// This is a simpler configuration struct that can be loaded from TOML
/// and converted to `ProtectedResourceMetadata`.
#[derive(Debug, Clone, Deserialize)]
pub struct PrmConfig {
    /// The protected resource's resource identifier URL
    pub resource: String,

    /// List of OAuth authorization server issuer identifiers
    #[serde(default)]
    pub authorization_servers: Vec<String>,

    /// URL of the protected resource's JWK Set document
    #[serde(default)]
    pub jwks_uri: Option<String>,

    /// List of scope values supported
    #[serde(default)]
    pub scopes_supported: Vec<String>,

    /// List of supported bearer token methods
    #[serde(default = "default_bearer_methods")]
    pub bearer_methods_supported: Vec<String>,

    /// List of JWS signing algorithms supported
    #[serde(default)]
    pub resource_signing_alg_values_supported: Vec<String>,

    /// Human-readable name of the protected resource
    #[serde(default)]
    pub resource_name: Option<String>,

    /// URL of documentation for developers
    #[serde(default)]
    pub resource_documentation: Option<String>,

    /// URL of policy information
    #[serde(default)]
    pub resource_policy_uri: Option<String>,

    /// URL of terms of service
    #[serde(default)]
    pub resource_tos_uri: Option<String>,
}

fn default_bearer_methods() -> Vec<String> {
    vec!["header".to_string()]
}

impl Default for PrmConfig {
    fn default() -> Self {
        Self {
            resource: String::new(),
            authorization_servers: Vec::new(),
            jwks_uri: None,
            scopes_supported: Vec::new(),
            bearer_methods_supported: default_bearer_methods(),
            resource_signing_alg_values_supported: Vec::new(),
            resource_name: None,
            resource_documentation: None,
            resource_policy_uri: None,
            resource_tos_uri: None,
        }
    }
}

impl From<PrmConfig> for ProtectedResourceMetadata {
    fn from(config: PrmConfig) -> Self {
        ProtectedResourceMetadata {
            resource: config.resource,
            authorization_servers: if config.authorization_servers.is_empty() {
                None
            } else {
                Some(config.authorization_servers)
            },
            jwks_uri: config.jwks_uri,
            scopes_supported: if config.scopes_supported.is_empty() {
                None
            } else {
                Some(config.scopes_supported)
            },
            bearer_methods_supported: if config.bearer_methods_supported.is_empty() {
                None
            } else {
                Some(config.bearer_methods_supported)
            },
            resource_signing_alg_values_supported: if config.resource_signing_alg_values_supported.is_empty() {
                None
            } else {
                Some(config.resource_signing_alg_values_supported)
            },
            resource_name: config.resource_name,
            resource_documentation: config.resource_documentation,
            resource_policy_uri: config.resource_policy_uri,
            resource_tos_uri: config.resource_tos_uri,
            tls_client_certificate_bound_access_tokens: None,
            authorization_details_types_supported: None,
            dpop_signing_alg_values_supported: None,
            dpop_bound_access_tokens_required: None,
        }
    }
}

/// Axum handler for serving Protected Resource Metadata
///
/// This handler returns the PRM JSON document at the well-known endpoint.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use pep::rfc9728::{PrmConfig, prm_handler};
///
/// let config = PrmConfig {
///     resource: "https://api.example.com".to_string(),
///     authorization_servers: vec!["https://idm.example.com".to_string()],
///     scopes_supported: vec!["openid".to_string()],
///     ..Default::default()
/// };
///
/// let app = Router::new()
///     .route("/.well-known/oauth-protected-resource", axum::routing::get(prm_handler))
///     .with_state(config);
/// ```
pub async fn prm_handler(State(config): State<PrmConfig>) -> Response {
    let metadata: ProtectedResourceMetadata = config.into();
    
    match serde_json::to_string(&metadata) {
        Ok(json) => {
            ([("content-type", "application/json")], json).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to serialize PRM: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Convenience function to create a PRM endpoint route
///
/// Use this with `.route()` and `.with_state()` in your Axum application.
///
/// # Example
///
/// ```rust,ignore
/// use axum::Router;
/// use pep::rfc9728::{PrmConfig, prm_route};
///
/// let config = PrmConfig {
///     resource: "https://api.example.com".to_string(),
///     authorization_servers: vec!["https://idm.example.com".to_string()],
///     ..Default::default()
/// };
///
/// let app = Router::new()
///     .route("/.well-known/oauth-protected-resource", prm_route())
///     .with_state(config);
/// ```
pub fn prm_route() -> axum::routing::MethodRouter<PrmConfig> {
    axum::routing::get(prm_handler)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prm_config_to_metadata() {
        let config = PrmConfig {
            resource: "https://api.example.com".to_string(),
            authorization_servers: vec!["https://idm.example.com".to_string()],
            scopes_supported: vec!["openid".to_string(), "profile".to_string()],
            bearer_methods_supported: vec!["header".to_string()],
            ..Default::default()
        };

        let metadata: ProtectedResourceMetadata = config.into();

        assert_eq!(metadata.resource, "https://api.example.com");
        assert_eq!(
            metadata.authorization_servers,
            Some(vec!["https://idm.example.com".to_string()])
        );
        assert_eq!(
            metadata.scopes_supported,
            Some(vec!["openid".to_string(), "profile".to_string()])
        );
    }

    #[test]
    fn test_metadata_serialization() {
        let metadata = ProtectedResourceMetadata {
            resource: "https://api.example.com".to_string(),
            authorization_servers: Some(vec!["https://idm.example.com".to_string()]),
            scopes_supported: Some(vec!["openid".to_string()]),
            bearer_methods_supported: Some(vec!["header".to_string()]),
            ..Default::default()
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"resource\":\"https://api.example.com\""));
        assert!(json.contains("\"authorization_servers\":[\"https://idm.example.com\"]"));
    }

    #[test]
    fn test_metadata_skip_none_fields() {
        let metadata = ProtectedResourceMetadata {
            resource: "https://api.example.com".to_string(),
            authorization_servers: None,
            jwks_uri: None,
            scopes_supported: None,
            bearer_methods_supported: Some(vec!["header".to_string()]),
            ..Default::default()
        };

        let json = serde_json::to_string(&metadata).unwrap();
        assert!(!json.contains("\"authorization_servers\""));
        assert!(!json.contains("\"jwks_uri\""));
        assert!(json.contains("\"bearer_methods_supported\""));
    }

    #[test]
    fn test_empty_arrays_become_none() {
        let config = PrmConfig {
            resource: "https://api.example.com".to_string(),
            authorization_servers: vec![], // empty
            scopes_supported: vec![],      // empty
            ..Default::default()
        };

        let metadata: ProtectedResourceMetadata = config.into();

        assert_eq!(metadata.authorization_servers, None);
        assert_eq!(metadata.scopes_supported, None);
    }
}
