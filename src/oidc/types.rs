//! Common types for OIDC operations

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: Option<String>,
    /// Expiration time
    pub exp: i64,
    /// Issued at time
    pub iat: Option<i64>,
    /// Email address
    pub email: Option<String>,
    /// Full name
    pub name: Option<String>,
    /// Preferred username
    pub preferred_username: Option<String>,
    /// Additional custom claims
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// OIDC discovery document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    /// Issuer identifier
    pub issuer: String,
    /// JWKS URI
    pub jwks_uri: String,
    /// Authorization endpoint
    pub authorization_endpoint: Option<String>,
    /// Token endpoint
    pub token_endpoint: Option<String>,
    /// User info endpoint
    pub userinfo_endpoint: Option<String>,
    /// End session endpoint
    pub end_session_endpoint: Option<String>,
}

/// JWKS cache entry
#[derive(Clone)]
pub struct CachedJwks {
    /// Decoded keys mapped by key ID
    pub keys: HashMap<String, (jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)>,
    /// When the keys were fetched
    pub fetched_at: std::time::SystemTime,
    /// How long to cache the keys
    pub cache_duration: std::time::Duration,
}

/// JWT validation options
#[derive(Debug, Clone, Default)]
pub struct JwtValidationOptions {
    /// Skip issuer validation
    pub skip_issuer_validation: bool,
    /// Skip audience validation
    pub skip_audience_validation: bool,
    /// Expected audience value (if different from client_id)
    pub expected_audience: Option<String>,
}

/// OIDC client configuration
#[derive(Debug, Clone)]
pub struct OidcClientConfig {
    /// OIDC provider issuer URL
    pub issuer_url: String,
    /// Client ID
    pub client_id: String,
    /// Client secret (optional for public clients)
    pub client_secret: Option<String>,
    /// Redirect URI
    pub redirect_uri: String,
    /// OAuth 2.0 scope
    pub scope: String,
    /// Code challenge method
    pub code_challenge_method: String,
}

/// Resource server configuration
#[derive(Debug, Clone)]
pub struct ResourceServerConfig {
    /// OIDC provider issuer URL
    pub issuer_url: String,
    /// Client ID (used as default audience)
    pub client_id: String,
    /// JWT validation options
    pub validation_options: JwtValidationOptions,
}

/// Local development configuration
#[derive(Debug, Clone)]
pub struct DevConfig {
    /// Enable local development mode
    pub local_dev_mode: bool,
    /// Mock email for dev mode
    pub local_dev_email: Option<String>,
    /// Mock name for dev mode
    pub local_dev_name: Option<String>,
    /// Mock username for dev mode
    pub local_dev_username: Option<String>,
}