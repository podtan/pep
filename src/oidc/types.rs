//! Common types for OIDC operations

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

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

impl Default for JwtClaims {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            sub: "anonymous".to_string(),
            iss: "unknown".to_string(),
            aud: None,
            exp: now + 3600, // 1 hour from now
            iat: Some(now),
            email: None,
            name: None,
            preferred_username: None,
            extra: HashMap::new(),
        }
    }
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
#[derive(Debug, Clone, Default)]
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

impl DevConfig {
    /// Create a new DevConfig with dev mode enabled
    pub fn enabled() -> Self {
        Self {
            local_dev_mode: true,
            local_dev_email: Some("dev@localhost".to_string()),
            local_dev_name: Some("Dev User".to_string()),
            local_dev_username: Some("dev".to_string()),
        }
    }

    /// Create mock JWT claims for development mode
    ///
    /// # Example
    ///
    /// ```rust
    /// use pep::oidc::types::DevConfig;
    ///
    /// let dev_config = DevConfig {
    ///     local_dev_mode: true,
    ///     local_dev_email: Some("test@example.com".to_string()),
    ///     local_dev_name: Some("Test User".to_string()),
    ///     local_dev_username: Some("testuser".to_string()),
    /// };
    ///
    /// let claims = dev_config.create_dev_claims();
    /// assert_eq!(claims.email, Some("test@example.com".to_string()));
    /// assert_eq!(claims.name, Some("Test User".to_string()));
    /// ```
    pub fn create_dev_claims(&self) -> JwtClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        JwtClaims {
            sub: self.local_dev_username.clone().unwrap_or_else(|| "dev-user".to_string()),
            iss: "dev".to_string(),
            aud: Some("development".to_string()),
            exp: now + 86400, // 24 hours
            iat: Some(now),
            email: self.local_dev_email.clone(),
            name: self.local_dev_name.clone(),
            preferred_username: self.local_dev_username.clone(),
            extra: HashMap::new(),
        }
    }

    /// Check if dev mode is enabled
    pub fn is_enabled(&self) -> bool {
        self.local_dev_mode
    }
}