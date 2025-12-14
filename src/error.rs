//! Error types for PEP operations

/// PEP-specific error type
#[derive(Debug, thiserror::Error)]
pub enum PepError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("OIDC discovery error: {0}")]
    OidcDiscovery(String),

    #[error("JWKS fetch error: {0}")]
    JwksFetch(String),

    #[error("JWT validation error: {0}")]
    JwtValidation(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, PepError>;

/// HTTP response for errors
#[cfg(feature = "oidc-resource-server")]
impl PepError {
    pub fn status_code(&self) -> http::StatusCode {
        use http::StatusCode;
        match self {
            PepError::BadRequest(_) => StatusCode::BAD_REQUEST,
            PepError::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            PepError::AuthorizationFailed(_) => StatusCode::FORBIDDEN,
            PepError::JwtValidation(_) => StatusCode::UNAUTHORIZED,
            PepError::OidcDiscovery(_) | PepError::JwksFetch(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}