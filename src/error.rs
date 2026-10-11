//! Error types for PEP operations

/// PEP-specific error type
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

    #[error("Token refresh failed: {status} {detail}")]
    TokenRefreshFailed { status: u16, detail: String },

    #[error("Userinfo endpoint error: {0}")]
    Userinfo(String),

    /// Authorization-critical upstream failure: the token itself validated,
    /// but the claims needed for an authorization decision (groups/role via
    /// the userinfo endpoint) could NOT be obtained.
    ///
    /// This is deliberately distinguishable from "userinfo returned no
    /// groups": enforcement layers MUST fail closed on it — map `retryable`
    /// failures to a retryable 503-class degraded response, and non-retryable
    /// failures to deny. Silently proceeding with empty claims produced the
    /// lying-empty incident class (F1/F3/365be03f, October 2026).
    #[error("auth degraded (retryable={retryable}): {detail}")]
    AuthDegraded {
        detail: String,
        retryable: bool,
    },

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl PepError {
    /// True when this error means an authorization dependency failed and the
    /// request must not proceed with empty claims (fail-closed signal).
    pub fn is_auth_degraded(&self) -> bool {
        matches!(self, PepError::AuthDegraded { .. })
    }

    /// For auth-degraded failures: whether a retry may succeed (transient
    /// upstream problem → 503-class) or the failure is terminal for this
    /// token (e.g. userinfo rejected the token → deny).
    pub fn retryable(&self) -> bool {
        match self {
            PepError::AuthDegraded { retryable, .. } => *retryable,
            _ => false,
        }
    }
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
            PepError::OidcDiscovery(_) | PepError::JwksFetch(_) | PepError::Userinfo(_) => StatusCode::BAD_GATEWAY,
            PepError::AuthDegraded { retryable, .. } => {
                if *retryable {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}