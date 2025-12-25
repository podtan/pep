use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Authorization-specific errors for role and scope verification
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    /// No authentication token was provided
    #[error("Missing authentication token")]
    MissingToken,

    /// Token validation failed for the given reason
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// Required role was not found in token claims
    #[error("Insufficient role. Required one of: {}", .0.join(", "))]
    InsufficientRole(Vec<String>),

    /// Required scope(s) were not found in token claims
    #[error("Insufficient scope. Required all of: {}", .0.join(", "))]
    InsufficientScope(Vec<String>),
}

impl IntoResponse for AuthorizationError {
    fn into_response(self) -> Response {
        match self {
            AuthorizationError::MissingToken | AuthorizationError::InvalidToken(_) => {
                (StatusCode::UNAUTHORIZED, self.to_string()).into_response()
            }
            AuthorizationError::InsufficientRole(_) | AuthorizationError::InsufficientScope(_) => {
                (StatusCode::FORBIDDEN, self.to_string()).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_token_error() {
        let err = AuthorizationError::MissingToken;
        assert_eq!(err.to_string(), "Missing authentication token");
    }

    #[test]
    fn test_invalid_token_error() {
        let err = AuthorizationError::InvalidToken("signature mismatch".to_string());
        assert_eq!(err.to_string(), "Invalid token: signature mismatch");
    }

    #[test]
    fn test_insufficient_role_error() {
        let err = AuthorizationError::InsufficientRole(vec!["admin".to_string(), "moderator".to_string()]);
        assert!(err.to_string().contains("Insufficient role"));
        assert!(err.to_string().contains("admin"));
    }

    #[test]
    fn test_insufficient_scope_error() {
        let err = AuthorizationError::InsufficientScope(vec!["read".to_string(), "write".to_string()]);
        assert!(err.to_string().contains("Insufficient scope"));
        assert!(err.to_string().contains("read"));
        assert!(err.to_string().contains("write"));
    }

    #[test]
    fn test_unauthorized_status() {
        let err = AuthorizationError::MissingToken;
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_forbidden_status_role() {
        let err = AuthorizationError::InsufficientRole(vec!["admin".to_string()]);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_forbidden_status_scope() {
        let err = AuthorizationError::InsufficientScope(vec!["read".to_string()]);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
