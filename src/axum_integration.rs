//! Axum integration for PEP authentication
//!
//! This module provides utilities for integrating PEP with the Axum web framework:
//! - Bearer token extraction from request headers
//! - `FromRequestParts` extractor for `JwtClaims`
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{routing::get, Router};
//! use pep::axum::{JwtClaimsExtractor, extract_bearer_token};
//!
//! async fn protected_handler(claims: JwtClaimsExtractor) -> String {
//!     format!("Hello, {}!", claims.sub)
//! }
//!
//! let app = Router::new()
//!     .route("/protected", get(protected_handler));
//! ```

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode, HeaderMap},
};
use std::ops::Deref;

use crate::oidc::types::JwtClaims;

/// Extract Bearer token from Authorization header
///
/// # Example
///
/// ```rust,ignore
/// use axum::http::HeaderMap;
/// use pep::axum::extract_bearer_token;
///
/// let mut headers = HeaderMap::new();
/// headers.insert("Authorization", "Bearer my-token".parse().unwrap());
///
/// let token = extract_bearer_token(&headers);
/// assert_eq!(token, Some("my-token".to_string()));
/// ```
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer ").map(|s| s.to_string()))
}

/// Axum extractor for JWT claims
///
/// This extractor retrieves `JwtClaims` from the request extensions.
/// The claims must be inserted by authentication middleware before this extractor is used.
///
/// # Example
///
/// ```rust,ignore
/// use axum::{routing::get, Router};
/// use pep::axum::JwtClaimsExtractor;
///
/// async fn handler(claims: JwtClaimsExtractor) -> String {
///     format!("User: {}", claims.sub)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct JwtClaimsExtractor(pub JwtClaims);

impl Deref for JwtClaimsExtractor {
    type Target = JwtClaims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<JwtClaims> for JwtClaimsExtractor {
    fn from(claims: JwtClaims) -> Self {
        Self(claims)
    }
}

impl JwtClaimsExtractor {
    /// Get the inner JwtClaims
    pub fn into_inner(self) -> JwtClaims {
        self.0
    }
}

impl<S> FromRequestParts<S> for JwtClaimsExtractor
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<JwtClaimsExtractor>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_extract_bearer_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer my-secret-token".parse().unwrap());
        
        let token = extract_bearer_token(&headers);
        assert_eq!(token, Some("my-secret-token".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_extract_bearer_token_no_space() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearertoken".parse().unwrap());
        
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn test_jwt_claims_extractor_deref() {
        let claims = JwtClaims::default();
        let extractor = JwtClaimsExtractor::from(claims.clone());
        
        assert_eq!(extractor.sub, claims.sub);
    }
}
