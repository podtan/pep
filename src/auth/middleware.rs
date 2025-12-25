use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use tower::Layer;
use tower::Service;

use crate::oidc::types::JwtClaims;
use super::error::AuthorizationError;

/// Middleware layer that requires one of the specified roles
#[derive(Clone)]
pub struct RequireRole {
    required_roles: Arc<Vec<String>>,
}

impl RequireRole {
    /// Create a new RequireRole middleware requiring at least one of the specified roles
    pub fn new(required_roles: Vec<String>) -> Self {
        Self {
            required_roles: Arc::new(required_roles),
        }
    }
}

impl<S> Layer<S> for RequireRole {
    type Service = RequireRoleMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireRoleMiddleware {
            inner,
            required_roles: self.required_roles.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RequireRoleMiddleware<S> {
    inner: S,
    required_roles: Arc<Vec<String>>,
}

impl<S> Service<Request> for RequireRoleMiddleware<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = inner;
        let required_roles = self.required_roles.clone();

        Box::pin(async move {
            // Extract JwtClaims from request extensions
            if let Some(claims) = request.extensions().get::<JwtClaims>() {
                // Check if user has any of the required roles
                let has_required_role = required_roles.iter().any(|role| claims.has_role(role));

                if !has_required_role {
                    return Ok(AuthorizationError::InsufficientRole(
                        required_roles.iter().map(|s| s.to_string()).collect(),
                    )
                    .into_response());
                }
            } else {
                // No claims in extensions - authorization failed
                return Ok(AuthorizationError::MissingToken.into_response());
            }

            inner.call(request).await
        })
    }
}

/// Middleware layer that requires all of the specified scopes
#[derive(Clone)]
pub struct RequireScope {
    required_scopes: Arc<Vec<String>>,
}

impl RequireScope {
    /// Create a new RequireScope middleware requiring all of the specified scopes
    pub fn new(required_scopes: Vec<String>) -> Self {
        Self {
            required_scopes: Arc::new(required_scopes),
        }
    }
}

impl<S> Layer<S> for RequireScope {
    type Service = RequireScopeMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireScopeMiddleware {
            inner,
            required_scopes: self.required_scopes.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RequireScopeMiddleware<S> {
    inner: S,
    required_scopes: Arc<Vec<String>>,
}

impl<S> Service<Request> for RequireScopeMiddleware<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = inner;
        let required_scopes = self.required_scopes.clone();

        Box::pin(async move {
            // Extract JwtClaims from request extensions
            if let Some(claims) = request.extensions().get::<JwtClaims>() {
                // Check if user has all required scopes
                let has_all_scopes =
                    required_scopes.iter().all(|scope| claims.has_scope(scope));

                if !has_all_scopes {
                    return Ok(AuthorizationError::InsufficientScope(
                        required_scopes.iter().map(|s| s.to_string()).collect(),
                    )
                    .into_response());
                }
            } else {
                // No claims in extensions - authorization failed
                return Ok(AuthorizationError::MissingToken.into_response());
            }

            inner.call(request).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::collections::HashMap;

    fn create_test_claims_with_roles(roles: Vec<&str>) -> JwtClaims {
        let mut extra = HashMap::new();
        extra.insert(
            "roles".to_string(),
            serde_json::Value::Array(
                roles
                    .iter()
                    .map(|r| serde_json::Value::String(r.to_string()))
                    .collect(),
            ),
        );

        JwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: None,
            exp: 9999999999,
            iat: None,
            email: None,
            name: None,
            preferred_username: None,
            extra,
        }
    }

    fn create_test_claims_with_scopes(scope_str: &str) -> JwtClaims {
        let mut extra = HashMap::new();
        extra.insert(
            "scope".to_string(),
            serde_json::Value::String(scope_str.to_string()),
        );

        JwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: None,
            exp: 9999999999,
            iat: None,
            email: None,
            name: None,
            preferred_username: None,
            extra,
        }
    }

    #[tokio::test]
    async fn test_require_role_has_required_role() {
        let claims = create_test_claims_with_roles(vec!["admin", "user"]);

        let middleware = RequireRole::new(vec!["admin".to_string()]);
        let mut request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(claims);

        // Create a simple echo service
        let echo_service = tower::service_fn(|_req: Request| async {
            Ok::<Response, Box<dyn std::error::Error + Send + Sync>>(
                "OK".into_response(),
            )
        });

        let mut service = tower::ServiceBuilder::new()
            .layer(middleware)
            .service(echo_service);

        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_require_role_missing_required_role() {
        let claims = create_test_claims_with_roles(vec!["user"]);

        let middleware = RequireRole::new(vec!["admin".to_string(), "moderator".to_string()]);
        let mut request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(claims);

        // Create a simple echo service
        let echo_service = tower::service_fn(|_req: Request| async {
            Ok::<Response, Box<dyn std::error::Error + Send + Sync>>(
                "OK".into_response(),
            )
        });

        let mut service = tower::ServiceBuilder::new()
            .layer(middleware)
            .service(echo_service);

        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_require_role_no_claims() {
        let middleware = RequireRole::new(vec!["admin".to_string()]);
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        // Create a simple echo service
        let echo_service = tower::service_fn(|_req: Request| async {
            Ok::<Response, Box<dyn std::error::Error + Send + Sync>>(
                "OK".into_response(),
            )
        });

        let mut service = tower::ServiceBuilder::new()
            .layer(middleware)
            .service(echo_service);

        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_require_scope_has_all_scopes() {
        let claims = create_test_claims_with_scopes("read write delete");

        let middleware = RequireScope::new(vec!["read".to_string(), "write".to_string()]);
        let mut request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(claims);

        // Create a simple echo service
        let echo_service = tower::service_fn(|_req: Request| async {
            Ok::<Response, Box<dyn std::error::Error + Send + Sync>>(
                "OK".into_response(),
            )
        });

        let mut service = tower::ServiceBuilder::new()
            .layer(middleware)
            .service(echo_service);

        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_require_scope_missing_scope() {
        let claims = create_test_claims_with_scopes("read");

        let middleware = RequireScope::new(vec!["read".to_string(), "write".to_string()]);
        let mut request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(claims);

        // Create a simple echo service
        let echo_service = tower::service_fn(|_req: Request| async {
            Ok::<Response, Box<dyn std::error::Error + Send + Sync>>(
                "OK".into_response(),
            )
        });

        let mut service = tower::ServiceBuilder::new()
            .layer(middleware)
            .service(echo_service);

        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_require_scope_no_claims() {
        let middleware = RequireScope::new(vec!["read".to_string()]);
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        // Create a simple echo service
        let echo_service = tower::service_fn(|_req: Request| async {
            Ok::<Response, Box<dyn std::error::Error + Send + Sync>>(
                "OK".into_response(),
            )
        });

        let mut service = tower::ServiceBuilder::new()
            .layer(middleware)
            .service(echo_service);

        let response = service.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
