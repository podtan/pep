use crate::oidc::types::JwtClaims;
use serde_json::Value;

/// Extension trait for JWT claims role and scope verification
impl JwtClaims {
    /// Check if claims contain a specific role
    pub fn has_role(&self, role: &str) -> bool {
        if let Some(Value::Array(roles)) = self.extra.get("roles") {
            roles.iter().any(|r| {
                if let Value::String(s) = r {
                    s == role
                } else {
                    false
                }
            })
        } else {
            false
        }
    }

    /// Check if claims contain a specific scope
    pub fn has_scope(&self, scope: &str) -> bool {
        if let Some(Value::String(scopes_str)) = self.extra.get("scope") {
            scopes_str.split(' ').any(|s| s == scope)
        } else if let Some(Value::Array(scopes)) = self.extra.get("scopes") {
            scopes.iter().any(|s| {
                if let Value::String(scope_str) = s {
                    scope_str == scope
                } else {
                    false
                }
            })
        } else {
            false
        }
    }

    /// Check if claims contain any of the provided roles
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|&role| self.has_role(role))
    }

    /// Check if claims contain all of the provided roles
    pub fn has_all_roles(&self, roles: &[&str]) -> bool {
        roles.iter().all(|&role| self.has_role(role))
    }

    /// Get all roles from claims (returns empty vec if not present or invalid type)
    pub fn roles(&self) -> Vec<String> {
        if let Some(Value::Array(roles)) = self.extra.get("roles") {
            roles
                .iter()
                .filter_map(|r| {
                    if let Value::String(s) = r {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all scopes from claims (returns empty vec if not present or invalid type)
    pub fn scopes(&self) -> Vec<String> {
        if let Some(Value::String(scopes_str)) = self.extra.get("scope") {
            scopes_str.split(' ').map(|s| s.to_string()).collect()
        } else if let Some(Value::Array(scopes)) = self.extra.get("scopes") {
            scopes
                .iter()
                .filter_map(|s| {
                    if let Value::String(scope_str) = s {
                        Some(scope_str.clone())
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_claims_with_roles(roles: Vec<&str>) -> JwtClaims {
        let mut extra = HashMap::new();
        extra.insert(
            "roles".to_string(),
            Value::Array(roles.iter().map(|r| Value::String(r.to_string())).collect()),
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
        extra.insert("scope".to_string(), Value::String(scope_str.to_string()));

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

    #[test]
    fn test_has_role_with_roles_array() {
        let claims = create_test_claims_with_roles(vec!["admin", "user"]);

        assert!(claims.has_role("admin"));
        assert!(claims.has_role("user"));
        assert!(!claims.has_role("superadmin"));
    }

    #[test]
    fn test_has_role_empty_roles() {
        let claims = JwtClaims::default();
        assert!(!claims.has_role("admin"));
    }

    #[test]
    fn test_has_role_non_array_roles() {
        let mut extra = HashMap::new();
        extra.insert("roles".to_string(), Value::String("admin".to_string()));

        let claims = JwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: None,
            exp: 9999999999,
            iat: None,
            email: None,
            name: None,
            preferred_username: None,
            extra,
        };

        assert!(!claims.has_role("admin"));
    }

    #[test]
    fn test_has_scope_space_separated() {
        let claims = create_test_claims_with_scopes("read write delete");

        assert!(claims.has_scope("read"));
        assert!(claims.has_scope("write"));
        assert!(claims.has_scope("delete"));
        assert!(!claims.has_scope("admin"));
    }

    #[test]
    fn test_has_scope_array() {
        let mut extra = HashMap::new();
        extra.insert(
            "scopes".to_string(),
            Value::Array(vec![
                Value::String("read".to_string()),
                Value::String("write".to_string()),
            ]),
        );

        let claims = JwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: None,
            exp: 9999999999,
            iat: None,
            email: None,
            name: None,
            preferred_username: None,
            extra,
        };

        assert!(claims.has_scope("read"));
        assert!(claims.has_scope("write"));
        assert!(!claims.has_scope("delete"));
    }

    #[test]
    fn test_has_scope_missing() {
        let claims = JwtClaims::default();
        assert!(!claims.has_scope("read"));
    }

    #[test]
    fn test_has_any_role() {
        let claims = create_test_claims_with_roles(vec!["user", "moderator"]);

        assert!(claims.has_any_role(&["admin", "user"]));
        assert!(claims.has_any_role(&["superadmin", "moderator"]));
        assert!(!claims.has_any_role(&["admin", "superadmin"]));
    }

    #[test]
    fn test_has_all_roles() {
        let claims = create_test_claims_with_roles(vec!["user", "moderator", "admin"]);

        assert!(claims.has_all_roles(&["user", "admin"]));
        assert!(!claims.has_all_roles(&["user", "superadmin"]));
    }

    #[test]
    fn test_roles_extraction() {
        let claims = create_test_claims_with_roles(vec!["admin", "user", "viewer"]);

        let roles = claims.roles();
        assert_eq!(roles, vec!["admin", "user", "viewer"]);
    }

    #[test]
    fn test_roles_extraction_empty() {
        let claims = JwtClaims::default();
        let roles = claims.roles();
        assert_eq!(roles, Vec::<String>::new());
    }

    #[test]
    fn test_scopes_extraction_space_separated() {
        let claims = create_test_claims_with_scopes("read write delete");

        let scopes = claims.scopes();
        assert_eq!(scopes, vec!["read", "write", "delete"]);
    }

    #[test]
    fn test_scopes_extraction_array() {
        let mut extra = HashMap::new();
        extra.insert(
            "scopes".to_string(),
            Value::Array(vec![
                Value::String("read".to_string()),
                Value::String("write".to_string()),
            ]),
        );

        let claims = JwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: None,
            exp: 9999999999,
            iat: None,
            email: None,
            name: None,
            preferred_username: None,
            extra,
        };

        let scopes = claims.scopes();
        assert_eq!(scopes, vec!["read", "write"]);
    }

    #[test]
    fn test_scopes_extraction_empty() {
        let claims = JwtClaims::default();
        let scopes = claims.scopes();
        assert_eq!(scopes, Vec::<String>::new());
    }

    #[test]
    fn test_edge_case_empty_role_strings() {
        let mut extra = HashMap::new();
        extra.insert(
            "roles".to_string(),
            Value::Array(vec![
                Value::String("".to_string()),
                Value::String("admin".to_string()),
            ]),
        );

        let claims = JwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: None,
            exp: 9999999999,
            iat: None,
            email: None,
            name: None,
            preferred_username: None,
            extra,
        };

        assert!(claims.has_role("admin"));
        assert!(claims.has_role(""));
    }

    #[test]
    fn test_edge_case_unicode_scope() {
        let claims = create_test_claims_with_scopes("read:文档 write");

        assert!(claims.has_scope("read:文档"));
        assert!(claims.has_scope("write"));
    }
}
