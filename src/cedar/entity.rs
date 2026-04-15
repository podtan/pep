//! Entity building utilities for Cedar authorization
//!
//! Maps PEP's `JwtClaims` and resource information into Cedar `Entity` objects
//! that can be used in authorization requests.

use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use crate::oidc::types::JwtClaims;
use super::error::CedarError;

/// Information about a resource being accessed, used to build a Cedar entity
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    /// Entity type name (e.g., "Project", "Task", "Workstream", "Asset")
    pub entity_type: String,
    /// Unique identifier for the resource
    pub id: String,
    /// Optional attributes as key-value pairs
    pub attributes: HashMap<String, String>,
}

impl ResourceInfo {
    /// Create a new ResourceInfo with just type and id
    pub fn new(entity_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            entity_type: entity_type.into(),
            id: id.into(),
            attributes: HashMap::new(),
        }
    }

    /// Add an attribute to the resource
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Build a Cedar Entity from this ResourceInfo
    pub fn to_cedar_entity(&self) -> Result<Entity, CedarError> {
        let uid = self.to_cedar_uid()?;
        let attrs: HashMap<String, RestrictedExpression> = self
            .attributes
            .iter()
            .map(|(k, v)| (k.clone(), RestrictedExpression::new_string(v.clone())))
            .collect();

        let parents: HashSet<EntityUid> = HashSet::new();
        Entity::new(uid, attrs, parents)
            .map_err(|e| CedarError::EntityBuildFailed(format!("{}", e)))
    }

    /// Build a Cedar EntityUid from this ResourceInfo
    pub fn to_cedar_uid(&self) -> Result<EntityUid, CedarError> {
        let type_name = EntityTypeName::from_str(&self.entity_type)
            .map_err(|e| CedarError::EntityBuildFailed(format!("Invalid entity type '{}': {}", self.entity_type, e)))?;
        let entity_id = EntityId::from_str(&self.id)
            .map_err(|e| CedarError::EntityBuildFailed(format!("Invalid entity id '{}': {}", self.id, e)))?;
        Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
    }
}

/// Build a Cedar principal EntityUid from JwtClaims
pub fn build_principal_uid(claims: &JwtClaims) -> Result<EntityUid, CedarError> {
    let type_name = EntityTypeName::from_str("User")
        .map_err(|e| CedarError::EntityBuildFailed(format!("Invalid principal type: {}", e)))?;
    let entity_id = EntityId::from_str(&claims.sub)
        .map_err(|e| CedarError::EntityBuildFailed(format!("Invalid principal id '{}': {}", claims.sub, e)))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

/// Build a Cedar principal Entity from JwtClaims with attributes
pub fn build_principal_entity(claims: &JwtClaims) -> Result<Entity, CedarError> {
    let uid = build_principal_uid(claims)?;
    let mut attrs: HashMap<String, RestrictedExpression> = HashMap::new();

    if let Some(ref email) = claims.email {
        attrs.insert("email".to_string(), RestrictedExpression::new_string(email.clone()));
    }
    if let Some(ref name) = claims.name {
        attrs.insert("name".to_string(), RestrictedExpression::new_string(name.clone()));
    }
    if let Some(ref username) = claims.preferred_username {
        attrs.insert(
            "username".to_string(),
            RestrictedExpression::new_string(username.clone()),
        );
    }

    // Add roles as a set if present in extra claims
    if let Some(serde_json::Value::Array(roles)) = claims.extra.get("roles") {
        let set_exprs: Vec<RestrictedExpression> = roles
            .iter()
            .filter_map(|r| {
                if let serde_json::Value::String(s) = r {
                    Some(RestrictedExpression::new_string(s.clone()))
                } else {
                    None
                }
            })
            .collect();
        if !set_exprs.is_empty() {
            attrs.insert("roles".to_string(), RestrictedExpression::new_set(set_exprs));
        }
    }

    let parents: HashSet<EntityUid> = HashSet::new();
    Entity::new(uid, attrs, parents)
        .map_err(|e| CedarError::EntityBuildFailed(format!("{}", e)))
}

/// Build a Cedar action EntityUid from an action string like "view", "edit", "delete"
pub fn build_action_uid(action: &str) -> Result<EntityUid, CedarError> {
    let type_name = EntityTypeName::from_str("Action")
        .map_err(|e| CedarError::EntityBuildFailed(format!("Invalid action type: {}", e)))?;
    let entity_id = EntityId::from_str(action)
        .map_err(|e| CedarError::EntityBuildFailed(format!("Invalid action '{}': {}", action, e)))?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_claims() -> JwtClaims {
        let mut extra = HashMap::new();
        extra.insert(
            "roles".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("admin".to_string()),
                serde_json::Value::String("user".to_string()),
            ]),
        );

        JwtClaims {
            sub: "alice".to_string(),
            iss: "test-issuer".to_string(),
            aud: None,
            exp: 9999999999,
            iat: None,
            email: Some("alice@example.com".to_string()),
            name: Some("Alice Smith".to_string()),
            preferred_username: Some("alice".to_string()),
            extra,
        }
    }

    #[test]
    fn test_build_principal_uid() {
        let claims = create_test_claims();
        let uid = build_principal_uid(&claims).unwrap();
        assert_eq!(uid.to_string(), r#"User::"alice""#);
    }

    #[test]
    fn test_build_principal_entity() {
        let claims = create_test_claims();
        let entity = build_principal_entity(&claims).unwrap();
        assert_eq!(entity.uid().to_string(), r#"User::"alice""#);
    }

    #[test]
    fn test_build_action_uid() {
        let uid = build_action_uid("view").unwrap();
        assert_eq!(uid.to_string(), r#"Action::"view""#);
    }

    #[test]
    fn test_resource_info_new() {
        let info = ResourceInfo::new("Task", "task-123");
        assert_eq!(info.entity_type, "Task");
        assert_eq!(info.id, "task-123");
        assert!(info.attributes.is_empty());
    }

    #[test]
    fn test_resource_info_with_attribute() {
        let info = ResourceInfo::new("Task", "task-123")
            .with_attribute("status", "Pending")
            .with_attribute("priority", "High");
        assert_eq!(info.attributes.len(), 2);
        assert_eq!(info.attributes.get("status").unwrap(), "Pending");
    }

    #[test]
    fn test_resource_info_to_cedar_uid() {
        let info = ResourceInfo::new("Task", "task-123");
        let uid = info.to_cedar_uid().unwrap();
        assert_eq!(uid.to_string(), r#"Task::"task-123""#);
    }

    #[test]
    fn test_resource_info_to_cedar_entity() {
        let info = ResourceInfo::new("Task", "task-123")
            .with_attribute("status", "Pending");
        let entity = info.to_cedar_entity().unwrap();
        assert_eq!(entity.uid().to_string(), r#"Task::"task-123""#);
    }

    #[test]
    fn test_build_principal_uid_default_claims() {
        let claims = JwtClaims::default();
        let uid = build_principal_uid(&claims).unwrap();
        assert_eq!(uid.to_string(), r#"User::"anonymous""#);
    }
}
