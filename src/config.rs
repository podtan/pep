//! Configuration parsing module for PEP
//! 
//! This module provides standardized configuration loading from TOML files,
//! supporting both OIDC and development-mode settings.
//!
//! # Example
//!
//! ```rust,ignore
//! use pep::config::load_config;
//!
//! let config = load_config("config.toml")?;
//! let oidc_config = config.oidc_config()?;
//! let client_config = oidc_config.to_oidc_client_config();
//! ```

use crate::{OidcClientConfig, DevConfig, Result, PepError};
use crate::oidc::types::{ResourceServerConfig, JwtValidationOptions};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PepConfig {
    /// OIDC configuration section
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    
    /// Development mode configuration section
    #[serde(default)]
    pub dev: Option<OidcDevConfig>,
}

impl PepConfig {
    /// Load configuration from a TOML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        load_config(path)
    }

    /// Get OIDC configuration
    pub fn oidc_config(&self) -> Result<OidcConfig> {
        self.oidc.clone().ok_or_else(|| {
            PepError::Config("OIDC configuration not found in config file".to_string())
        })
    }

    /// Get development mode configuration
    pub fn dev_config(&self) -> Option<OidcDevConfig> {
        self.dev.clone()
    }
}

/// OIDC configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC provider name (e.g., "kanidm", "okta")
    #[serde(default)]
    pub provider: Option<String>,

    /// OIDC provider issuer URL
    pub issuer_url: String,

    /// Client ID
    pub client_id: String,

    /// Client secret (optional for public clients)
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Redirect URL (for authorization code flow)
    #[serde(default)]
    pub redirect_url: Option<String>,

    /// Code challenge method for PKCE (default: "S256")
    #[serde(default)]
    pub code_challenge_method: Option<String>,

    /// OAuth 2.0 scope
    #[serde(default)]
    pub scope: Option<String>,

    /// Skip issuer validation (not recommended for production)
    #[serde(default)]
    pub skip_issuer_validation: Option<bool>,

    /// Skip audience validation
    #[serde(default)]
    pub skip_audience_validation: Option<bool>,

    /// Expected audience value (if different from client_id)
    #[serde(default)]
    pub expected_audience: Option<String>,
}

impl OidcConfig {
    /// Convert to OidcClientConfig for use with OidcClient
    pub fn to_oidc_client_config(&self) -> OidcClientConfig {
        OidcClientConfig {
            issuer_url: self.issuer_url.clone(),
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            redirect_uri: self.redirect_url.clone().unwrap_or_default(),
            scope: self.scope.clone().unwrap_or_else(|| "openid profile email".to_string()),
            code_challenge_method: self.code_challenge_method.clone().unwrap_or_else(|| "S256".to_string()),
        }
    }

    /// Convert to ResourceServerConfig for use with ResourceServerClient
    pub fn to_resource_server_config(&self) -> ResourceServerConfig {
        let validation_options = JwtValidationOptions {
            skip_issuer_validation: self.skip_issuer_validation.unwrap_or(false),
            skip_audience_validation: self.skip_audience_validation.unwrap_or(false),
            expected_audience: self.expected_audience.clone(),
        };

        ResourceServerConfig {
            issuer_url: self.issuer_url.clone(),
            client_id: self.client_id.clone(),
            validation_options,
        }
    }
}

/// Development mode configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OidcDevConfig {
    /// Enable local development mode (bypasses real OIDC)
    #[serde(default)]
    pub local_dev_mode: bool,

    /// Mock email for development
    #[serde(default)]
    pub local_dev_email: Option<String>,

    /// Mock name for development
    #[serde(default)]
    pub local_dev_name: Option<String>,

    /// Mock username for development
    #[serde(default)]
    pub local_dev_username: Option<String>,

    /// Mock role for development
    #[serde(default)]
    pub local_dev_role: Option<String>,
}

impl OidcDevConfig {
    /// Convert to PEP's internal DevConfig
    pub fn to_pep_dev_config(&self) -> DevConfig {
        DevConfig {
            local_dev_mode: self.local_dev_mode,
            local_dev_email: self.local_dev_email.clone(),
            local_dev_name: self.local_dev_name.clone(),
            local_dev_username: self.local_dev_username.clone(),
        }
    }
}

/// Load configuration from a TOML file
///
/// # Arguments
///
/// * `path` - Path to the TOML configuration file
///
/// # Returns
///
/// A `Result<PepConfig>` containing the parsed configuration or an error
///
/// # Example
///
/// ```rust,ignore
/// let config = pep::config::load_config("config.toml")?;
/// ```
pub fn load_config<P: AsRef<Path>>(path: P) -> Result<PepConfig> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)
        .map_err(|e| PepError::Config(format!("Failed to read config file: {}", e)))?;

    toml::from_str(&content)
        .map_err(|e| PepError::Config(format!("Failed to parse TOML config: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_oidc_config() {
        let toml_str = r#"
[oidc]
issuer_url = "https://idm.example.com"
client_id = "test-client"
"#;
        let config: PepConfig = toml::from_str(toml_str).unwrap();
        assert!(config.oidc.is_some());
        let oidc = config.oidc.unwrap();
        assert_eq!(oidc.issuer_url, "https://idm.example.com");
        assert_eq!(oidc.client_id, "test-client");
        assert!(oidc.client_secret.is_none());
    }

    #[test]
    fn test_parse_full_oidc_config() {
        let toml_str = r#"
[oidc]
provider = "kanidm"
issuer_url = "https://idm.example.com"
client_id = "test-client"
client_secret = "test-secret"
redirect_url = "https://app.example.com/callback"
code_challenge_method = "S256"
scope = "openid email profile offline_access"
skip_issuer_validation = false
skip_audience_validation = false
expected_audience = "test-audience"
"#;
        let config: PepConfig = toml::from_str(toml_str).unwrap();
        assert!(config.oidc.is_some());
        let oidc = config.oidc.unwrap();
        assert_eq!(oidc.provider.unwrap(), "kanidm");
        assert_eq!(oidc.client_secret.unwrap(), "test-secret");
        assert_eq!(oidc.scope.unwrap(), "openid email profile offline_access");
    }

    #[test]
    fn test_parse_dev_config() {
        let toml_str = r#"
[dev]
local_dev_mode = true
local_dev_email = "dev@example.com"
local_dev_name = "Dev User"
local_dev_username = "devuser"
local_dev_role = "admin"
"#;
        let config: PepConfig = toml::from_str(toml_str).unwrap();
        assert!(config.dev.is_some());
        let dev = config.dev.unwrap();
        assert!(dev.local_dev_mode);
        assert_eq!(dev.local_dev_email.unwrap(), "dev@example.com");
    }

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
[oidc]
issuer_url = "https://idm.example.com"
client_id = "test-client"
client_secret = "test-secret"
scope = "openid email profile"

[dev]
local_dev_mode = true
local_dev_email = "dev@example.com"
"#;
        let config: PepConfig = toml::from_str(toml_str).unwrap();
        assert!(config.oidc.is_some());
        assert!(config.dev.is_some());
    }

    #[test]
    fn test_oidc_config_conversion() {
        let oidc_config = OidcConfig {
            provider: Some("kanidm".to_string()),
            issuer_url: "https://idm.example.com".to_string(),
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
            redirect_url: Some("https://app.example.com/callback".to_string()),
            code_challenge_method: Some("S256".to_string()),
            scope: Some("openid email profile".to_string()),
            skip_issuer_validation: None,
            skip_audience_validation: None,
            expected_audience: None,
        };

        let client_config = oidc_config.to_oidc_client_config();
        assert_eq!(client_config.issuer_url, "https://idm.example.com");
        assert_eq!(client_config.client_id, "test-client");
        assert_eq!(client_config.scope, "openid email profile");

        let resource_config = oidc_config.to_resource_server_config();
        assert_eq!(resource_config.issuer_url, "https://idm.example.com");
        assert_eq!(resource_config.client_id, "test-client");
    }

    #[test]
    fn test_dev_config_conversion() {
        let dev_config = OidcDevConfig {
            local_dev_mode: true,
            local_dev_email: Some("dev@example.com".to_string()),
            local_dev_name: Some("Dev User".to_string()),
            local_dev_username: Some("devuser".to_string()),
            local_dev_role: Some("admin".to_string()),
        };

        let pep_dev = dev_config.to_pep_dev_config();
        assert!(pep_dev.local_dev_mode);
        assert_eq!(pep_dev.local_dev_email.unwrap(), "dev@example.com");
    }

    #[test]
    fn test_pep_config_oidc_config_method() {
        let toml_str = r#"
[oidc]
issuer_url = "https://idm.example.com"
client_id = "test-client"
"#;
        let config: PepConfig = toml::from_str(toml_str).unwrap();
        let oidc = config.oidc_config().unwrap();
        assert_eq!(oidc.client_id, "test-client");
    }
}
