//! OIDC client functionality for web applications

use std::{collections::HashMap, sync::Arc, time::{Duration, SystemTime}};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing;
use base64::Engine;

use crate::error::{PepError, Result};
use super::types::{OidcClientConfig, OidcDiscoveryDocument, DevConfig};

/// OIDC token response
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,
    /// Token type (usually "Bearer")
    pub token_type: String,
    /// Token expiration in seconds
    pub expires_in: Option<u64>,
    /// Refresh token
    pub refresh_token: Option<String>,
    /// ID token
    pub id_token: Option<String>,
    /// Granted scope
    pub scope: Option<String>,
}

/// OIDC client for handling authentication flows
#[derive(Clone)]
pub struct OidcClient {
    /// HTTP client
    http_client: Client,
    /// Discovery document cache
    discovery_cache: Arc<RwLock<HashMap<String, (OidcDiscoveryDocument, SystemTime)>>>,
}

impl OidcClient {
    /// Create a new OIDC client
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
            discovery_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Fetch OIDC discovery document with caching
    pub async fn get_discovery_document(&self, issuer_url: &str) -> Result<OidcDiscoveryDocument> {
        // Check cache first
        {
            let cache = self.discovery_cache.read().await;
            if let Some((doc, fetched_at)) = cache.get(issuer_url) {
                // Cache for 1 hour
                if fetched_at.elapsed().unwrap_or(Duration::from_secs(3600)) < Duration::from_secs(3600) {
                    return Ok(doc.clone());
                }
            }
        }

        // Fetch discovery document
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer_url.trim_end_matches('/'));
        tracing::debug!("Fetching OIDC discovery document from: {}", discovery_url);

        let response = self.http_client
            .get(&discovery_url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PepError::OidcDiscovery(format!("Failed to fetch discovery document: {}", e)))?;

        if !response.status().is_success() {
            return Err(PepError::OidcDiscovery(format!("Discovery document fetch failed with status: {}", response.status())));
        }

        let discovery_doc: OidcDiscoveryDocument = response
            .json()
            .await
            .map_err(|e| PepError::OidcDiscovery(format!("Failed to parse discovery document: {}", e)))?;

        // Cache the document
        {
            let mut cache = self.discovery_cache.write().await;
            cache.insert(issuer_url.to_string(), (discovery_doc.clone(), SystemTime::now()));
        }

        Ok(discovery_doc)
    }

    /// Build authorization URL for OIDC login
    pub async fn build_authorization_url(
        &self,
        config: &OidcClientConfig,
        state: &str,
        code_challenge: Option<&str>,
    ) -> Result<String> {
        let discovery = self.get_discovery_document(&config.issuer_url).await?;

        let auth_endpoint = discovery.authorization_endpoint
            .ok_or_else(|| PepError::BadRequest("No authorization endpoint in discovery document".to_string()))?;

        let mut url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            auth_endpoint,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&config.redirect_uri),
            urlencoding::encode(&config.scope),
            urlencoding::encode(state)
        );

        // Add PKCE code challenge if provided
        if let Some(challenge) = code_challenge {
            url.push_str(&format!("&code_challenge={}&code_challenge_method={}",
                                urlencoding::encode(challenge),
                                urlencoding::encode(&config.code_challenge_method)));
        }

        Ok(url)
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code_for_tokens(
        &self,
        config: &OidcClientConfig,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse> {
        let discovery = self.get_discovery_document(&config.issuer_url).await?;

        let token_endpoint = discovery.token_endpoint
            .ok_or_else(|| PepError::BadRequest("No token endpoint in discovery document".to_string()))?;

        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code".to_string());
        params.insert("client_id", config.client_id.clone());
        params.insert("code", code.to_string());
        params.insert("redirect_uri", config.redirect_uri.clone());

        if let Some(verifier) = code_verifier {
            params.insert("code_verifier", verifier.to_string());
        }

        let mut request = self.http_client
            .post(&token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded");

        // Add basic auth if client secret is provided
        if let Some(secret) = &config.client_secret {
            use base64::engine::general_purpose::STANDARD;
            let credentials = STANDARD.encode(format!("{}:{}", config.client_id, secret));
            request = request.header("Authorization", format!("Basic {}", credentials));
        } else {
            // For public clients, include client_id in body
            params.insert("client_id", config.client_id.clone());
        }

        let response = request
            .form(&params)
            .send()
            .await
            .map_err(|e| PepError::BadRequest(format!("Token exchange failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(PepError::BadRequest(format!("Token exchange failed: {}", error_text)));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| PepError::BadRequest(format!("Failed to parse token response: {}", e)))?;

        Ok(token_response)
    }

    /// Generate PKCE code challenge
    pub fn generate_code_challenge(verifier: &str) -> String {
        use sha2::{Digest, Sha256};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        URL_SAFE_NO_PAD.encode(hash)
    }

    /// Generate random PKCE code verifier
    pub fn generate_code_verifier() -> String {
        use rand::{distributions::Alphanumeric, Rng};
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }

    /// Generate random state parameter
    pub fn generate_state() -> String {
        use uuid::Uuid;
        Uuid::new_v4().to_string()
    }
}

impl Default for OidcClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Development mode authentication helper
pub struct DevAuthHelper;

impl DevAuthHelper {
    /// Create mock session data for development
    pub fn create_dev_session(dev_config: &DevConfig) -> HashMap<String, String> {
        let mut session_data = HashMap::new();
        session_data.insert("sub".to_string(), "dev-user".to_string());
        session_data.insert("iss".to_string(), "dev".to_string());
        session_data.insert("aud".to_string(), "dev-client".to_string());

        if let Some(email) = &dev_config.local_dev_email {
            session_data.insert("email".to_string(), email.clone());
        }

        if let Some(name) = &dev_config.local_dev_name {
            session_data.insert("name".to_string(), name.clone());
            session_data.insert("preferred_username".to_string(), name.clone());
        }

        if let Some(username) = &dev_config.local_dev_username {
            session_data.insert("preferred_username".to_string(), username.clone());
        }

        session_data
    }
}