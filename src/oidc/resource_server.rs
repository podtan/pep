//! Resource server functionality for JWT validation and API protection

use std::{collections::HashMap, sync::Arc, time::{Duration, SystemTime}};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use tokio::sync::RwLock;
use tracing;

use crate::error::{PepError, Result};
use super::types::{JwtClaims, OidcDiscoveryDocument, CachedJwks, JwtValidationOptions};

/// Map a JWK's algorithm parameters to a `jsonwebtoken::Algorithm`
pub fn jwk_algorithm_to_algorithm(jwk: &jsonwebtoken::jwk::Jwk) -> Result<Algorithm> {
    match &jwk.algorithm {
        jsonwebtoken::jwk::AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(params) => match &params.curve {
            jsonwebtoken::jwk::EllipticCurve::P256 => Ok(Algorithm::ES256),
            jsonwebtoken::jwk::EllipticCurve::P384 => Ok(Algorithm::ES384),
            other => Err(PepError::BadRequest(format!("Unsupported elliptic curve for JWK: {:?}", other))),
        },
        jsonwebtoken::jwk::AlgorithmParameters::OctetKey(_) => Err(PepError::BadRequest("HMAC keys not supported for OIDC verification".to_string())),
        jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(_) => Ok(Algorithm::EdDSA),
    }
}

/// Resource server client for JWT validation
#[derive(Clone)]
pub struct ResourceServerClient {
    /// HTTP client
    pub http_client: Client,
    /// JWKS cache
    pub jwks_cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
    /// Discovery document cache
    pub discovery_cache: Arc<RwLock<HashMap<String, (OidcDiscoveryDocument, SystemTime)>>>,
}

impl ResourceServerClient {
    /// Create a new resource server client
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
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

    /// Fetch JWKS with caching
    pub async fn get_jwks(&self, jwks_uri: &str) -> Result<HashMap<String, (DecodingKey, Algorithm)>> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(cached) = cache.get(jwks_uri) {
                // Cache for 1 hour
                if cached.fetched_at.elapsed().unwrap_or(cached.cache_duration) < cached.cache_duration {
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Fetch JWKS
        tracing::debug!("Fetching JWKS from: {}", jwks_uri);

        let response = self.http_client
            .get(jwks_uri)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PepError::JwksFetch(format!("Failed to fetch JWKS: {}", e)))?;

        if !response.status().is_success() {
            return Err(PepError::JwksFetch(format!("JWKS fetch failed with status: {}", response.status())));
        }

        let jwks_text = response
            .text()
            .await
            .map_err(|e| PepError::JwksFetch(format!("Failed to read JWKS response: {}", e)))?;

        let jwk_set: JwkSet = serde_json::from_str(&jwks_text)
            .map_err(|e| PepError::JwksFetch(format!("Failed to parse JWKS: {}", e)))?;

        // Parse the keys
        let mut keys = HashMap::new();
        for jwk in jwk_set.keys {
            if let Some(kid) = &jwk.common.key_id {
                match DecodingKey::from_jwk(&jwk) {
                    Ok(decoding_key) => {
                        match jwk_algorithm_to_algorithm(&jwk) {
                            Ok(algorithm) => {
                                keys.insert(kid.clone(), (decoding_key, algorithm));
                                tracing::debug!("Successfully parsed key {}: algorithm={:?}", kid, algorithm);
                            }
                            Err(e) => {
                                tracing::warn!("Unsupported algorithm for kid {}: {}", kid, e);
                                continue;
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!("Failed to create decoding key for kid {}: {}", kid, err);
                    }
                }
            } else {
                tracing::warn!("JWK missing kid field, skipping");
            }
        }

        // Cache the keys
        let cached = CachedJwks {
            keys: keys.clone(),
            fetched_at: SystemTime::now(),
            cache_duration: Duration::from_secs(3600), // 1 hour
        };
        {
            let mut cache = self.jwks_cache.write().await;
            cache.insert(jwks_uri.to_string(), cached);
        }

        Ok(keys)
    }

    /// Validate JWT token with custom validation options
    pub async fn validate_jwt_with_options(
        &self,
        token: &str,
        issuer_url: &str,
        client_id: &str,
        options: &JwtValidationOptions,
    ) -> Result<JwtClaims> {
        // Decode header to get kid and algorithm
        let header = decode_header(token)
            .map_err(|e| PepError::JwtValidation(format!("Invalid JWT header: {}", e)))?;

        let kid = header.kid
            .ok_or_else(|| PepError::JwtValidation("JWT missing kid in header".to_string()))?;

        // Get discovery document
        let discovery_doc = self.get_discovery_document(issuer_url).await?;

        // Get JWKS
        let keys = self.get_jwks(&discovery_doc.jwks_uri).await?;

        // Find the key for this kid
        let (decoding_key, key_algorithm) = keys.get(&kid)
            .ok_or_else(|| PepError::JwtValidation(format!("No key found for kid: {}", kid)))?;

        // Determine which algorithm to use:
        let algorithm = {
            let jwt_alg = header.alg;
            if jwt_alg == *key_algorithm {
                jwt_alg
            } else {
                tracing::warn!(
                    "JWT header algorithm ({:?}) doesn't match key algorithm ({:?}) for kid {}. Using key algorithm.",
                    jwt_alg, key_algorithm, kid
                );
                *key_algorithm
            }
        };

        tracing::debug!("Validating JWT with kid: {}, algorithm: {:?}", kid, algorithm);

        // Set up validation
        let mut validation = Validation::new(algorithm);

        // Configure issuer validation
        if options.skip_issuer_validation {
            tracing::debug!("Skipping issuer validation as configured");
        } else {
            validation.set_issuer(&[issuer_url]);
        }

        // Configure audience validation
        if options.skip_audience_validation {
            tracing::debug!("Skipping audience validation as configured");
            validation.validate_aud = false;
        } else {
            let audience = options.expected_audience.as_deref().unwrap_or(client_id);
            tracing::debug!("Validating audience against: {}", audience);
            validation.set_audience(&[audience]);
        }

        // Decode and validate the token
        let token_data = decode::<JwtClaims>(token, decoding_key, &validation)
            .map_err(|e| PepError::JwtValidation(format!("JWT validation failed: {}", e)))?;

        Ok(token_data.claims)
    }

    /// Validate JWT token with default options
    pub async fn validate_jwt(&self, token: &str, issuer_url: &str, client_id: &str) -> Result<JwtClaims> {
        self.validate_jwt_with_options(token, issuer_url, client_id, &JwtValidationOptions::default()).await
    }
}

impl Default for ResourceServerClient {
    fn default() -> Self {
        Self::new()
    }
}