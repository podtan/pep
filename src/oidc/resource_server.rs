//! Resource server functionality for JWT validation and API protection

use std::{collections::HashMap, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use tokio::sync::RwLock;
use tracing;

use crate::error::{PepError, Result};
use super::types::{JwtClaims, OidcDiscoveryDocument, CachedJwks, CachedDiscoveryRaw, JwtValidationOptions};

/// Cache entry for userinfo endpoint responses
#[derive(Clone)]
pub struct CachedUserInfo {
    /// The userinfo claims
    pub claims: serde_json::Map<String, serde_json::Value>,
    /// When the entry was cached
    pub cached_at: SystemTime,
    /// TTL in seconds (derived from token expiry)
    pub ttl_secs: u64,
}

impl CachedUserInfo {
    /// Check if this cache entry has expired
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed().unwrap_or(Duration::from_secs(self.ttl_secs + 1)) >= Duration::from_secs(self.ttl_secs)
    }
}

/// In-memory cache for OIDC userinfo responses.
///
/// Keyed by JWT `jti` (token ID) when available, falling back to `sub` (subject).
/// Entries auto-expire based on the remaining token lifetime.
#[derive(Clone)]
pub struct UserInfoCache {
    inner: Arc<RwLock<HashMap<String, CachedUserInfo>>>,
}

impl UserInfoCache {
    /// Create a new empty userinfo cache
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get cached userinfo if present and not expired
    pub async fn get(&self, key: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
        let cache = self.inner.read().await;
        cache.get(key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.claims.clone())
            }
        })
    }

    /// Store userinfo claims with a TTL derived from token expiry
    pub async fn insert(
        &self,
        key: String,
        claims: serde_json::Map<String, serde_json::Value>,
        token_exp: i64,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs() as i64;

        // TTL = remaining token lifetime, with a safety margin of 30 seconds
        let remaining = if token_exp > now {
            (token_exp - now) as u64
        } else {
            0
        };
        let ttl_secs = remaining.saturating_sub(30).max(30); // at least 30s, at most token remaining - 30s

        let entry = CachedUserInfo {
            claims,
            cached_at: SystemTime::now(),
            ttl_secs,
        };

        let mut cache = self.inner.write().await;
        cache.insert(key, entry);
    }

    /// Purge expired entries (call periodically to free memory)
    pub async fn purge_expired(&self) {
        let mut cache = self.inner.write().await;
        cache.retain(|_, entry| !entry.is_expired());
    }
}

impl Default for UserInfoCache {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// Discovery document cache (parsed)
    pub discovery_cache: Arc<RwLock<HashMap<String, (OidcDiscoveryDocument, SystemTime)>>>,
    /// Discovery document cache (raw JSON for proxying)
    pub discovery_cache_raw: Arc<RwLock<HashMap<String, CachedDiscoveryRaw>>>,
    /// Userinfo response cache (keyed by jti/sub, TTL = token remaining lifetime)
    pub userinfo_cache: Arc<UserInfoCache>,
}

impl ResourceServerClient {
    /// Create a new resource server client
    pub fn new() -> Self {
        Self {
            http_client: Client::new(),
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
            discovery_cache: Arc::new(RwLock::new(HashMap::new())),
            discovery_cache_raw: Arc::new(RwLock::new(HashMap::new())),
            userinfo_cache: Arc::new(UserInfoCache::new()),
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

    /// Fetch OIDC discovery document as raw JSON with caching
    pub async fn get_discovery_document_raw(&self, issuer_url: &str) -> Result<String> {
        let cache_duration = Duration::from_secs(3600);
        
        {
            let cache = self.discovery_cache_raw.read().await;
            if let Some(cached) = cache.get(issuer_url) {
                if cached.fetched_at.elapsed().unwrap_or(cache_duration) < cache_duration {
                    return Ok(cached.raw_json.clone());
                }
            }
        }

        let discovery_url = format!("{}/.well-known/openid-configuration", issuer_url.trim_end_matches('/'));
        tracing::debug!("Fetching raw OIDC discovery document from: {}", discovery_url);

        let response = self.http_client
            .get(&discovery_url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PepError::OidcDiscovery(format!("Failed to fetch discovery document: {}", e)))?;

        if !response.status().is_success() {
            return Err(PepError::OidcDiscovery(format!("Discovery document fetch failed with status: {}", response.status())));
        }

        let raw_json = response
            .text()
            .await
            .map_err(|e| PepError::OidcDiscovery(format!("Failed to read discovery document: {}", e)))?;

        let cached = CachedDiscoveryRaw {
            raw_json: raw_json.clone(),
            fetched_at: SystemTime::now(),
            cache_duration,
        };
        {
            let mut cache = self.discovery_cache_raw.write().await;
            cache.insert(issuer_url.to_string(), cached);
        }

        Ok(raw_json)
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
        // Allow 60 seconds of clock skew between issuer, proxy, and resource server.
        // Without this, sub-second timing differences between Torpi (proxy) and
        // Trustee (resource server) can cause ExpiredSignature on valid tokens.
        validation.leeway = 60;

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

    /// Adaptive claims enrichment: fill missing `groups` / `role` from the OIDC `/userinfo` endpoint.
    ///
    /// **IdP-agnostic design:**
    /// 1. If `claims.extra` already contains `groups` or `role`, use them directly (zero cost).
    /// 2. Otherwise, call the `/userinfo` endpoint with the access token as Bearer.
    /// 3. Merge `groups` and `role` from userinfo into `claims.extra`.
    /// 4. Cache the userinfo response by `jti` (or `sub` fallback) until the token expires.
    ///
    /// This works with Kanidm (no groups in AT), Keycloak/Auth0 (groups in AT → fast path),
    /// Okta, Azure AD, Google, and any other OIDC-compliant provider.
    ///
    /// # Arguments
    ///
    /// * `claims` - The JWT claims returned by `validate_jwt_*`. Mutated in place.
    /// * `token` - The raw access token string (used as Bearer for the userinfo call).
    /// * `issuer_url` - The OIDC issuer URL (used to derive the userinfo endpoint).
    /// * `userinfo_url_override` - Optional explicit userinfo URL. If `None`, the URL is
    ///   derived from the discovery document's `userinfo_endpoint`, falling back to
    ///   `{issuer_url}/userinfo`.
    pub async fn enrich_claims_with_userinfo(
        &self,
        claims: &mut JwtClaims,
        token: &str,
        issuer_url: &str,
        userinfo_url_override: Option<&str>,
    ) -> Result<()> {
        // Fast path: claims already have groups — sufficient for authorization.
        // `role` is an application-level concept not issued by standard OIDC providers,
        // so requiring it here would cause unnecessary userinfo calls on every request.
        let has_groups = claims.extra.contains_key("groups");

        if has_groups {
            tracing::debug!("Claims already contain groups — skipping userinfo enrichment");
            return Ok(());
        }

        tracing::debug!("Claims missing groups — attempting userinfo enrichment");

        // Build cache key from jti (if present in extra) or sub
        let cache_key = claims
            .extra
            .get("jti")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| claims.sub.clone());

        // Check userinfo cache first
        if let Some(cached_claims) = self.userinfo_cache.get(&cache_key).await {
            tracing::debug!(cache_key = %cache_key, "Using cached userinfo for claims enrichment");
            merge_userinfo_into_claims(claims, &cached_claims);
            return Ok(());
        }

        // Resolve the userinfo endpoint URL
        let userinfo_url = match userinfo_url_override {
            Some(url) => url.to_string(),
            None => {
                // Try discovery document first (has the canonical userinfo_endpoint)
                match self.get_discovery_document(issuer_url).await {
                    Ok(doc) if doc.userinfo_endpoint.is_some() => {
                        doc.userinfo_endpoint.unwrap()
                    }
                    Ok(_) => {
                        // Fallback: derive from issuer URL
                        format!("{}/userinfo", issuer_url.trim_end_matches('/'))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch discovery for userinfo URL: {}. Deriving from issuer.", e);
                        format!("{}/userinfo", issuer_url.trim_end_matches('/'))
                    }
                }
            }
        };

        tracing::debug!(userinfo_url = %userinfo_url, "Calling userinfo endpoint for claims enrichment");

        // Call the userinfo endpoint with the access token as Bearer
        let response = self.http_client
            .get(&userinfo_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PepError::Userinfo(format!("Userinfo request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::warn!(
                userinfo_url = %userinfo_url, status = %status,
                "Userinfo endpoint returned error: {}", body
            );
            // Non-fatal: enrichment failed but JWT is still valid.
            // Return Ok so the request proceeds with whatever claims we have.
            return Ok(());
        }

        let userinfo: serde_json::Map<String, serde_json::Value> = response
            .json()
            .await
            .map_err(|e| PepError::Userinfo(format!("Failed to parse userinfo response: {}", e)))?;

        tracing::debug!(
            userinfo_keys = ?userinfo.keys().collect::<Vec<_>>(),
            "Userinfo response received"
        );

        // Cache the userinfo response (TTL = remaining token lifetime)
        self.userinfo_cache.insert(cache_key.clone(), userinfo.clone(), claims.exp).await;

        // Merge userinfo claims into JWT claims
        merge_userinfo_into_claims(claims, &userinfo);

        Ok(())
    }
}

/// Merge select fields from the userinfo endpoint response into JWT claims `extra`.
///
/// Only merges fields that are relevant for authorization decisions (`groups`, `role`)
/// and are not already present in `claims.extra`. This avoids overwriting values that
/// the IdP may have already put into the access token.
fn merge_userinfo_into_claims(
    claims: &mut JwtClaims,
    userinfo: &serde_json::Map<String, serde_json::Value>,
) {
    let fields_to_merge = ["groups", "role"];
    for field in &fields_to_merge {
        if !claims.extra.contains_key(*field) {
            if let Some(value) = userinfo.get(*field) {
                claims.extra.insert(field.to_string(), value.clone());
                tracing::debug!(
                    field,
                    value = %value,
                    "Merged field from userinfo into claims"
                );
            }
        }
    }
}

impl Default for ResourceServerClient {
    fn default() -> Self {
        Self::new()
    }
}