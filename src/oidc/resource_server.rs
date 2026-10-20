//! Resource server functionality for JWT validation and API protection

use std::{collections::HashMap, sync::Arc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Client;
use tokio::sync::RwLock;
use tracing;

use crate::error::{PepError, Result};
use super::types::{JwtClaims, OidcDiscoveryDocument, CachedJwks, CachedDiscoveryRaw, JwtValidationOptions};

/// Minimum interval between forced JWKS refreshes for the same `jwks_uri`.
///
/// Storm guard: a burst of tokens bearing unknown/random kids must not hammer
/// the IdP's JWKS endpoint — at most one forced fetch per interval.
const FORCED_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);

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
    /// Last forced JWKS refresh per jwks_uri (storm guard for IdP key rotation)
    pub last_forced_fetch: Arc<RwLock<HashMap<String, Instant>>>,
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
            last_forced_fetch: Arc::new(RwLock::new(HashMap::new())),
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
        self.get_jwks_inner(jwks_uri, false).await
    }

    /// Fetch JWKS, optionally bypassing the cache TTL (`force_refresh = true`).
    async fn get_jwks_inner(&self, jwks_uri: &str, force_refresh: bool) -> Result<HashMap<String, (DecodingKey, Algorithm)>> {
        if !force_refresh {
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

    /// Force-refresh the JWKS for `jwks_uri`, bypassing the cache TTL.
    ///
    /// Storm-guarded: the attempt timestamp is recorded BEFORE fetching (so
    /// failed fetches are rate-limited too), and when a forced refresh already
    /// happened within `FORCED_REFRESH_MIN_INTERVAL`, the cached keys are
    /// served instead of hitting the IdP again.
    async fn force_refresh_jwks(&self, jwks_uri: &str) -> Result<HashMap<String, (DecodingKey, Algorithm)>> {
        {
            let mut last = self.last_forced_fetch.write().await;
            let now = Instant::now();
            if let Some(prev) = last.get(jwks_uri) {
                if now.duration_since(*prev) < FORCED_REFRESH_MIN_INTERVAL {
                    drop(last);
                    tracing::debug!("Storm guard held for {} — serving cached JWKS instead of forced refresh", jwks_uri);
                    let cache = self.jwks_cache.read().await;
                    if let Some(cached) = cache.get(jwks_uri) {
                        return Ok(cached.keys.clone());
                    }
                    return self.get_jwks_inner(jwks_uri, false).await;
                }
            }
            last.insert(jwks_uri.to_string(), now);
        }
        self.get_jwks_inner(jwks_uri, true).await
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
        let mut keys = self.get_jwks(&discovery_doc.jwks_uri).await?;

        // Find the key for this kid. On a miss, the IdP may have rotated its
        // signing keys after our cached JWKS was fetched — force one refresh
        // (storm-guarded) and retry the lookup before failing.
        if !keys.contains_key(&kid) {
            tracing::info!(
                "kid {} not in cached JWKS for {} — forcing refresh",
                kid,
                discovery_doc.jwks_uri
            );
            if let Err(e) = self.force_refresh_jwks(&discovery_doc.jwks_uri).await {
                tracing::warn!("Forced JWKS refresh failed for {}: {}", discovery_doc.jwks_uri, e);
            }
            keys = self.get_jwks(&discovery_doc.jwks_uri).await?;
        }
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

        // Call the userinfo endpoint with the access token as Bearer.
        // FAIL-CLOSED contract: any transport failure here surfaces as
        // `PepError::AuthDegraded` — NEVER as silent empty-claims success.
        let response = self.http_client
            .get(&userinfo_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| PepError::AuthDegraded {
                detail: format!("userinfo request failed ({}): {}", userinfo_url, e),
                // timeout / connection refused / TLS: transient — retry may succeed
                retryable: true,
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let retryable = status.is_server_error() || status.as_u16() == 429;
            tracing::warn!(
                userinfo_url = %userinfo_url, status = %status, retryable,
                "Userinfo endpoint returned error — surfacing auth_degraded (fail-closed)"
            );
            // 4xx (e.g. 400/401 invalid_token mid-flight): terminal for this
            // token → deny. 5xx/429: transient → retryable 503-class.
            return Err(PepError::AuthDegraded {
                detail: format!("userinfo returned HTTP {} for {}", status, userinfo_url),
                retryable,
            });
        }

        let userinfo: serde_json::Map<String, serde_json::Value> = response
            .json()
            .await
            .map_err(|e| PepError::AuthDegraded {
                detail: format!("userinfo response malformed: {}", e),
                retryable: true,
            })?;

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

    /// Own-token claims enrichment (nghr 9ee826c2; owner FIX ORDER payam
    /// 8e50cbca, 2026-10-20): the enrichment leg for a token this service
    /// minted ITSELF (RFC 8693 service-account flows).
    ///
    /// Why it exists: [`Self::enrich_claims_with_userinfo`] treats a userinfo
    /// 400/401 as terminal for the presented token — correct for a FOREIGN
    /// bearer, wrong when the bearer came from our own provider: the cached
    /// token can be IdP-expired despite local freshness, and the caller
    /// deserves a re-mint, not a deny.
    ///
    /// The composition, exactly as ordered:
    ///
    ///   userinfo 400/401 ⇒ `provider.invalidate()` → re-mint →
    ///   VALIDATE the fresh credential with a second userinfo roundtrip
    ///   → retry once → on a second rejection: terminal loud.
    ///
    /// Re-mint alone is INSUFFICIENT: during the 2026-10-20 payam write-leg
    /// outage, eight fresh ~900s tokens were rejected within ~40ms of mint,
    /// and the SAME generation succeeded 69s later with no new mint (journal
    /// 711f2688 — a bounded upstream validation window). Therefore the fresh
    /// token is validated BEFORE the caller may proceed: if userinfo rejects
    /// a just-minted token, the defect is UPSTREAM and this surfaces as
    /// `PepError::AuthDegraded { retryable: false }` carrying the upstream
    /// rejection body. The caller must never burn the real operation on an
    /// unvalidated credential, and silent success is structurally impossible.
    ///
    /// 5xx/429/transport/malformed failures are NOT token rejections: no
    /// re-mint on either leg; they surface retryable (503-class) with the
    /// established classification. Other 4xx stay terminal, as before.
    ///
    /// Foreign-token semantics: [`Self::enrich_claims_with_userinfo`] is
    /// untouched — separate function, no behavior change for `pep = "0.5"`
    /// pins; consumers adopt the composition by bumping and calling this.
    #[cfg(feature = "token-provider")]
    pub async fn enrich_claims_with_userinfo_own_token<
        P: crate::token_provider::TokenProvider,
    >(
        &self,
        provider: &P,
        claims: &mut JwtClaims,
        issuer_url: &str,
        userinfo_url_override: Option<&str>,
    ) -> Result<()> {
        // Fast path: identical policy to the foreign-token method.
        let has_groups = claims.extra.contains_key("groups");
        if has_groups {
            tracing::debug!("Claims already contain groups — skipping userinfo enrichment");
            return Ok(());
        }

        // Cache: identical policy (jti → sub fallback, TTL = token expiry).
        let cache_key = claims
            .extra
            .get("jti")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| claims.sub.clone());
        if let Some(cached_claims) = self.userinfo_cache.get(&cache_key).await {
            tracing::debug!(cache_key = %cache_key, "Using cached userinfo for claims enrichment");
            merge_userinfo_into_claims(claims, &cached_claims);
            return Ok(());
        }

        // Resolve the userinfo endpoint (identical policy).
        let userinfo_url = match userinfo_url_override {
            Some(url) => url.to_string(),
            None => match self.get_discovery_document(issuer_url).await {
                Ok(doc) if doc.userinfo_endpoint.is_some() => {
                    doc.userinfo_endpoint.unwrap()
                }
                Ok(_) => format!("{}/userinfo", issuer_url.trim_end_matches('/')),
                Err(e) => {
                    tracing::warn!("Failed to fetch discovery for userinfo URL: {}. Deriving from issuer.", e);
                    format!("{}/userinfo", issuer_url.trim_end_matches('/'))
                }
            },
        };

        // Leg 1: mint + call.
        let token = provider.get_token().await?;
        match userinfo_once(&self.http_client, &userinfo_url, &token).await {
            Ok(userinfo) => {
                self.userinfo_cache.insert(cache_key, userinfo.clone(), claims.exp).await;
                merge_userinfo_into_claims(claims, &userinfo);
                Ok(())
            }
            // The incident wire: our OWN bearer was rejected. Invalidate,
            // re-mint, and make the retry double as the fresh-credential
            // validation gate.
            Err(UserinfoFailure::TokenRejected { status, body }) => {
                tracing::warn!(
                    userinfo_url = %userinfo_url, status, upstream_body = %body,
                    "own-token userinfo rejected the bearer — invalidating, re-minting, validating fresh token (9ee826c2 composition)"
                );
                provider.invalidate().await;
                let fresh = provider.get_token().await?;
                match userinfo_once(&self.http_client, &userinfo_url, &fresh).await {
                    Ok(userinfo) => {
                        tracing::info!(
                            userinfo_url = %userinfo_url,
                            "own-token enrichment: fresh credential validated — proceeding"
                        );
                        self.userinfo_cache.insert(cache_key, userinfo.clone(), claims.exp).await;
                        merge_userinfo_into_claims(claims, &userinfo);
                        Ok(())
                    }
                    // Fresh token rejected too → the upstream validation
                    // state is the defect (711f2688 class). Terminal loud;
                    // the caller must NOT proceed and burn the operation.
                    Err(UserinfoFailure::TokenRejected { status, body }) => {
                        tracing::error!(
                            userinfo_url = %userinfo_url, status,
                            "own-token userinfo rejected a JUST-MINTED token — bounded upstream window; surfacing terminal upstream-degraded"
                        );
                        Err(PepError::AuthDegraded {
                            detail: format!(
                                "own-token userinfo rejected a JUST-MINTED token after re-mint \
                                 (upstream validation window, not a stale credential): \
                                 HTTP {status} for {userinfo_url}; upstream body: {body}"
                            ),
                            retryable: false,
                        })
                    }
                    Err(UserinfoFailure::Surfaced { detail, retryable }) => {
                        Err(PepError::AuthDegraded { detail, retryable })
                    }
                }
            }
            // Transient upstream (5xx/429/transport/malformed) or other 4xx:
            // not a token rejection — surface with the established
            // classification, no re-mint (foreign-token semantics preserved).
            Err(UserinfoFailure::Surfaced { detail, retryable }) => {
                Err(PepError::AuthDegraded { detail, retryable })
            }
        }
    }
}

/// One userinfo roundtrip, classified for the own-token composition
/// ([`ResourceServerClient::enrich_claims_with_userinfo_own_token`]).
///
/// `TokenRejected` = HTTP 400/401: the IdP says THIS bearer is invalid — the
/// only statuses that justify a re-mint ("400/401 on own-token enrichment",
/// order 8e50cbca). `Surfaced` = everything else, with the established
/// retryable classification (5xx/429/transport/malformed → `true`; other
/// 4xx → `false`). Rejection bodies are carried (truncated to
/// [`MAX_USERINFO_BODY_SNIPPET`] chars) so the next occurrence
/// self-describes.
enum UserinfoFailure {
    TokenRejected { status: u16, body: String },
    Surfaced { detail: String, retryable: bool },
}

const MAX_USERINFO_BODY_SNIPPET: usize = 200;

async fn userinfo_once(
    client: &Client,
    userinfo_url: &str,
    token: &str,
) -> std::result::Result<serde_json::Map<String, serde_json::Value>, UserinfoFailure> {
    let response = client
        .get(userinfo_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| UserinfoFailure::Surfaced {
            detail: format!("userinfo request failed ({}): {}", userinfo_url, e),
            retryable: true,
        })?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        let snippet: String = body_text.chars().take(MAX_USERINFO_BODY_SNIPPET).collect();
        if status.as_u16() == 400 || status.as_u16() == 401 {
            return Err(UserinfoFailure::TokenRejected {
                status: status.as_u16(),
                body: snippet,
            });
        }
        let retryable = status.is_server_error() || status.as_u16() == 429;
        return Err(UserinfoFailure::Surfaced {
            detail: format!(
                "userinfo returned HTTP {} for {}; upstream body: {}",
                status, userinfo_url, snippet
            ),
            retryable,
        });
    }

    response
        .json()
        .await
        .map_err(|e| UserinfoFailure::Surfaced {
            detail: format!("userinfo response malformed: {}", e),
            retryable: true,
        })
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