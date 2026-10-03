//! Regression tests for JWKS rotation resilience (nghr c83a8215).
//!
//! Field failure: after an IdP rotates its signing key, tokens signed by the
//! new kid were rejected with `No key found for kid` for up to 1 hour per
//! process (JWKS cache TTL), because validation never re-fetched the JWKS on
//! an unknown kid. Fix: force-refresh (storm-guarded) on kid miss.
//!
//! These tests run a minimal in-process mock IdP (raw HTTP over tokio
//! TcpListener — no extra dev-dependencies) whose JWKS payload can be rotated
//! mid-flight, and assert:
//!   1. a token under a rotated kid validates WITHOUT restarting the process
//!   2. forced refreshes are storm-guarded (bounded fetch count)
#![cfg(feature = "oidc-resource-server")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use pep::oidc_resource_server::ResourceServerClient;

// Throwaway RSA-2048 keys generated solely for these tests. Never used anywhere.
const PRIV_KEY_A: &str = include_str!("keys/test_rsa_a.pem");
const PRIV_KEY_B: &str = include_str!("keys/test_rsa_b.pem");
const N_A_B64: &str = "vJ4e7b4haN0431Bu62qqL_XIhIMEgxf35drfjcxJ6kOn69iARtYz3jI5K-nNE9CM9x1-PDa53w_qgMUx8Wm46bOWPM3ns5DJjqhCIe2ZHLB_cobu8FMOnnkicTPh8_1bZfavOwBm1piwW3dGpW9DGfF7E7SD-yzAWZXllGCh1fOfuZ7kI5226fcV30vdJff3vqiYmI3U5bI3B6B8l0_wJfo_wHqpjJq_LicpI6fD24LU4wHyNqPBGRVC3Jo6WALG88ZJGx5O-5L9zUBeciG6GIHzGEY0I27q5Tjeh-YrolHhtaeLggkd2CTtzv-NBwSzapvVgCuN2TQMl9GFnMB8Fw";
const N_B_B64: &str = "hdbsBPNyjE3HwP_7eOFsK5reU2FoDsSZK0Q8_gREidGhzyFi3KZO48Hv1XnLOVkXh1vxZ1ebyYPFqlnL3Gq3lgvV5Ydkmt2CsWI3NLuNscULIrPBqIxIh8tLLvw3nncYQeDcKYwtOMbsdGn3zDQS7_5dMYMsDWPNCYto9VpAf682vrScmJukPNvVh65NFmrAqF_MdUBqCZmPSH7C8PfARXluTXQyXpQayqEWlwOov7erMV1AbVoVRNkkqh6s8pbnqS2a_Hn-W6hGe_uTRH7t6rUr4O1SaDhiqXoPiKPsHvyfecMm8Cjpn-7lFnEtz_WzBMjLg6Lza-nF3koigB2REQ";

struct MockIdp {
    iss: String,
    jwks: Arc<RwLock<String>>,
    jwks_fetches: Arc<AtomicUsize>,
}

fn jwks_doc(kid: &str, n_b64: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","n":"{n_b64}","e":"AQAB","alg":"RS256"}}]}}"#
    )
}

/// Spawn a mock IdP serving discovery + a rotatable JWKS document.
async fn spawn_mock_idp() -> MockIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let iss = format!("http://{addr}");
    let jwks_shared: Arc<RwLock<String>> = Arc::new(RwLock::new(jwks_doc("key-a", N_A_B64)));
    let fetches_shared: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    let state = Arc::new((Arc::clone(&jwks_shared), Arc::clone(&fetches_shared), iss.clone()));

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let state = state.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = Vec::with_capacity(1024);
                let mut chunk = [0u8; 1024];
                loop {
                    let n = match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if buf.len() > 16_384 {
                        return;
                    }
                }
                let req = String::from_utf8_lossy(&buf);
                let path = req.split_whitespace().nth(1).unwrap_or("/");
                let body = if path.starts_with("/jwks") {
                    state.1.fetch_add(1, Ordering::SeqCst);
                    state.0.read().unwrap().clone()
                } else if path.starts_with("/.well-known/openid-configuration") {
                    format!(r#"{{"issuer":"{}","jwks_uri":"{}/jwks"}}"#, state.2, state.2)
                } else {
                    r#"{"error":"not found"}"#.to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    MockIdp {
        iss,
        jwks: jwks_shared,
        jwks_fetches: fetches_shared,
    }
}

impl MockIdp {
    /// Rotate the served JWKS to a different key (different kid + keypair).
    fn rotate(&self, kid: &str, n_b64: &str) {
        *self.jwks.write().unwrap() = jwks_doc(kid, n_b64);
    }
}

fn sign_token(iss: &str, kid: &str, priv_pem: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let claims = serde_json::json!({
        "sub": "user-1",
        "iss": iss,
        "aud": "client",
        "iat": unix_now(),
        "exp": unix_now() + 3600,
    });
    let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).expect("valid test RSA PEM");
    encode(&header, &claims, &key).expect("sign test token")
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// The exact field case from nghr c83a8215: IdP rotates its signing key after
/// our JWKS cache was populated. A token under the NEW kid must validate
/// WITHOUT a process restart, via a single storm-guarded forced refresh.
#[tokio::test]
async fn rotated_kid_force_refreshes_and_validates_without_restart() {
    let idp = spawn_mock_idp().await;
    let rs = ResourceServerClient::new();

    // Warm the cache with key-a (JWKS fetch #1).
    let tok_a = sign_token(&idp.iss, "key-a", PRIV_KEY_A);
    let claims = rs.validate_jwt(&tok_a, &idp.iss, "client").await.expect("key-a token validates");
    assert_eq!(claims.sub, "user-1");
    assert_eq!(idp.jwks_fetches.load(Ordering::SeqCst), 1);

    // IdP rotates: JWKS now serves key-b only.
    idp.rotate("key-b", N_B_B64);
    let tok_b = sign_token(&idp.iss, "key-b", PRIV_KEY_B);

    // Pre-fix behavior: hard error `No key found for kid: key-b` (cached 1h).
    // Post-fix behavior: forced refresh + retry → validates.
    let claims = rs
        .validate_jwt(&tok_b, &idp.iss, "client")
        .await
        .expect("rotated kid must validate via forced refresh — no restart needed");
    assert_eq!(claims.sub, "user-1");

    // Exactly one forced refresh happened (JWKS fetch #2).
    assert_eq!(
        idp.jwks_fetches.load(Ordering::SeqCst),
        2,
        "expected exactly one forced refresh after rotation"
    );

    // And subsequent key-b tokens are served from the refreshed cache.
    let _ = rs.validate_jwt(&tok_b, &idp.iss, "client").await.expect("key-b now cached");
    assert_eq!(idp.jwks_fetches.load(Ordering::SeqCst), 2);
}

/// Storm guard: a burst of tokens with DISTINCT unknown kids must trigger at
/// most one forced refresh per guard window (30s), not one per token.
#[tokio::test]
async fn storm_guard_bounds_forced_fetches() {
    let idp = spawn_mock_idp().await;
    let rs = ResourceServerClient::new();

    // Warm the cache with key-a (fetch #1).
    let tok_a = sign_token(&idp.iss, "key-a", PRIV_KEY_A);
    rs.validate_jwt(&tok_a, &idp.iss, "client").await.expect("warm");

    // Rotate, then fire 5 tokens with distinct never-seen kids.
    idp.rotate("key-b", N_B_B64);
    for i in 0..5 {
        let tok = sign_token(&idp.iss, &format!("rot-{i}"), PRIV_KEY_B);
        let err = rs
            .validate_jwt(&tok, &idp.iss, "client")
            .await
            .expect_err("unknown kid must not validate even after forced refresh");
        assert!(
            err.to_string().contains("No key found for kid"),
            "unexpected error: {err}"
        );
    }

    // First miss forced one refresh (fetch #2); the storm guard held the rest.
    assert_eq!(
        idp.jwks_fetches.load(Ordering::SeqCst),
        2,
        "storm guard must bound forced fetches to one per window"
    );
}
