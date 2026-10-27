//! Regression tests for the userinfo fail-closed contract (owner FIX ORDER,
//! payam a77cd19c, October 2026 — the "lying-empty" incident class).
//!
//! Incident wire being reproduced: JWT validates fine → userinfo endpoint
//! fails mid-flight (400/401 invalid_token, 5xx, connection refused) → OLD
//! behavior: pep swallowed the failure and returned Ok(()), so requests
//! proceeded with NO groups/role → Cedar scoped to zero → filtered reads
//! answered 200-empty and guards never fired.
//!
//! NEW contract: enrichment failures surface as `PepError::AuthDegraded`
//! (distinguishable from "empty userinfo"), `retryable()` classifies 503 vs
//! deny, and claims are never silently passed through.
#![cfg(feature = "oidc-resource-server")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use pep::oidc_resource_server::ResourceServerClient;
use pep::PepError;

// Same throwaway RSA test keys as tests/jwks_rotation.rs. Never used anywhere else.
const PRIV_KEY_A: &str = include_str!("keys/test_rsa_a.pem");
const N_A_B64: &str = "vJ4e7b4haN0431Bu62qqL_XIhIMEgxf35drfjcxJ6kOn69iARtYz3jI5K-nNE9CM9x1-PDa53w_qgMUx8Wm46bOWPM3ns5DJjqhCIe2ZHLB_cobu8FMOnnkicTPh8_1bZfavOwBm1piwW3dGpW9DGfF7E7SD-yzAWZXllGCh1fOfuZ7kI5226fcV30vdJff3vqiYmI3U5bI3B6B8l0_wJfo_wHqpjJq_LicpI6fD24LU4wHyNqPBGRVC3Jo6WALG88ZJGx5O-5L9zUBeciG6GIHzGEY0I27q5Tjeh-YrolHhtaeLggkd2CTtzv-NBwSzapvVgCuN2TQMl9GFnMB8Fw";

#[derive(Clone, Copy, PartialEq)]
enum UserinfoMode {
    /// 200 with groups — the healthy IdP.
    Ok200,
    /// 400 invalid_token — the exact mid-flight token blip from the incidents.
    Status400,
    /// 400 invalid_grant + session-supersession vocabulary — the IdP
    /// single-active-grant class (595f826d fix lane): the token is likely
    /// VALID, superseded by a later exchange.
    Status400Superseded,
    /// 503 — IdP briefly unavailable.
    Status503,
}

struct MockIdp {
    iss: String,
    mode: Arc<RwLock<UserinfoMode>>,
    userinfo_calls: Arc<AtomicUsize>,
}

async fn spawn_mock_idp(initial: UserinfoMode) -> MockIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let iss = format!("http://{addr}");
    let mode = Arc::new(RwLock::new(initial));
    let userinfo_calls = Arc::new(AtomicUsize::new(0));
    let state = Arc::new((Arc::clone(&mode), Arc::clone(&userinfo_calls), iss.clone()));

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
                let (status, body) = if path.starts_with("/userinfo") {
                    state.1.fetch_add(1, Ordering::SeqCst);
                    match *state.0.read().unwrap() {
                        UserinfoMode::Ok200 => (
                            "200 OK",
                            r#"{"sub":"user-1","groups":["admin"],"email":"user-1@tanbal"}"#.to_string(),
                        ),
                        UserinfoMode::Status400 => {
                            ("400 Bad Request", r#"{"error":"invalid_token"}"#.to_string())
                        }
                        UserinfoMode::Status400Superseded => (
                            "400 Bad Request",
                            r#"{"error":"invalid_grant","error_description":"oauth2 session superseded by a later exchange"}"#.to_string(),
                        ),
                        UserinfoMode::Status503 => {
                            ("503 Service Unavailable", r#"{"error":"temporarily_unavailable"}"#.to_string())
                        }
                    }
                } else if path.starts_with("/jwks") {
                    (
                        "200 OK",
                        format!(
                            r#"{{"keys":[{{"kty":"RSA","kid":"key-a","n":"{N_A_B64}","e":"AQAB","alg":"RS256"}}]}}"#
                        ),
                    )
                } else if path.starts_with("/.well-known/openid-configuration") {
                    let userinfo_url = format!("{}/userinfo", state.2);
                    (
                        "200 OK",
                        format!(
                            r#"{{"issuer":"{}","jwks_uri":"{}/jwks","userinfo_endpoint":"{}"}}"#,
                            state.2, state.2, userinfo_url
                        ),
                    )
                } else {
                    ("404 Not Found", r#"{"error":"not found"}"#.to_string())
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
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
        mode,
        userinfo_calls,
    }
}

impl MockIdp {
    fn set_mode(&self, m: UserinfoMode) {
        *self.mode.write().unwrap() = m;
    }
}

fn sign_token(iss: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("key-a".to_string());
    let claims = serde_json::json!({
        "sub": "user-1",
        "iss": iss,
        "aud": "client",
        "iat": unix_now(),
        "exp": unix_now() + 3600,
    });
    let key = EncodingKey::from_rsa_pem(PRIV_KEY_A.as_bytes()).expect("valid test RSA PEM");
    encode(&header, &claims, &key).expect("sign test token")
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

async fn validated_claims(rs: &ResourceServerClient, idp: &MockIdp, token: &str) -> pep::oidc::types::JwtClaims {
    rs.validate_jwt(token, &idp.iss, "client").await.expect("token must validate (JWKS path is healthy)")
}

/// THE incident wire: userinfo returns 400 invalid_token mid-flight.
/// OLD behavior: Ok(()) — request proceeded with no groups (200-empty lies).
/// NEW behavior: Err(AuthDegraded), retryable=false (terminal for this token).
#[tokio::test]
async fn userinfo_400_invalid_token_is_auth_degraded_non_retryable() {
    let idp = spawn_mock_idp(UserinfoMode::Status400).await;
    let rs = ResourceServerClient::new();
    let token = sign_token(&idp.iss);

    let mut claims = validated_claims(&rs, &idp, &token).await;
    let err = rs
        .enrich_claims_with_userinfo(&mut claims, &token, &idp.iss, None)
        .await
        .expect_err("the swallow is dead: userinfo 400 must NOT return Ok");
    assert!(err.is_auth_degraded(), "must be distinguishable: {err}");
    assert!(!err.retryable(), "400 invalid_token is terminal → deny, not 503");
    // And the lie is structurally impossible: claims never gain silent emptiness.
    assert!(claims.extra.get("groups").is_none());
    // 0.5.14 attribution-only enrichment: the body is carried, but the
    // GENERIC invalid_token body must NOT name the supersession class —
    // mis-attribution on ordinary dead bearers would be a new lying class.
    let detail = format!("{err}");
    assert!(
        detail.contains("invalid_token"),
        "upstream body must be carried into the detail: {detail}"
    );
    assert!(
        !detail.contains("superseded by a later"),
        "generic invalid_token must NOT carry the supersession attribution: {detail}"
    );
}

/// The 595f826d fix lane (CPO ruling 2026-10-27, leg 4): a 400 body that
/// identifies the IdP single-active-grant session-supersession class
/// (invalid_grant + "session superseded by a later exchange") gets the
/// attribution NAMED in the terminal detail — token likely VALID, re-mint
/// heals, lifecycle not at fault. Classification unchanged: still terminal.
#[tokio::test]
async fn userinfo_400_superseded_session_names_the_class() {
    let idp = spawn_mock_idp(UserinfoMode::Status400Superseded).await;
    let rs = ResourceServerClient::new();
    let token = sign_token(&idp.iss);

    let mut claims = validated_claims(&rs, &idp, &token).await;
    let err = rs
        .enrich_claims_with_userinfo(&mut claims, &token, &idp.iss, None)
        .await
        .expect_err("fail-closed contract unchanged: superseded-session 400 still denies");
    assert!(err.is_auth_degraded(), "same AuthDegraded variant: {err}");
    assert!(!err.retryable(), "classification unchanged: terminal → deny");
    assert!(claims.extra.get("groups").is_none(), "claims never gain silent emptiness");
    let detail = format!("{err}");
    assert!(
        detail.contains("invalid_grant"),
        "upstream body must be carried into the detail: {detail}"
    );
    assert!(
        detail.contains("superseded by a later"),
        "supersession class must be NAMED when the body identifies it: {detail}"
    );
    assert!(
        detail.contains("re-mint heals"),
        "attribution must state the heal path: {detail}"
    );
}

/// IdP briefly down (503): degraded AND retryable — maps to 503-class, not deny.
#[tokio::test]
async fn userinfo_503_is_auth_degraded_retryable() {
    let idp = spawn_mock_idp(UserinfoMode::Status503).await;
    let rs = ResourceServerClient::new();
    let token = sign_token(&idp.iss);

    let mut claims = validated_claims(&rs, &idp, &token).await;
    let err = rs
        .enrich_claims_with_userinfo(&mut claims, &token, &idp.iss, None)
        .await
        .expect_err("503 must surface as AuthDegraded");
    assert!(err.is_auth_degraded());
    assert!(err.retryable(), "5xx is transient → retryable 503-class");
    assert!(claims.extra.get("groups").is_none());
}

/// Connection refused (no listener behind userinfo_endpoint): degraded, retryable.
#[tokio::test]
async fn userinfo_connection_refused_is_auth_degraded_retryable() {
    let idp = spawn_mock_idp(UserinfoMode::Ok200).await;
    let rs = ResourceServerClient::new();
    let token = sign_token(&idp.iss);

    // Born-dead port: bind, read the address, drop the listener.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let dead_addr = dead.local_addr().expect("addr");
    drop(dead);

    let mut claims = validated_claims(&rs, &idp, &token).await;
    let err = rs
        .enrich_claims_with_userinfo(&mut claims, &token, &idp.iss, Some(&format!("http://{dead_addr}/userinfo")))
        .await
        .expect_err("connection refused must surface as AuthDegraded");
    assert!(err.is_auth_degraded());
    assert!(err.retryable(), "transport failures are transient");
    assert!(claims.extra.get("groups").is_none());
}

/// Control: healthy IdP → enrichment still works end-to-end (no behavior change
/// on the happy path; caching untouched).
#[tokio::test]
async fn userinfo_success_still_merges_groups() {
    let idp = spawn_mock_idp(UserinfoMode::Ok200).await;
    let rs = ResourceServerClient::new();
    let token = sign_token(&idp.iss);

    let mut claims = validated_claims(&rs, &idp, &token).await;
    rs.enrich_claims_with_userinfo(&mut claims, &token, &idp.iss, None)
        .await
        .expect("healthy userinfo must enrich");
    assert_eq!(
        claims.extra.get("groups").and_then(|g| g.as_array()).map(|a| a.len()),
        Some(1)
    );
    assert!(idp.userinfo_calls.load(Ordering::SeqCst) >= 1);
}

/// Control: fast path — claims already carry groups → no userinfo call at all.
#[tokio::test]
async fn fast_path_skips_userinfo_when_groups_present() {
    let idp = spawn_mock_idp(UserinfoMode::Ok200).await;
    let rs = ResourceServerClient::new();
    let token = sign_token(&idp.iss);

    let mut claims = validated_claims(&rs, &idp, &token).await;
    claims
        .extra
        .insert("groups".to_string(), serde_json::json!(["pre-existing"]));
    rs.enrich_claims_with_userinfo(&mut claims, &token, &idp.iss, None)
        .await
        .expect("fast path must stay Ok");
    assert_eq!(idp.userinfo_calls.load(Ordering::SeqCst), 0, "fast path must not call userinfo");
}
