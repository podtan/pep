//! Regression tests for the own-token enrichment composition
//! (nghr 9ee826c2, owner FIX ORDER payam 8e50cbca, 2026-10-20).
//!
//! Incident wire being closed: the payam→PDT store-write leg 401'd for ~6.5
//! minutes on 2026-10-20 while the provider re-minted EIGHT times — fresh
//! ~900s tokens rejected within ~40ms of mint (journal 711f2688), then the
//! SAME generation succeeded 69s later with no new mint. Two facts follow:
//! (1) a rejected own token needs invalidate → re-mint → VALIDATE-the-fresh-
//! token → retry once; (2) re-mint alone is insufficient — a fresh token
//! rejected at the validation leg means the defect is UPSTREAM and must
//! surface terminal-loud, never as a burned send.
//!
//! Pins under test:
//! 1. Expired/rejected own token → re-mint + fresh-token validation → retry
//!    once → success (the heal path).
//! 2. Fresh-valid token STILL rejected after re-mint → terminal
//!    AuthDegraded carrying the upstream body (the caller cannot proceed —
//!    "never a burned send"; double-failure stays terminal).
//! 3. Foreign-token path (`enrich_claims_with_userinfo`) is byte-identical:
//!    400 stays terminal, no re-mint, no new behavior.
//! 4. Happy path: single mint, single userinfo call, no churn.
//! 5. 5xx is not a token rejection: no re-mint, retryable 503-class.
//! 6. Fast path (groups present): no mint, no userinfo call at all.
#![cfg(all(feature = "oidc-resource-server", feature = "token-provider"))]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use pep::oidc_resource_server::ResourceServerClient;
use pep::{ServiceAccountConfig, ServiceAccountTokenProvider, TokenProvider};

// Same throwaway RSA test key as tests/userinfo_degraded.rs (JWKS path only).
const PRIV_KEY_A: &str = include_str!("keys/test_rsa_a.pem");
const N_A_B64: &str = "vJ4e7b4haN0431Bu62qqL_XIhIMEgxf35drfjcxJ6kOn69iARtYz3jI5K-nNE9CM9x1-PDa53w_qgMUx8Wm46bOWPM3ns5DJjqhCIe2ZHLB_cobu8FMOnnkicTPh8_1bZfavOwBm1piwW3dGpW9DGfF7E7SD-yzAWZXllGCh1fOfuZ7kI5226fcV30vdJff3vqiYmI3U5bI3B6B8l0_wJfo_wHqpjJq_LicpI6fD24LU4wHyNqPBGRVC3Jo6WALG88ZJGx5O-5L9zUBeciG6GIHzGEY0I27q5Tjeh-YrolHhtaeLggkd2CTtzv-NBwSzapvVgCuN2TQMl9GFnMB8Fw";

// ---------------------------------------------------------------------------
// Mock IdP: discovery + jwks + userinfo (scripted) + POST /token (RFC 8693)
// ---------------------------------------------------------------------------

struct MockIdp {
    iss: String,
    /// Scripted userinfo responses, consumed front-first. Empty script ⇒
    /// healthy 200 with groups (the default IdP mood).
    userinfo_script: Arc<Mutex<Vec<(u16, String)>>>,
    userinfo_calls: Arc<AtomicUsize>,
    exchanges: Arc<AtomicUsize>,
}

async fn spawn_mock_idp(script: Vec<(u16, String)>) -> MockIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let iss = format!("http://{addr}");
    let userinfo_script = Arc::new(Mutex::new(script));
    let userinfo_calls = Arc::new(AtomicUsize::new(0));
    let exchanges = Arc::new(AtomicUsize::new(0));

    let state = Arc::new((
        userinfo_script.clone(),
        userinfo_calls.clone(),
        exchanges.clone(),
        iss.clone(),
    ));

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let state = state.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Accumulate chunks — never re-read into the same buffer
                // (clobbers early headers with the tail).
                let mut buf = Vec::with_capacity(2048);
                let mut chunk = [0u8; 2048];
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
                let first_line = req.lines().next().unwrap_or("");
                let path = first_line.split_whitespace().nth(1).unwrap_or("/");

                let (status, body) = if first_line.starts_with("POST /token") {
                    // RFC 8693: mint a DISTINCT JWT per attempt (counting
                    // every ATTEMPT, before any branch).
                    let n = state.2.fetch_add(1, Ordering::SeqCst);
                    let exp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("clock")
                        .as_secs()
                        + 900;
                    let header = base64_url(br#"{"alg":"none","typ":"JWT"}"#);
                    let payload = base64_url(format!(r#"{{"exp":{exp},"jti":"mint-{n}"}}"#).as_bytes());
                    let jwt = format!("{header}.{payload}.sig");
                    let content = format!(
                        r#"{{"access_token":"{jwt}","token_type":"Bearer","expires_in":900}}"#
                    );
                    ("200 OK", content)
                } else if path.starts_with("/userinfo") {
                    let n = state.1.fetch_add(1, Ordering::SeqCst);
                    let next = state.0.lock().expect("script lock").pop_front(n);
                    match next {
                        Some((code, body)) => (status_line(code), body),
                        None => (
                            "200 OK",
                            r#"{"sub":"user-1","groups":["admin"],"role":"writer"}"#.to_string(),
                        ),
                    }
                } else if path.starts_with("/jwks") {
                    (
                        "200 OK",
                        format!(
                            r#"{{"keys":[{{"kty":"RSA","kid":"key-a","n":"{N_A_B64}","e":"AQAB","alg":"RS256"}}]}}"#
                        ),
                    )
                } else if path.starts_with("/.well-known/openid-configuration") {
                    let iss = &state.3;
                    (
                        "200 OK",
                        format!(
                            r#"{{"issuer":"{iss}","jwks_uri":"{iss}/jwks","token_endpoint":"{iss}/token","userinfo_endpoint":"{iss}/userinfo"}}"#
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

    MockIdp { iss, userinfo_script, userinfo_calls, exchanges }
}

impl MockIdp {
    fn userinfo_count(&self) -> usize {
        self.userinfo_calls.load(Ordering::SeqCst)
    }
    fn exchange_count(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }
}

/// Script entries are consumed FRONT-first (FILO would make the fixtures
/// unreadable).
trait PopFront {
    fn pop_front(&mut self, _n: usize) -> Option<(u16, String)>;
}
impl PopFront for Vec<(u16, String)> {
    fn pop_front(&mut self, _n: usize) -> Option<(u16, String)> {
        if self.is_empty() {
            None
        } else {
            Some(self.remove(0))
        }
    }
}

fn status_line(code: u16) -> &'static str {
    match code {
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        403 => "403 Forbidden",
        503 => "503 Service Unavailable",
        _ => "500 Internal Server Error",
    }
}

fn base64_url(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Signed user JWT (aud "client", kid key-a) — validates via the mock JWKS.
fn sign_user_token(iss: &str) -> String {
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

fn svc_provider(idp: &MockIdp) -> ServiceAccountTokenProvider {
    ServiceAccountTokenProvider::new(ServiceAccountConfig {
        service_token: "svc-long-lived".to_string(),
        issuer_url: idp.iss.clone(),
        client_id: "pdt-api".to_string(),
        client_secret: None,
        audience: "pdt-api".to_string(),
        scope: Some("openid profile".to_string()),
    })
}

async fn user_claims(rs: &ResourceServerClient, idp: &MockIdp) -> pep::oidc::types::JwtClaims {
    let token = sign_user_token(&idp.iss);
    rs.validate_jwt(&token, &idp.iss, "client")
        .await
        .expect("user JWT must validate (JWKS path is healthy)")
}

const INVALID_TOKEN_400: &str = r#"{"error":"invalid_token"}"#;

// ---------------------------------------------------------------------------
// Pin 1: the heal path — rejected own token → re-mint → validate fresh → Ok
// ---------------------------------------------------------------------------

/// Incident wire, healed: first userinfo call answers 400 invalid_token (the
/// cached bearer is IdP-expired despite local freshness). The composition
/// must invalidate, RE-MINT (exchange #2), validate the fresh credential
/// with the retry userinfo call, and succeed. Exactly 2 mints, 2 userinfo
/// calls, groups merged.
#[tokio::test]
async fn rejected_own_token_remints_validates_and_succeeds() {
    let idp = spawn_mock_idp(vec![
        (400, INVALID_TOKEN_400.to_string()),
    ])
    .await;
    let provider = svc_provider(&idp);
    let rs = ResourceServerClient::new();

    let mut claims = user_claims(&rs, &idp).await;
    rs.enrich_claims_with_userinfo_own_token(&provider, &mut claims, &idp.iss, None)
        .await
        .expect("re-mint + fresh-token validation must heal the rejected own token");

    assert_eq!(
        claims.extra.get("groups").and_then(|g| g.as_array()).map(|a| a.len()),
        Some(1),
        "groups must come from the RETRY userinfo call"
    );
    assert_eq!(idp.exchange_count(), 2, "initial mint + re-mint");
    assert_eq!(idp.userinfo_count(), 2, "rejected leg + fresh-token validation leg");
}

// ---------------------------------------------------------------------------
// Pin 2: fresh token rejected too → terminal loud, never a burned send
// ---------------------------------------------------------------------------

/// The 711f2688 wire: even a JUST-MINTED token is rejected (bounded upstream
/// validation window). The composition must surface TERMINAL AuthDegraded
/// carrying the upstream body — the caller sees Err and cannot proceed to
/// burn the real operation; silent success is structurally impossible.
#[tokio::test]
async fn fresh_token_rejected_upstream_is_terminal_loud() {
    let upstream_body = r#"{"error":"invalid_token","error_description":"session propagation window"}"#.to_string();
    let idp = spawn_mock_idp(vec![
        (400, INVALID_TOKEN_400.to_string()),
        (400, upstream_body.clone()),
    ])
    .await;
    let provider = svc_provider(&idp);
    let rs = ResourceServerClient::new();

    let mut claims = user_claims(&rs, &idp).await;
    let err = rs
        .enrich_claims_with_userinfo_own_token(&provider, &mut claims, &idp.iss, None)
        .await
        .expect_err("a fresh token rejected at the validation leg must NOT succeed");

    assert!(err.is_auth_degraded(), "must be the fail-closed class: {err}");
    assert!(
        !err.retryable(),
        "terminal: hammering an upstream validation window will not help — deny, never retry-burn"
    );
    let detail = format!("{err}");
    assert!(
        detail.contains("JUST-MINTED"),
        "must self-describe as the upstream-window class: {detail}"
    );
    assert!(
        detail.contains("session propagation window"),
        "upstream rejection body must be carried into the surfacing: {detail}"
    );
    assert!(claims.extra.get("groups").is_none(), "claims never gain silent emptiness");
    assert_eq!(idp.exchange_count(), 2, "re-mint DID happen — and STILL terminal");
    assert_eq!(idp.userinfo_count(), 2, "fresh-token validation happened — and STILL terminal");
}

/// 595f826d fix lane (CPO ruling 2026-10-27, leg 4): a SECOND-leg rejection
/// whose body identifies the IdP single-active-grant session-supersession
/// class names it in the terminal detail — the operator sees WHY the
/// just-minted token died (superseded by a later exchange) and that the
/// token lifecycle is not at fault. Terminal classification unchanged.
#[tokio::test]
async fn fresh_token_rejected_superseded_body_names_the_class() {
    let superseded_body = r#"{"error":"invalid_grant","error_description":"removing orphaned oauth2 session"}"#.to_string();
    let idp = spawn_mock_idp(vec![
        (400, INVALID_TOKEN_400.to_string()),
        (400, superseded_body.clone()),
    ])
    .await;
    let provider = svc_provider(&idp);
    let rs = ResourceServerClient::new();

    let mut claims = user_claims(&rs, &idp).await;
    let err = rs
        .enrich_claims_with_userinfo_own_token(&provider, &mut claims, &idp.iss, None)
        .await
        .expect_err("fail-closed contract unchanged: second-leg 400 still terminal");

    assert!(err.is_auth_degraded(), "same AuthDegraded variant: {err}");
    assert!(!err.retryable(), "classification unchanged: terminal, never retry-burn");
    let detail = format!("{err}");
    assert!(
        detail.contains("JUST-MINTED"),
        "still self-describes as the upstream-window class: {detail}"
    );
    assert!(
        detail.contains("invalid_grant"),
        "upstream body still carried: {detail}"
    );
    assert!(
        detail.contains("superseded by a later"),
        "supersession class must be NAMED when the body identifies it: {detail}"
    );
    assert!(
        detail.contains("token lifecycle not at fault"),
        "attribution must clear the token lifecycle: {detail}"
    );
    assert!(claims.extra.get("groups").is_none());
    assert_eq!(idp.exchange_count(), 2);
    assert_eq!(idp.userinfo_count(), 2);
}

// ---------------------------------------------------------------------------
// Pin 3: foreign-token path is byte-identical (no re-mint, terminal on 400)
// ---------------------------------------------------------------------------

/// The old API must be untouched: given the same 400 wire it stays terminal
/// with NO re-mint and NO second userinfo call — one exchange (minting the
/// bearer string), one userinfo call, done.
#[tokio::test]
async fn foreign_token_path_unchanged_no_remint() {
    let idp = spawn_mock_idp(vec![(400, INVALID_TOKEN_400.to_string())]).await;
    let provider = svc_provider(&idp);
    let rs = ResourceServerClient::new();

    // Obtain a bearer the way a foreign caller would hold one.
    let bearer = provider.get_token().await.expect("mint");
    assert_eq!(idp.exchange_count(), 1);

    let mut claims = user_claims(&rs, &idp).await;
    let err = rs
        .enrich_claims_with_userinfo(&mut claims, &bearer, &idp.iss, None)
        .await
        .expect_err("foreign-token 400 stays terminal — unchanged contract");

    assert!(err.is_auth_degraded());
    assert!(!err.retryable(), "400 invalid_token is terminal for a foreign bearer");
    assert!(claims.extra.get("groups").is_none());
    assert_eq!(idp.exchange_count(), 1, "the old API must NOT re-mint — no provider, no churn");
    assert_eq!(idp.userinfo_count(), 1, "the old API must NOT retry the userinfo leg");
}

// ---------------------------------------------------------------------------
// Pin 4: happy path — single mint, single call, no churn
// ---------------------------------------------------------------------------

#[tokio::test]
async fn own_token_happy_path_single_mint_no_churn() {
    let idp = spawn_mock_idp(vec![]).await;
    let provider = svc_provider(&idp);
    let rs = ResourceServerClient::new();

    let mut claims = user_claims(&rs, &idp).await;
    rs.enrich_claims_with_userinfo_own_token(&provider, &mut claims, &idp.iss, None)
        .await
        .expect("healthy IdP must enrich in one leg");

    assert_eq!(
        claims.extra.get("groups").and_then(|g| g.as_array()).map(|a| a.len()),
        Some(1)
    );
    assert_eq!(claims.extra.get("role").and_then(|r| r.as_str()), Some("writer"));
    assert_eq!(idp.exchange_count(), 1, "healthy path: exactly one mint");
    assert_eq!(idp.userinfo_count(), 1, "healthy path: exactly one userinfo call");
}

// ---------------------------------------------------------------------------
// Pin 5: 5xx is NOT a token rejection — no re-mint, retryable 503-class
// ---------------------------------------------------------------------------

#[tokio::test]
async fn own_token_5xx_surfaces_retryable_without_remint() {
    let idp = spawn_mock_idp(vec![(503, r#"{"error":"temporarily_unavailable"}"#.to_string())]).await;
    let provider = svc_provider(&idp);
    let rs = ResourceServerClient::new();

    let mut claims = user_claims(&rs, &idp).await;
    let err = rs
        .enrich_claims_with_userinfo_own_token(&provider, &mut claims, &idp.iss, None)
        .await
        .expect_err("5xx must surface, never swallow");

    assert!(err.is_auth_degraded());
    assert!(err.retryable(), "5xx is transient → 503-class, not deny");
    assert_eq!(idp.exchange_count(), 1, "5xx is not a token rejection — no re-mint");
    assert_eq!(idp.userinfo_count(), 1, "no retry leg on a non-rejection failure");
    assert!(claims.extra.get("groups").is_none());
}

// ---------------------------------------------------------------------------
// Pin 6: fast path — groups present ⇒ no mint, no userinfo call at all
// ---------------------------------------------------------------------------

#[tokio::test]
async fn own_token_fast_path_skips_mint_and_userinfo() {
    let idp = spawn_mock_idp(vec![]).await;
    let provider = svc_provider(&idp);
    let rs = ResourceServerClient::new();

    let mut claims = user_claims(&rs, &idp).await;
    claims
        .extra
        .insert("groups".to_string(), serde_json::json!(["pre-existing"]));

    rs.enrich_claims_with_userinfo_own_token(&provider, &mut claims, &idp.iss, None)
        .await
        .expect("fast path must stay Ok");

    assert_eq!(idp.exchange_count(), 0, "fast path must not even mint");
    assert_eq!(idp.userinfo_count(), 0, "fast path must not call userinfo");
}
