//! Wire tests for the PDT-backed roles resolver (task 4c57b9c5,
//! workstream ffe7f9cc — IdP decouple).
//!
//! Contract under test (spec of record PDT 2fea489c + the binding 4-point
//! consumer contract on thread beb8041d):
//! 1. A service-account token with NO groups claim authorizes from PDT
//!    roles alone: JWT validates (authn), its stable `sub` keys ONE
//!    sub-keyed PDT query, and the answer (both role families) is the
//!    authorization data. No `groups` claim is read anywhere.
//! 2. PDT-down = deny: transport failure is `Unreachable` (fail closed),
//!    never an empty-authority `Ok`.
//! 3. Empty ≠ unreachable: 200-with-defaults (unknown/zero-role sub) is an
//!    authoritative least-privilege `Ok` — NOT an error.
//! 4. Short-TTL cache: the whole answer caches per `sub`; one upstream hit
//!    serves repeat resolves inside the TTL; expiry or explicit invalidate
//!    forces a fresh fetch.
//! 5. 5xx and sub-mismatch answers are `Unreachable` (deny) — a misbehaving
//!    PDT must never bind foreign authority.
#![cfg(feature = "token-provider")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use pep::oidc_resource_server::ResourceServerClient;
use pep::roles::{PdtRolesClient, PdtRolesError};

const PRIV_KEY_A: &str = include_str!("keys/test_rsa_a.pem");
const N_A_B64: &str = "vJ4e7b4haN0431Bu62qqL_XIhIMEgxf35drfjcxJ6kOn69iARtYz3jI5K-nNE9CM9x1-PDa53w_qgMUx8Wm46bOWPM3ns5DJjqhCIe2ZHLB_cobu8FMOnnkicTPh8_1bZfavOwBm1piwW3dGpW9DGfF7E7SD-yzAWZXllGCh1fOfuZ7kI5226fcV30vdJff3vqiYmI3U5bI3B6B8l0_wJfo_wHqpjJq_LicpI6fD24LU4wHyNqPBGRVC3Jo6WALG88ZJGx5O-5L9zUBeciG6GIHzGEY0I27q5Tjeh-YrolHhtaeLggkd2CTtzv-NBwSzapvVgCuN2TQMl9GFnMB8Fw";

// ---------------------------------------------------------------------------
// Combined mock: IdP (discovery + jwks) + PDT (/api/roles/{sub}, scripted)
// ---------------------------------------------------------------------------

struct MockStack {
    iss: String,
    /// Base URL of the same listener serving the PDT roles API.
    pdt_base: String,
    roles_script: Arc<Mutex<Vec<(u16, String)>>>,
    roles_calls: Arc<AtomicUsize>,
}

/// Script entries are consumed FRONT-first; empty script ⇒ healthy 200 with
/// membership for any sub.
async fn spawn_mock_stack(script: Vec<(u16, String)>) -> MockStack {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{addr}");
    let roles_script = Arc::new(Mutex::new(script));
    let roles_calls = Arc::new(AtomicUsize::new(0));

    let state = Arc::new((roles_script.clone(), roles_calls.clone(), base.clone()));

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

                let (status, body) = if path.starts_with("/api/roles/") {
                    // Count ATTEMPTS, before any branch (house mock law).
                    let n = state.1.fetch_add(1, Ordering::SeqCst);
                    let next = state.0.lock().expect("script lock").pop_front(n);
                    match next {
                        Some((code, body)) => (status_line(code), body),
                        None => (
                            "200 OK",
                            // Healthy PDT mood: both families, opaque strings.
                            r#"{"sub":"svc-1","global_role":"agent","membership":[{"workspace_id":"ws-a","role":"owner"}]}"#.to_string(),
                        ),
                    }
                } else if path.starts_with("/jwks") {
                    (
                        "200 OK",
                        format!(
                            r#"{{"keys":[{{"kty":"RSA","kid":"key-a","n":"{}","e":"AQAB","alg":"RS256"}}]}}"#,
                            N_A_B64
                        ),
                    )
                } else if path.starts_with("/.well-known/openid-configuration") {
                    let iss = &state.2;
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

    MockStack { iss: base.clone(), pdt_base: base, roles_script, roles_calls }
}

impl MockStack {
    fn roles_count(&self) -> usize {
        self.roles_calls.load(Ordering::SeqCst)
    }
}

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
        200 => "200 OK",
        404 => "404 Not Found",
        500 => "500 Internal Server Error",
        503 => "503 Service Unavailable",
        _ => "400 Bad Request",
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Signed JWT for sub `svc-1` with **NO groups claim** — the task's AC
/// token shape (authz must come from PDT, not claims).
fn sign_no_groups_token(iss: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("key-a".to_string());
    let claims = serde_json::json!({
        "sub": "svc-1",
        "iss": iss,
        "aud": "client",
        "iat": unix_now(),
        "exp": unix_now() + 3600,
    });
    let key = EncodingKey::from_rsa_pem(PRIV_KEY_A.as_bytes()).expect("valid test RSA PEM");
    encode(&header, &claims, &key).expect("sign test token")
}

// ---------------------------------------------------------------------------
// Pin 1: no-groups-claim token authorizes from PDT roles alone
// ---------------------------------------------------------------------------

/// The full AC wire: validate the token (authn, no groups anywhere in the
/// claims), take the stable `sub`, run ONE sub-keyed PDT query, and hold the
/// answer as the authorization data. Exactly one upstream roles call.
#[tokio::test]
async fn no_groups_claim_token_authorizes_from_pdt_roles_alone() {
    let stack = spawn_mock_stack(vec![]).await;
    let rs = ResourceServerClient::new();

    // Authn: the JWT validates against the configured issuer. Its claims
    // contain NO groups — asserting that shape here makes the pin honest.
    let token = sign_no_groups_token(&stack.iss);
    let claims = rs
        .validate_jwt(&token, &stack.iss, "client")
        .await
        .expect("no-groups-claim JWT must validate (authn is IdP-pluggable)");
    assert!(
        claims.extra.get("groups").is_none(),
        "fixture must carry no groups claim — the AC is authorization WITHOUT it"
    );

    // Authz data: PDT roles keyed by the validated sub.
    let pdt = PdtRolesClient::new(&stack.pdt_base);
    let roles = pdt
        .resolve_roles(&claims.sub)
        .await
        .expect("PDT roles must resolve for the validated sub");

    assert_eq!(roles.sub, "svc-1");
    assert_eq!(roles.global_role.as_deref(), Some("agent"));
    assert_eq!(roles.membership.len(), 1);
    assert_eq!(roles.membership[0].workspace_id, "ws-a");
    assert_eq!(roles.membership[0].role, "owner");
    assert_eq!(stack.roles_count(), 1, "exactly one sub-keyed PDT query (contract point 1)");
}

// ---------------------------------------------------------------------------
// Pin 2: PDT-down = deny (Unreachable, never an empty Ok)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pdt_down_is_unreachable_fail_closed() {
    // Nothing listens on this port: pure transport failure.
    let pdt = PdtRolesClient::new("http://127.0.0.1:1");
    let err = pdt
        .resolve_roles("svc-1")
        .await
        .expect_err("PDT-down must be Unreachable, never an empty-authority Ok");
    assert!(err.is_unreachable(), "transport failure classifies unreachable: {err}");
}

// ---------------------------------------------------------------------------
// Pin 3: empty ≠ unreachable — 200-with-defaults is least-privilege Ok
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_sub_200_defaults_is_least_privilege_not_error() {
    let stack = spawn_mock_stack(vec![(
        200,
        r#"{"sub":"svc-unknown","global_role":null,"membership":[]}"#.to_string(),
    )])
    .await;
    let pdt = PdtRolesClient::new(&stack.pdt_base);

    let roles = pdt
        .resolve_roles("svc-unknown")
        .await
        .expect("authoritative empty answer must be Ok (empty ≠ unreachable)");

    assert!(roles.is_empty_authority(), "zero roles = least privilege: {roles:?}");
    assert_eq!(stack.roles_count(), 1);
}

// ---------------------------------------------------------------------------
// Pin 4: short-TTL cache — one upstream hit inside TTL, fresh fetch after
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ttl_cache_serves_inside_window_and_expires() {
    let stack = spawn_mock_stack(vec![]).await;
    let pdt = PdtRolesClient::new(&stack.pdt_base).with_ttl(Duration::from_millis(120));

    let _ = pdt.resolve_roles("svc-1").await.expect("first resolve");
    let _ = pdt.resolve_roles("svc-1").await.expect("second resolve (cache)");
    assert_eq!(stack.roles_count(), 1, "repeat resolve inside TTL must hit the cache");

    // TTL expiry forces a fresh fetch.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let _ = pdt.resolve_roles("svc-1").await.expect("post-TTL resolve");
    assert_eq!(stack.roles_count(), 2, "TTL expiry must trigger a fresh sub-keyed query");
}

#[tokio::test]
async fn explicit_invalidate_forces_fresh_fetch() {
    let stack = spawn_mock_stack(vec![]).await;
    let pdt = PdtRolesClient::new(&stack.pdt_base); // default 30s TTL

    let _ = pdt.resolve_roles("svc-1").await.expect("first resolve");
    pdt.invalidate("svc-1").await;
    let _ = pdt.resolve_roles("svc-1").await.expect("post-invalidate resolve");
    assert_eq!(stack.roles_count(), 2, "invalidate must drop the cached answer");
}

// ---------------------------------------------------------------------------
// Pin 5: misbehaving PDT answers are Unreachable (deny), incl. sub-mismatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_500_is_unreachable() {
    let stack = spawn_mock_stack(vec![(500, r#"{"error":"boom"}"#.to_string())]).await;
    let pdt = PdtRolesClient::new(&stack.pdt_base);
    let err = pdt.resolve_roles("svc-1").await.expect_err("5xx must be Unreachable");
    assert!(err.is_unreachable());
}

#[tokio::test]
async fn sub_mismatch_answer_refuses_foreign_authority() {
    // A broken/malicious PDT answers for a DIFFERENT principal. The resolver
    // must refuse to bind that authority (fail closed, loud).
    let stack = spawn_mock_stack(vec![(
        200,
        r#"{"sub":"someone-else","global_role":"admin","membership":[{"workspace_id":"ws-x","role":"owner"}]}"#
            .to_string(),
    )])
    .await;
    let pdt = PdtRolesClient::new(&stack.pdt_base);
    let err = pdt
        .resolve_roles("svc-1")
        .await
        .expect_err("sub mismatch must never yield another principal's authority");
    assert!(err.is_unreachable(), "sub mismatch classifies unreachable: {err}");
}

#[tokio::test]
async fn path_escape_sub_never_reaches_the_wire() {
    let stack = spawn_mock_stack(vec![]).await;
    let pdt = PdtRolesClient::new(&stack.pdt_base);
    let err = pdt
        .resolve_roles("../../etc/passwd")
        .await
        .expect_err("path-escape sub must be rejected pre-wire");
    assert!(!err.is_unreachable());
    assert!(matches!(err, PdtRolesError::InvalidSub { .. }));
    assert_eq!(stack.roles_count(), 0, "invalid sub must not produce an upstream call");
}
