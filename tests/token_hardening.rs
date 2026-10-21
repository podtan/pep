//! Token-provider hardening integration tests (pep 0.5.9, order payam ece49472).
//!
//! Three clauses under test:
//! 1. PROACTIVE REFRESH at T-90s: a token inside the horizon is never served
//!    from cache; a spawned refresher exchanges without caller pressure.
//! 2. UNIVERSAL 401 RETRY: `with_token_retry` re-mints + retries exactly once
//!    on 401 — reads AND writes; double-401 is terminal; non-401 untouched.
//! 3. REAL-EXP AUDIT: refreshed Interactive tokens persist the REAL JWT `exp`,
//!    not the `expires_in` estimate (nghr 849e7528 class).
//!
//! Incident wire being closed (nghr 374803e5): a long-idle process grabs a
//! token, the token dies mid-operation, and without re-mint the operation
//! fails with the error body parsed as an entity.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use pep::{
    with_token_retry, Attempt, InteractiveConfig, InteractiveTokenProvider, MemoryTokenStore,
    ServiceAccountConfig, ServiceAccountTokenProvider, StaticTokenProvider, StoredToken,
    TokenProvider, TokenStore,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Minimal unsigned-JWT minting (payload inspection only — no signature needed)
// ---------------------------------------------------------------------------

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// JWT with `exp` = now + `lifetime_secs` and a distinct `jti` per call.
fn mint_jwt(lifetime_secs: u64, jti: usize) -> String {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + lifetime_secs;
    let header = b64(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = b64(format!(r#"{{"exp":{exp},"jti":{jti}}}"#).as_bytes());
    format!("{header}.{payload}.sig")
}

// ---------------------------------------------------------------------------
// Mock IdP: discovery + token endpoints over a raw TcpListener (no new deps)
// ---------------------------------------------------------------------------

struct MockIdp {
    issuer: String,
    exchanges: Arc<AtomicUsize>,
    /// When set, POST /token answers 500 (IdP outage injection).
    fail_tokens: Arc<AtomicBool>,
    /// Lifetime of minted tokens (seconds from now).
    lifetime: Arc<AtomicU64>,
}

impl MockIdp {
    /// Spawn the mock IdP; returns handles. Serves forever until the process
    /// ends (port is unique per test, so leaks are harmless in tests).
    async fn spawn(lifetime_secs: u64) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let exchanges = Arc::new(AtomicUsize::new(0));
        let fail_tokens = Arc::new(AtomicBool::new(false));
        let lifetime = Arc::new(AtomicU64::new(lifetime_secs));

        let exchanges_task = exchanges.clone();
        let fail_task = fail_tokens.clone();
        let lifetime_task = lifetime.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let exchanges = exchanges_task.clone();
                let fail = fail_task.clone();
                let lifetime = lifetime_task.clone();
                tokio::spawn(async move {
                    // Accumulate chunks — a single read can split headers,
                    // and re-reading into the same buffer would clobber the
                    // early lines (Host!) with the tail.
                    let mut data = Vec::new();
                    loop {
                        let mut chunk = [0u8; 4096];
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(k) => {
                                data.extend_from_slice(&chunk[..k]);
                                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    if data.is_empty() {
                        return;
                    }
                    let req = String::from_utf8_lossy(&data).to_string();
                    let first_line = req.lines().next().unwrap_or("");
                    let is_token = first_line.starts_with("POST /token");
                    let body = if is_token {
                        // RFC 8693 token exchange: mint a distinct JWT.
                        // ONE increment per ATTEMPT (success or 500) — the
                        // tests assert exact counts.
                        exchanges.fetch_add(1, Ordering::SeqCst);
                        eprintln!("[MOCK] /token attempt #{}", exchanges.load(Ordering::SeqCst));
                        if fail.load(Ordering::SeqCst) {
                            let resp = "HTTP/1.1 500 Internal Server Error\r\n\
                                Content-Length: 5\r\nConnection: close\r\n\r\nidp-down";
                            let _ = sock.write_all(resp.as_bytes()).await;
                            let _ = sock.shutdown().await;
                            return;
                        }
                        let jti = exchanges.load(Ordering::SeqCst) - 1;
                        let jwt = mint_jwt(lifetime.load(Ordering::SeqCst), jti);
                        let content = format!(
                            r#"{{"access_token":"{jwt}","token_type":"Bearer","expires_in":900}}"#
                        );
                        http_ok(&content)
                    } else {
                        // Discovery document. `jwks_uri` is a REQUIRED field
                        // of OidcDiscoveryDocument — omitting it fails
                        // deserialization before any token POST happens.
                        let issuer_path = format!("http://{}", req_host(&req));
                        http_ok(&format!(
                            r#"{{"issuer":"{issuer_path}","jwks_uri":"{issuer_path}/jwks","token_endpoint":"{issuer_path}/token"}}"#
                        ))
                    };
                    let _ = sock.write_all(body.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        Self { issuer, exchanges, fail_tokens, lifetime }
    }

    fn exchange_count(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }

    /// Change the lifetime of subsequently minted tokens (seconds from now).
    fn set_lifetime(&self, secs: u64) {
        self.lifetime.store(secs, Ordering::SeqCst);
    }
}

fn req_host(req: &str) -> String {
    req.lines()
        .find_map(|l| {
            // hyper (reqwest's backend) writes header names LOWERCASE on the
            // wire — match case-insensitively.
            let (name, value) = l.split_once(':')?;
            if name.eq_ignore_ascii_case("host") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn http_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn svc_provider(idp: &MockIdp) -> ServiceAccountTokenProvider {
    ServiceAccountTokenProvider::new(ServiceAccountConfig {
        service_token: "svc-long-lived".to_string(),
        issuer_url: idp.issuer.clone(),
        client_id: "pdt-api".to_string(),
        client_secret: None,
        audience: "pdt-api".to_string(),
        scope: Some("openid profile".to_string()),
    })
}

// ---------------------------------------------------------------------------
// Clause 1: proactive refresh at T-90s
// ---------------------------------------------------------------------------

/// Incident wire: a cached token with <90s of life is NEVER served — the next
/// get_token exchanges first. Control: a healthy long-life token causes no churn.
#[tokio::test]
async fn t90_horizon_never_serves_a_dying_token() {
    let idp = MockIdp::spawn(200).await; // 200s life → cached remaining ≈ 80s < 90
    let provider = svc_provider(&idp);

    let tok1 = provider.get_token().await.unwrap();
    assert_eq!(idp.exchange_count(), 1);

    // Second call: cached token is inside the horizon (≈80s < 90s) →
    // must exchange, not serve.
    // From now on the IdP mints healthy 900s tokens.
    idp.set_lifetime(900);
    let tok2 = provider.get_token().await.unwrap();
    assert_eq!(idp.exchange_count(), 2, "dying token must not be served");
    assert_ne!(tok1, tok2, "retry must serve the NEW mint, not the dying one");

    // Control: the fresh long-life token is served repeatedly with no churn.
    let tok3 = provider.get_token().await.unwrap();
    let tok4 = provider.get_token().await.unwrap();
    assert_eq!(idp.exchange_count(), 2, "healthy token must not cause churn");
    assert_eq!(tok3, tok4);
}

/// The proactive refresher exchanges at the horizon WITHOUT any caller, so a
/// long-idle process always holds a live token (the exact 374803e5 posture:
/// activity does not trigger refresh — the provider must not need activity).
#[tokio::test]
async fn refresher_exchanges_without_caller_pressure() {
    let idp = MockIdp::spawn(200).await; // cached remaining ≈ 80s < 90 → refresher fires immediately
    let provider = svc_provider(&idp);

    let tok1 = provider.get_token().await.unwrap();
    assert_eq!(idp.exchange_count(), 1);

    // Future mints are healthy 900s tokens — otherwise the refresher would
    // churn forever on 200s mints that are born inside the horizon.
    idp.set_lifetime(900);
    let handle = provider.spawn_proactive_refresh();
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // The refresher exchanged at the horizon with NO get_token call.
    assert!(
        idp.exchange_count() >= 2,
        "refresher must exchange proactively, count={}",
        idp.exchange_count()
    );
    // The cache now holds the fresh token; get_token serves it without churn.
    let tok2 = provider.get_token().await.unwrap();
    assert_ne!(tok1, tok2);
    let after = idp.exchange_count();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(idp.exchange_count(), after, "fresh token must stop the churn");

    handle.abort();
}

/// Failure posture: while the IdP is down the refresher logs-and-backs-off
/// (never panics, never serves a lie) and get_token FAILS LOUD — fail-closed.
#[tokio::test]
async fn refresher_idp_outage_is_fail_loud_not_fail_silent() {
    let idp = MockIdp::spawn(900).await;
    idp.fail_tokens.store(true, Ordering::SeqCst);
    let provider = svc_provider(&idp);

    let handle = provider.spawn_proactive_refresh();
    tokio::time::sleep(Duration::from_millis(800)).await;

    // One failed exchange, then the task sits in backoff — alive, not panicking.
    assert!(!handle.is_finished(), "refresher must survive an IdP outage");
    assert_eq!(idp.exchange_count(), 1, "the failed attempt is counted");

    // get_token with no cache + dead IdP: loud error, never an empty success.
    let err = provider.get_token().await.unwrap_err();
    assert!(
        err.to_string().contains("Token exchange failed"),
        "expected loud exchange failure, got: {err}"
    );

    handle.abort();
}

// ---------------------------------------------------------------------------
// Clause 2: universal 401 retry — reads AND writes
//
// NOTE: token capture uses Rc<RefCell> deliberately — a std::sync::MutexGuard
// inside an async block can be captured by the generator and held across
// suspension, self-deadlocking single-threaded #[tokio::test] runtimes.
// with_token_retry imposes no Send bound, so Rc is legal here.
// ---------------------------------------------------------------------------

/// Incident wire: send-path 401 mid-materialization with NO re-mint. The
/// driver re-mints and retries ONCE, with a genuinely DIFFERENT token, and
/// the same posture applies to a POST (write) as to a GET (read).
#[tokio::test]
async fn universal_401_retry_re_mints_and_retries_once_writes_included() {
    let idp = MockIdp::spawn(900).await;
    let provider = svc_provider(&idp);
    let tok1 = provider.get_token().await.unwrap(); // seed the cache (jti 0)

    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let seen_w = seen.clone();
    let tok1_in = tok1.clone();
    // A "POST /messages" closure: first attempt (tok1) → 401; second → 200.
    let result: String = with_token_retry(&provider, move |token| {
        let seen = seen_w.clone();
        let stale = tok1_in.clone();
        async move {
            seen.borrow_mut().push(token.clone());
            if token == stale {
                Attempt::StaleToken // the server rejected the stale bearer
            } else {
                Attempt::Served(format!("created-with-{}", token))
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(seen.borrow().len(), 2, "exactly one retry");
    assert!(result.starts_with("created-with-"));
    assert_ne!(result, format!("created-with-{tok1}"), "retry must use the re-minted token");
    // The re-mint REALLY hit the IdP (invalidate → exchange), count=2.
    assert_eq!(idp.exchange_count(), 2, "401 must trigger a real re-mint");
    // And the retry used the NEW token, not the stale one.
    assert_ne!(seen.borrow()[0], seen.borrow()[1]);
}

/// A read (GET) takes the identical path — one driver, no read/write asymmetry.
#[tokio::test]
async fn universal_401_retry_reads_same_path() {
    let idp = MockIdp::spawn(900).await;
    let provider = svc_provider(&idp);
    let tok1 = provider.get_token().await.unwrap();

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_w = attempts.clone();
    let out: String = with_token_retry(&provider, move |token| {
        let attempts = attempts_w.clone();
        async move {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Attempt::StaleToken
            } else {
                Attempt::Served(token)
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_ne!(out, tok1);
}

/// Double-401: still rejected after a fresh mint → terminal AuthDegraded
/// (retryable=false). Bounded: exactly two attempts, never a third.
#[tokio::test]
async fn double_401_is_terminal_auth_degraded() {
    let idp = MockIdp::spawn(900).await;
    let provider = svc_provider(&idp);
    provider.get_token().await.unwrap();

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_w = attempts.clone();
    let err = with_token_retry(&provider, move |_| {
        let attempts = attempts_w.clone();
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            Attempt::<String>::StaleToken
        }
    })
    .await
    .unwrap_err();

    assert!(err.is_auth_degraded(), "double-401 must be AuthDegraded");
    assert!(!err.retryable(), "credential rejected ≠ retryable");
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "retry is bounded at one");
}

/// Non-401 failures pass through untouched and are never retried.
#[tokio::test]
async fn non_401_errors_pass_through_without_retry() {
    let idp = MockIdp::spawn(900).await;
    let provider = svc_provider(&idp);
    provider.get_token().await.unwrap();

    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_w = attempts.clone();
    let err = with_token_retry(&provider, move |_| {
        let attempts = attempts_w.clone();
        async move {
            attempts.fetch_add(1, Ordering::SeqCst);
            Attempt::<String>::Failed(pep::PepError::BadRequest("pdt 500-class".into()))
        }
    })
    .await
    .unwrap_err();

    assert!(err.to_string().contains("pdt 500-class"));
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "non-401 must not retry");
    assert_eq!(idp.exchange_count(), 1, "no re-mint for non-401");
}

/// Static providers (externally managed tokens) participate too: the driver
/// retries once; a static token legitimately comes back identical.
#[tokio::test]
async fn static_provider_participates_in_the_driver() {
    let provider = StaticTokenProvider::new("fixed-token".to_string());
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_w = attempts.clone();
    let out: String = with_token_retry(&provider, move |token| {
        let attempts = attempts_w.clone();
        async move {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Attempt::StaleToken
            } else {
                Attempt::Served(token)
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(out, "fixed-token");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

// ---------------------------------------------------------------------------
// Clause 3: real-exp audit — refreshed tokens persist the REAL exp
// ---------------------------------------------------------------------------

/// Incident wire (849e7528 class): the IdP says expires_in=900 but really
/// mints a 300s token. The STORED record must say 300s (real), not 900s
/// (estimate) — otherwise a restart resurrects an over-lived token.
#[tokio::test]
async fn interactive_refresh_persists_real_jwt_exp_not_estimate() {
    let idp = MockIdp::spawn(300).await; // real life: 300s; expires_in field: 900
    let store = Arc::new(MemoryTokenStore::new());

    // Seed an expired token WITH a refresh token so get_token takes the
    // refresh path.
    store
        .save(
            "kanidm_interactive",
            &StoredToken::new(
                "expired-access".to_string(),
                Some("refresh-token".to_string()),
                "Bearer",
                "2020-01-01T00:00:00Z", // long expired
                None,
            ),
        )
        .unwrap();

    let provider = InteractiveTokenProvider::with_store(
        InteractiveConfig {
            issuer_url: idp.issuer.clone(),
            client_id: "trustee-web".to_string(),
            client_secret: None,
            redirect_uri: "http://localhost:1/cb".to_string(),
            scope: "openid profile".to_string(),
            credential_name: "kanidm_interactive".to_string(),
        },
        store.clone(),
    );

    let fresh = provider.get_token().await.unwrap();
    assert_ne!(fresh, "expired-access", "refresh path must mint a new token");
    assert_eq!(idp.exchange_count(), 1);

    // The stored record now carries the REAL exp (≈ now+300), not the
    // expires_in estimate (≈ now+900).
    let saved = store.load("kanidm_interactive").unwrap().unwrap();
    let stored_epoch = parse_rfc3339(&saved.expires_at);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let real_exp = now + 300;
    let estimate = now + 900;
    assert!(
        stored_epoch.abs_diff(real_exp) <= 5,
        "stored expiry must be the REAL exp (~now+300), got {} (Δ {}s)",
        saved.expires_at,
        stored_epoch.abs_diff(real_exp)
    );
    assert!(
        stored_epoch.abs_diff(estimate) > 60,
        "stored expiry must NOT be the estimate (~now+900)"
    );
}

/// Minimal RFC-3339 Zulu parser (fixed format `YYYY-MM-DDTHH:MM:SSZ`).
fn parse_rfc3339(ts: &str) -> u64 {
    let (date, time) = ts.split_once('T').unwrap();
    let ymd: Vec<u64> = date.split('-').map(|p| p.parse().unwrap()).collect();
    let hms: Vec<u64> = time
        .trim_end_matches('Z')
        .split(':')
        .map(|p| p.parse().unwrap())
        .collect();
    let (y, m, d) = (ymd[0] as i64, ymd[1] as i64, ymd[2] as i64);
    let y_adj = if m <= 2 { y - 1 } else { y };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let mp = (if m > 2 { m - 3 } else { m + 9 }) as i64;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days as u64 * 86400 + hms[0] * 3600 + hms[1] * 60 + hms[2]
}

// ---------------------------------------------------------------------------
// 0.5.11 — single-flight mint (task 0b5df97e B3, S3 contract 2a4e7402):
// an N-way concurrent 401 storm must collapse into exactly ONE IdP exchange
// ---------------------------------------------------------------------------

/// 8-way concurrent `get_token` on an EMPTY cache: the mint gate serializes
/// the slow path and re-checks the cache after acquiring it, so exactly one
/// caller exchanges and the rest serve the freshly installed token.
#[tokio::test]
async fn storm_on_empty_cache_mints_exactly_once() {
    let idp = MockIdp::spawn(300).await;
    let provider = std::sync::Arc::new(svc_provider(&idp));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let p = provider.clone();
        handles.push(tokio::spawn(async move { p.get_token().await.unwrap() }));
    }
    let mut tokens = Vec::new();
    for h in handles {
        tokens.push(h.await.unwrap());
    }

    assert!(
        tokens.iter().all(|t| t == &tokens[0]),
        "every storm caller must be served the same fresh token"
    );
    assert_eq!(
        idp.exchange_count(),
        1,
        "8-way storm on an empty cache must collapse to ONE mint"
    );
}

/// 8-way concurrent `get_token` after `invalidate()` (the with_token_retry
/// reflex under concurrency): the re-mint generation also collapses to a
/// single exchange.
#[tokio::test]
async fn storm_after_invalidate_mints_exactly_once_per_generation() {
    let idp = MockIdp::spawn(300).await;
    let provider = std::sync::Arc::new(svc_provider(&idp));

    // Generation 1: prime the cache with a single mint.
    let _ = provider.get_token().await.unwrap();
    assert_eq!(idp.exchange_count(), 1);

    // Invalidate, then storm the reactive path.
    provider.invalidate().await;
    let mut handles = Vec::new();
    for _ in 0..8 {
        let p = provider.clone();
        handles.push(tokio::spawn(async move { p.get_token().await.unwrap() }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(
        idp.exchange_count(),
        2,
        "post-invalidate storm must collapse to ONE re-mint (total 2 across generations)"
    );
}
