//! Wire tests for the per-token issuer fallback (0.5.16, issue 895cbcea —
//! CPO IdP cut-over re-arm condition 1, ruling 2026-10-31 option (a)).
//!
//! Field failure: pep's resource-server validated against exactly ONE
//! configured issuer (JWKS from its discovery doc only, `iss` enforced to
//! it). The IdP cut-over (petit pdt AUTH_ISSUER_URL → idm.podai.ir) would
//! have 401'd every idp.tanbal.ir-minted token twice over (iss mismatch AND
//! kid miss) and darkened the platform store's authz plane for the whole
//! Tanbal leaf.
//!
//! Fix under test: `ResourceServerClient::with_trusted_issuers` — a token
//! that FAILS against the configured issuer is retried ONCE against the
//! issuer named by its own `iss`, but ONLY if that issuer is allowlisted.
//! The retry runs FULL validation (signature via that issuer's discovery +
//! JWKS, exp, audience); any fallback failure returns the ORIGINAL error.
//! Empty allowlist (default) = byte-identical pre-0.5.16 behavior.
//!
//! Mock pattern: raw HTTP over tokio TcpListener, no extra dev-dependencies.
//! Each mock IdP serves discovery + a FIXED JWKS document; two throwaway
//! RSA-2048 keypairs (never used anywhere else).
#![cfg(feature = "oidc-resource-server")]

use std::sync::Arc;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use pep::oidc_resource_server::ResourceServerClient;

// Throwaway RSA-2048 keys generated solely for these tests. Never used anywhere.
const PRIV_KEY_A: &str = include_str!("keys/test_rsa_a.pem");
const PRIV_KEY_B: &str = include_str!("keys/test_rsa_b.pem");
const N_A_B64: &str = "vJ4e7b4haN0431Bu62qqL_XIhIMEgxf35drfjcxJ6kOn69iARtYz3jI5K-nNE9CM9x1-PDa53w_qgMUx8Wm46bOWPM3ns5DJjqhCIe2ZHLB_cobu8FMOnnkicTPh8_1bZfavOwBm1piwW3dGpW9DGfF7E7SD-yzAWZXllGCh1fOfuZ7kI5226fcV30vdJff3vqiYmI3U5bI3B6B8l0_wJfo_wHqpjJq_LicpI6fD24LU4wHyNqPBGRVC3Jo6WALG88ZJGx5O-5L9zUBeciG6GIHzGEY0I27q5Tjeh-YrolHhtaeLggkd2CTtzv-NBwSzapvVgCuN2TQMl9GFnMB8Fw";
const N_B_B64: &str = "hdbsBPNyjE3HwP_7eOFsK5reU2FoDsSZK0Q8_gREidGhzyFi3KZO48Hv1XnLOVkXh1vxZ1ebyYPFqlnL3Gq3lgvV5Ydkmt2CsWI3NLuNscULIrPBqIxIh8tLLvw3nncYQeDcKYwtOMbsdGn3zDQS7_5dMYMsDWPNCYto9VpAf682vrScmJukPNvVh65NFmrAqF_MdUBqCZmPSH7C8PfARXluTXQyXpQayqEWlwOov7erMV1AbVoVRNkkqh6s8pbnqS2a_Hn-W6hGe_uTRH7t6rUr4O1SaDhiqXoPiKPsHvyfecMm8Cjpn-7lFnEtz_WzBMjLg6Lza-nF3koigB2REQ";

struct MockIdp {
    iss: String,
}

fn jwks_doc(kid: &str, n_b64: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","n":"{n_b64}","e":"AQAB","alg":"RS256"}}]}}"#
    )
}

/// Spawn a mock IdP serving discovery + a FIXED JWKS document (one key).
async fn spawn_mock_idp(kid: &str, n_b64: &str) -> MockIdp {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let iss = format!("http://{addr}");
    let state = Arc::new((iss.clone(), jwks_doc(kid, n_b64)));

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
                    state.1.clone()
                } else if path.starts_with("/.well-known/openid-configuration") {
                    format!(r#"{{"issuer":"{}","jwks_uri":"{}/jwks"}}"#, state.0, state.0)
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

    MockIdp { iss }
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

/// Default posture unchanged (issue 895cbcea repro, both failure classes):
/// with an EMPTY allowlist a foreign-issuer token is rejected exactly as
/// before — kid-miss class AND iss-mismatch class — with NO fallback fetch.
#[tokio::test]
async fn foreign_issuer_token_rejected_by_default() {
    let idp_a = spawn_mock_idp("key-a", N_A_B64).await;
    let idp_b = spawn_mock_idp("key-b", N_B_B64).await;
    let rs = ResourceServerClient::new();

    // (a) kid-miss class: token signed by B's key, kid not in A's JWKS.
    let tok_b = sign_token(&idp_b.iss, "key-b", PRIV_KEY_B);
    let err = rs
        .validate_jwt(&tok_b, &idp_a.iss, "client")
        .await
        .expect_err("foreign token must be rejected with the empty allowlist");
    assert!(
        err.to_string().contains("No key found for kid"),
        "expected the kid-miss error, got: {err}"
    );

    // (b) iss-mismatch class: token signed by A's key (kid present at A) but
    // iss claims the foreign issuer.
    let tok_a_key_iss_b = sign_token(&idp_b.iss, "key-a", PRIV_KEY_A);
    let err = rs
        .validate_jwt(&tok_a_key_iss_b, &idp_a.iss, "client")
        .await
        .expect_err("iss mismatch must be rejected with the empty allowlist");
    assert!(
        err.to_string().contains("InvalidIssuer"),
        "expected InvalidIssuer, got: {err}"
    );
}

/// THE cut-over contract: with the old issuer allowlisted, a token minted by
/// it (own key, own iss) validates against a client configured for the NEW
/// issuer — via one full-validation fallback. Trailing slash on the
/// allowlist entry must normalize.
#[tokio::test]
async fn allowlisted_issuer_token_validates_via_fallback() {
    let idp_a = spawn_mock_idp("key-a", N_A_B64).await;
    let idp_b = spawn_mock_idp("key-b", N_B_B64).await;
    let rs = ResourceServerClient::new()
        .with_trusted_issuers(vec![format!("{}/", idp_b.iss)]);

    let tok_b = sign_token(&idp_b.iss, "key-b", PRIV_KEY_B);
    let claims = rs
        .validate_jwt(&tok_b, &idp_a.iss, "client")
        .await
        .expect("allowlisted old-issuer token must validate via fallback");
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.iss, idp_b.iss);
}

/// The allowlist BOUNDS the fallback: a foreign issuer NOT on it keeps the
/// configured-issuer error even though its key material would validate.
#[tokio::test]
async fn non_allowlisted_issuer_still_rejected() {
    let idp_a = spawn_mock_idp("key-a", N_A_B64).await;
    let idp_b = spawn_mock_idp("key-b", N_B_B64).await;
    // Issuer C serves A's key material but is NOT allowlisted.
    let idp_c = spawn_mock_idp("key-a", N_A_B64).await;
    let rs = ResourceServerClient::new()
        .with_trusted_issuers(vec![idp_b.iss.clone()]);

    let tok_c = sign_token(&idp_c.iss, "key-a", PRIV_KEY_A);
    let err = rs
        .validate_jwt(&tok_c, &idp_a.iss, "client")
        .await
        .expect_err("non-allowlisted issuer must stay rejected");
    assert!(
        err.to_string().contains("InvalidIssuer"),
        "expected the configured-issuer error to be preserved, got: {err}"
    );
}

/// The configured issuer stays primary: its own tokens pass without any
/// fallback involvement when an allowlist is present.
#[tokio::test]
async fn configured_issuer_tokens_unaffected_by_allowlist() {
    let idp_a = spawn_mock_idp("key-a", N_A_B64).await;
    let idp_b = spawn_mock_idp("key-b", N_B_B64).await;
    let rs = ResourceServerClient::new()
        .with_trusted_issuers(vec![idp_b.iss.clone()]);

    let tok_a = sign_token(&idp_a.iss, "key-a", PRIV_KEY_A);
    let claims = rs
        .validate_jwt(&tok_a, &idp_a.iss, "client")
        .await
        .expect("configured-issuer token must validate on the primary path");
    assert_eq!(claims.sub, "user-1");
}

/// Fail-closed: when the fallback itself fails (allowlisted issuer's JWKS
/// lacks the token's kid), the caller sees the ORIGINAL configured-issuer
/// error — never a synthesized pass, never the fallback's error.
#[tokio::test]
async fn fallback_failure_preserves_primary_error() {
    let idp_a = spawn_mock_idp("key-a", N_A_B64).await;
    let idp_b = spawn_mock_idp("key-b", N_B_B64).await;
    let rs = ResourceServerClient::new()
        .with_trusted_issuers(vec![idp_b.iss.clone()]);

    // iss = B (allowlisted → fallback fires) but signed by A's key, whose
    // kid lives at A (signature passes at A, iss fails) and NOT at B
    // (fallback kid-misses). Primary error must be what surfaces.
    let tok = sign_token(&idp_b.iss, "key-a", PRIV_KEY_A);
    let err = rs
        .validate_jwt(&tok, &idp_a.iss, "client")
        .await
        .expect_err("fallback failure must not produce a pass");
    assert!(
        err.to_string().contains("InvalidIssuer"),
        "expected the PRIMARY configured-issuer error, got: {err}"
    );
}
