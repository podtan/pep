# Changelog

## 0.5.8 — 2026-10-03

### Fixed

- **FAIL-CLOSED userinfo enrichment (breaking behavior change, owner FIX ORDER
  payam a77cd19c)**: `enrich_claims_with_userinfo` no longer swallows userinfo
  failures. Previously an HTTP error from the userinfo endpoint (400/401
  invalid_token mid-flight, 5xx) was logged and converted to `Ok(())`, so
  requests proceeded with NO groups/role — Cedar scoped to zero, filtered reads
  answered 200-empty (the "lying-empty" incident class: F1, F3, 365be03f) and
  downstream 401/degraded guards never fired. The swallow is dead.

### Added

- `PepError::AuthDegraded { detail, retryable }` — the distinguishable state
  between "userinfo returned no groups" and "we could not ask the userinfo
  endpoint". `PepError::is_auth_degraded()` and `PepError::retryable()`
  classifiers for guards that must not match exhaustively.
- `status_code()` mapping: `AuthDegraded` retryable → **503 SERVICE_UNAVAILABLE**
  (reads may retry), non-retryable → **401 UNAUTHORIZED** (terminal for the
  token → deny writes).
- Regression tests (`tests/userinfo_degraded.rs`) reproducing the incident wire:
  userinfo 400 / 503 / connection-refused mid-flight each surface
  `AuthDegraded` with correct retryability; healthy-200 enrichment and the
  groups-fast-path are unchanged.

### Upgrade / adoption notes (fame, tocpi, nghr, thq, trustee-api)

- **Adopt by crate bump only** (`pep = "0.5"`): no coordinated cutover, no
  required consumer code changes to receive the honest signal. Consumers that
  propagate `Result` from `enrich_claims_with_userinfo` now get fail-closed
  semantics automatically.
- **Guard activation**: middleware should classify with
  `err.is_auth_degraded()` and map `err.retryable()` → retryable 503-class
  response vs deny. `status_code()` already encodes this mapping.
- **trustee-api note**: its enrichment call site currently absorbs errors with
  an error-grade log (auth.rs ~L526) — the signal is now *visible and
  distinguishable* there; mapping it to 503/deny responses is trustee-api's own
  follow-up bump (separate Paydar-window event, per the blast-radius ruling).
- **Semver**: `PepError` is now `#[non_exhaustive]`; exhaustive `match`es must
  add a wildcard arm. Shipped as 0.5.8 (not 0.6.0) deliberately so consumers
  pinned to `pep = "0.5"` pick it up by bump — do not skip this reasoning in
  future releases.
- Caching (JWKS 1h TTL, userinfo per-token TTL) is unchanged; the bug was the
  swallow, not the cache.

## 0.5.7 — 2026-10-03

### Fixed

- **JWKS rotation resilience** (nghr c83a8215): after an IdP rotates its signing
  keys, tokens signed by the new `kid` were rejected with `No key found for
  kid` for up to 1 hour per process (the JWKS cache TTL) — restart was the only
  cure. `validate_jwt*` now force-refreshes the JWKS (bypassing the TTL) when
  the `kid` is missing from the cached keys, and retries the lookup once before
  failing. Field case: Kanidm key rotation locked out console/dispatch on a
  trustee node until process restart.
- Storm guard on forced refreshes: rate-limited per `jwks_uri` (minimum 30s
  between forced fetches, at most one forced fetch per validation). The guard
  timestamp is recorded on attempt, so fetch failures are rate-limited too.
  The 1h cache TTL is unchanged for the normal path.

### Added

- Regression tests (`tests/jwks_rotation.rs`) with an in-process mock IdP:
  key rotation mid-flight validates without restart; forced-fetch count is
  bounded (≤1) under a storm of unknown-kid tokens.

## 0.4.4 — 2026-07-22

### Added

- `WebSessionManager::force_refresh()` — force-refreshes a session's token,
  ignoring the in-memory cache. Used by callers when JWT validation fails
  with ExpiredSignature despite the session manager's expiry estimate saying
  there's time left (clock skew between servers).

### Changed

- Default `refresh_buffer_secs` increased from 60 → 120 seconds to give more
  margin against clock skew between the application server and the IdP.

## 0.4.3 — 2026-07-22

### Added

- `WebSessionManager` now tracks `last_accessed` per session for idle-timeout
  eviction. Sessions idle for longer than `idle_timeout_secs` (default: 1 hour)
  are automatically swept.
- Amortized idle-session sweep: when session count exceeds `sweep_threshold`
  (default: 64), `get_token()` triggers a cleanup pass that evicts all idle-
  expired entries. No background task needed.
- Builder methods: `with_idle_timeout(secs)`, `with_sweep_threshold(n)`.
- `WebSessionManager::session_count()` — returns current active session count.

### Changed

- `WebSessionManager` no longer uses the `TokenStore` trait internally — it
  has its own `HashMap<String, SessionEntry>` with access-time tracking.
  `InMemoryTokenStore` is kept for `TokenStore` trait compatibility (e.g.
  `InteractiveTokenProvider`).
- `with_store()` constructor removed — session lifecycle is self-contained.
- Cookie max-age should be set by callers to match `idle_timeout_secs`, not
  the refresh token lifetime.

## 0.4.2 — 2026-07-06

### Added

- `WebSessionManager` — server-side session manager for web applications.
  Maps opaque UUID session IDs to OAuth tokens with automatic refresh.
  When `get_token()` is called and the access token is near expiry (within
  a configurable buffer), it transparently refreshes via
  `OidcClient::refresh_access_token()` and updates the stored token.
- `InMemoryTokenStore` — in-memory `TokenStore` implementation using
  `std::sync::RwLock<HashMap>`. Designed for session data that does not
  need to survive process restarts.
- `WebSessionManager::create_session()` — stores tokens from a
  `TokenResponse`, returns a UUID session ID for use as a cookie value.
- `WebSessionManager::destroy_session()` — removes a session (logout).
- `WebSessionManager::with_store()` — constructor accepting a custom
  `Arc<dyn TokenStore>` backend for pluggable persistence.

### Changed

- `compute_expires_at()` and `seconds_until_expiry()` in `token_provider`
  are now `pub(crate)` so `session_manager` can reuse them.

## 0.4.1 — 2026-07-05

### Added

- `PkceCookieManager` — stateless PKCE state manager using HMAC-SHA256 signed
  cookies. Eliminates the need for in-memory state stores in multi-instance /
  load-balanced deployments. Any instance can handle the OIDC callback without
  shared state.
- `PkceSession` — result type containing `state`, `verifier`, and a signed
  `cookie_value` for use as an HttpOnly cookie.
- Cookie payload format: `base64url(state).base64url(verifier).base64url(expiry).base64url(hmac)`.
- New dependency: `hmac = "0.12"`.

### Changed

- `oidc::pkce_cookie` module re-exported at `pep::oidc::PkceCookieManager`,
  `pep::oidc_client::PkceCookieManager`.

## 0.4.0 — 2026-06-27

### Added

- `OidcClient::refresh_access_token()` — OAuth2 refresh token grant (RFC 6749 §6)
  for obtaining new access tokens without re-authentication.
- `TokenStore` trait + `FileTokenStore` — persistent token storage abstraction
  with JSON files at `~/.{agent}/tokens/{name}.json` (0600 permissions).
- `StoredToken` struct — serializable representation of an OAuth token pair
  (access + refresh) with `is_expired()` and `can_refresh()` helpers.
- `CallbackServer` — minimal one-shot HTTP server that listens on localhost for
  the OAuth authorization code redirect, with timeout and error handling.
- `AuthorizationCode` struct — the result type from `CallbackServer::wait_for_code()`.
- `InteractiveTokenProvider` — full implementation (was a stub). Loads tokens
  from a `TokenStore`, auto-refreshes expired tokens via `refresh_access_token()`,
  and caches results in memory. Returns helpful errors guiding users to
  `trustee mcp auth <name>` when not authenticated.
- `InteractiveConfig` gains `credential_name` field (used as `TokenStore` key).
- `PepError::TokenRefreshFailed { status, detail }` — new error variant for
  refresh token failures with HTTP status and response body.
- `epoch_to_rfc3339()` and `civil_to_epoch()` date conversion helpers
  (no `chrono` dependency needed).

### Changed

- `InteractiveTokenProvider::new()` → replaced by `with_store()` which accepts
  an `Arc<dyn TokenStore>`.
- `InteractiveConfig` now has `credential_name: String` field.
- `token-provider` feature flag now also enables `io` capability in tokio
  (needed by `CallbackServer`).
