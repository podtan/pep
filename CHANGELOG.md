# Changelog

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
