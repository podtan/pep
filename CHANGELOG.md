# Changelog

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
