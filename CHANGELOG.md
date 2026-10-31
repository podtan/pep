# Changelog

## 0.5.16 — 2026-10-31

**Ruling: patch-class** (pin `pep = "0.5"` unchanged; consumers adopt by
bump). Strictly additive: one new optional field on `OidcConfig`
(`trusted_issuers`), one builder method + one field on `ResourceServerClient`,
one new internal helper — the `validate_jwt_with_options` signature is
UNCHANGED and, with the allowlist empty (the default; every existing
consumer's shape today), validation is byte-identical to 0.5.15. The 0.5.12
additive-behind-optional-feature precedent applies; `PepError` untouched.

- **Per-token issuer fallback / trusted-issuers allowlist** (nghr 895cbcea —
  CPO ruling 2026-10-31 option (a), IdP cut-over re-arm condition 1): a
  token that FAILS validation against the configured issuer is retried ONCE
  against the issuer named by its own `iss` claim — but only when that
  issuer is on the operator's allowlist
  (`ResourceServerClient::new().with_trusted_issuers(...)`, TOML key
  `[oidc] trusted_issuers`). The retry runs FULL validation — signature via
  the token issuer's own discovery + JWKS through the existing per-issuer
  caches, expiry, audience — and is accepted only on full success; any
  fallback failure returns the ORIGINAL configured-issuer error (fail-closed
  preserved). Rationale: the IdP cut-over (petit pdt AUTH_ISSUER_URL →
  idm.podai.ir) would otherwise 401 every old-issuer token twice over (iss
  mismatch AND kid miss) and darken the platform store's authz plane for the
  whole Tanbal leaf (thq reconciler writes, fame/payam/nghr service
  exchanges, agent calls).
- Tests: 5 new wire tests (`tests/trusted_issuers.rs`, mock-IdP pattern, two
  issuers/two keypairs): default-reject both failure classes, allowlisted
  fallback validates, non-allowlisted stays rejected, configured-issuer
  primary path unaffected, fallback failure preserves the primary error.
  Suite: 215 green (168 unit + 4 jwks_rotation + 7 own_token_enrichment +
  8 pdt_roles + 12 token_hardening + 5 trusted_issuers + 6
  userinfo_degraded + 5 doc).

## 0.5.15 — 2026-10-28

**Ruling: patch-class** (pin `pep = "0.5"` unchanged; consumers adopt by bump).
No public type, trait, or function signature changes; one additive public
constant (`REFRESH_JITTER_SECS`). Tuning behind the existing
`ServiceAccountTokenProvider` — the 0.5.12 additive-behind-optional-feature
precedent is stricter than what this needs.

- **Fleet refresh jitter (±15s)** on the `ServiceAccountTokenProvider`
  proactive-refresh horizon (nghr fb82b866, spec response c35042bb, leg L1
  "re-exchange before expiry … jitter ±15s fleet-wide to avoid herd"): each
  provider instance draws a FIXED offset in `[0, 15]` seconds at construction
  (process-start nanos — no `rand` dependency) and applies it consistently to
  the background refresher's wake-up, the single-flight cache re-check, and
  the serve threshold. The offset can only move the horizon EARLIER: the
  per-seat real-life mint margin grows from `exp − 210s` (120s buffer + 90s
  horizon) to `exp − 210…225s`, so the correctness floor — never serve a
  token that can die mid-request (payam 374803e5 wire) — is never weakened,
  while fleet mint phases stop overlapping. The spec's "re-exchange at
  T-120s" ask was ALREADY exceeded by the in-tree buffered horizon (effective
  `exp − 210s` since 0.5.9/0.5.11); nothing was relaxed, the genuine gap was
  the herd desync alone.
- Verified unchanged (spec leg L2, "mostly shipped, finish it"): the
  refresh-leg 400-on-expired path re-mints with fresh-token validation and a
  single retry — existing wire coverage
  (`rejected_own_token_remints_validates_and_succeeds`, plus the terminal and
  supersession pins). Real-exp parsing (849e7528) and the single-flight mint
  gate (0.5.11) untouched. `AuthDegraded` fail-closed classification
  unchanged everywhere (CPO ruling 595f826d posture). The fixed-floor
  clock-skew warning ("fresh token born at/below the serve threshold") still
  keys on the unjittered floor — jitter must not mask the skew signature.
- Doc fix: the struct-level "proactively refreshes it 30 seconds before
  expiry" claim was stale (pre-0.5.9); it now states the buffered horizon +
  jitter posture.

## 0.5.14 — 2026-10-27

**Ruling: patch-class** (pin `pep = "0.5"` unchanged; consumers adopt by bump).
No public type, trait, or function signature changes: attribution-only detail
enrichment inside the existing `PepError::AuthDegraded` payloads — the 0.5.13
rotation-window naming precedent, applied to the userinfo rejection class.

Attribution enrichment for the IdP session-supersession class (CPO ruling
2026-10-27, 595f826d fix lane, leg 4 — "attribution-only, zero behavior
change"):

- Foreign-token path (`enrich_claims_with_userinfo`; the 0.5.8 fail-closed
  contract stays BYTE-FROZEN — classification unchanged): a 4xx AuthDegraded
  detail now carries the upstream rejection body (truncated to 200 chars,
  the same rule as the 0.5.10 own-token path) so the specimen self-describes.
- When a 400/401 body identifies the IdP single-active-grant
  session-supersession class, the terminal detail NAMES it:
  "token likely VALID: superseded by a later IdP exchange
  (single-active-grant session semantics); re-mint heals; token lifecycle
  not at fault". Applied on both terminal surfaces: the foreign-token 400
  detail and the own-token second-leg (JUST-MINTED rejected after re-mint)
  detail.
- Attribution gate: the body must carry grant/session-invalidation
  vocabulary (`invalid_grant` / `invalid_session`, or `session` plus one of
  `orphaned` / `superseded` / `removed` / `revoked`) — never the generic
  `invalid_token`, which is the ordinary dead-bearer signal; firing on it
  would be a new lying class. The exact upstream rendering is ruling leg
  (b) (kanidm source investigation, paydar's lane); this marker set is the
  tunable contract point, refinable by patch with zero API impact.
- Classification unchanged everywhere: 4xx terminal `retryable: false`,
  5xx/429 `retryable: true`, budget-of-one re-mint, single-flight mint —
  exactly as shipped through 0.5.13. No consumer-visible behavior change;
  `detail` strings only.

## 0.5.13 — 2026-10-26

**Ruling: patch-class** (pin `pep = "0.5"` unchanged; consumers adopt by bump).
No public type, trait, or function signature changes: `PepError` remains
`#[non_exhaustive]`, the fix works inside the existing JWKS cache-guard
behavior, the new `ResourceServerClient` fields are additive (consumers use
`ResourceServerClient::new()`, never struct literals), and diagnostics are
log fields + error-message text. Owner trigger: estate-wide recurring 401
walls on pep-backed send paths (payam `send_message` et al.) — agents burning
agent-level retries on sends that fail "twice with the same 401".

**Root cause (server side, this fix):** during IdP key rotation, one unknown-kid
validation armed the forced-refresh storm guard — and a FAILED forced fetch
armed it just as hard as a successful one (30s). While the guard held, every
request served the kidless cached JWKS, so freshly-minted VALID tokens were
rejected with identical 401s; clients burned their single re-mint pointlessly
and agents retried the whole operation — minutes-long self-recovering windows
(kavosh specimen 9ee826c2: 5.5min / ~6.5min recurring; triggered by today's
kaniop/IdP restarts). The client token lifecycle was never at fault; the
"fix = payam seat" routing on that specimen is corrected by this release.

**Fixes (server):**
- Outcome-sensitive storm guard: a successful forced JWKS fetch holds 30s; a
  FAILED one holds only 2s (`FORCED_REFRESH_FAIL_INTERVAL`). One transient IdP
  blip no longer walls the rotation path.
- Paced single-flight bypass (`BYPASS_PACE` 1s, per jwks_uri, per process):
  when a kid is still missing after the guarded attempt — replica lag served a
  stale key set, or the guarded fetch failed — the request gets exactly one
  live second chance in-request instead of 30s of 401s. Storm bound evolves
  from "1 forced fetch per 30s window" to "1 forced fetch + 1 paced bypass".
- Unknown-kid terminal error now names the class ("No key found for kid: X
  (JWKS has N keys, cache age Ys) — IdP key-rotation propagation lag or bogus
  kid. The token is likely VALID: do not re-mint…") with a WARN journal, so
  ops attributes the window in minutes and clients stop re-minting.

**Hardening (client, same wire):**
- Mint journal fingerprint: every exchange logs jti + SHA-256 prefix (never
  the token) + real remaining life; a fresh token born at/below the serve
  threshold logs a loud clock-skew WARN.
- `with_token_retry`: if the re-mint returns the IDENTICAL rejected token
  (IdP grant-dedupe), the terminal `AuthDegraded` detail names the
  deterministic rejection (clock skew / revoked credential / server-side
  rotation window) and states the token lifecycle is NOT the fault. Budget-of-
  one is unchanged.

**Regression tests:** failed-forced-fetch bypass heals in-request (zero 401s);
stale-replica fetch healed by the bypass; storm bound re-anchored at 3 fetches;
identical-re-mint terminal detail names the cause.

## 0.5.12 — 2026-10-21

**Ruling: patch-class** (pin `pep = "0.5"` unchanged; consumers adopt by bump —
the new surface is additive behind the existing optional `token-provider`
feature, `PepError` remains `#[non_exhaustive]`, and no existing type, trait,
or function changes shape or semantics).

Task 4c57b9c5 (workstream ffe7f9cc, IdP decouple) — **PDT-backed roles
resolver: drop the groups-claim dependency.** Kanidm 1.11.0's service-account
claim projection is broken upstream (nghr 6c8efe55), so token `groups`
claims are demoted to optional hints: authorization data becomes PDT roles
keyed by the validated token's stable `sub` (spec of record PDT 2fea489c;
binding consumer contract thread beb8041d).

- New module `pep::roles` (feature `token-provider`): `PdtRolesClient`
  resolves `GET {base}/api/roles/{sub}` — ONE sub-keyed query returning
  both role families (workspace membership + user global role), with a
  short-TTL per-sub cache (30s default, `with_ttl` tunable, `invalidate`
  for explicit revocation).
- **Roles are opaque strings**: `PdtRoles` / `WorkspaceMembership` carry
  the PDT vocabulary verbatim; the resolver never inspects role content.
- **Empty ≠ unreachable**: 200-with-defaults (known or unknown sub, zero
  roles) is an authoritative least-privilege `Ok` — "authorize nothing",
  not an error. Only transport failure / timeout / 5xx / contract-violating
  answers are `PdtRolesError::Unreachable`, the fail-closed arm: consumers
  MUST deny on it, never fail open. A 404 from a non-conforming PDT is
  journaled and treated as least-privilege empty (deny-by-empty), since
  retrying cannot change an authoritative empty.
- **Foreign-authority guard**: an answer whose `sub` differs from the
  requested one is refused (`Unreachable`) — a misbehaving PDT can never
  bind another principal's roles.
- **No groups-claim read anywhere in the path**: the input is the validated
  JWT's `sub` alone. Wire-pinned in `tests/pdt_roles.rs` (signed JWT with
  NO groups claim authorizes from PDT roles alone; PDT-down = deny;
  200-defaults = least privilege; TTL cache single-upstream-hit; 500 and
  sub-mismatch = Unreachable; path-escape subs rejected pre-wire).

Cedar policy cutover onto this resolver is tracked separately (nghr
2e45619e); this release ships the resolution seam and pins its contract.

## 0.5.11 — 2026-10-21

**Ruling: patch-class** (pin `pep = "0.5"` unchanged; consumers adopt by bump —
the internal gate adds no public surface; `Attempt`/`with_token_retry`/
`invalidate` semantics are untouched and `PepError` remains `#[non_exhaustive]`).

Task 0b5df97e leg B3 — reconciliation of the token lifecycle against the
approved S3 TokenProvider client contract (doc 2a4e7402, review-cleared
d8c835e9: "the reflex contract is cleared for implementation"). Budget-of-one,
403-never-retried, and double-401-terminal were already pinned in 0.5.9/0.5.10;
this release closes the two deltas the reconciliation found:

- **Single-flight mint (S3 acceptance case: an N-way concurrent 401 storm
  must produce exactly ONE IdP exchange).** All exchanges now take a mint
  gate and re-check the cache after acquiring it: callers that queue behind
  an in-flight mint serve the freshly installed token instead of minting
  again. A reactive re-mint racing the proactive refresher collapses the
  same way.
- **Per-mint journaling made normative (S3 review note 1 — "make per-refresh
  journaling normative in the crate … the silent-mint was half of how
  b82a1925 hid").** The mint success line now carries audience + expires_in,
  and reactive-path exchange failures journal a WARN (previously only the
  proactive refresher warned; reactive failures surfaced to the caller
  alone, leaving ops nothing).

Storm regression pins added to `tests/token_hardening.rs`: 8-way concurrent
`get_token` on an empty cache and on a just-invalidated cache each collapse
to exactly one exchange, with every caller served the same fresh token.

## 0.5.10 — 2026-10-20

### Added

- **OWN-TOKEN ENRICHMENT COMPOSITION (nghr 9ee826c2; owner FIX ORDER payam
  8e50cbca, 2026-10-20)**: new
  `ResourceServerClient::enrich_claims_with_userinfo_own_token(provider,
  claims, issuer_url, userinfo_url_override)` (feature `token-provider`) for
  the enrichment leg of tokens the service minted ITSELF (RFC 8693
  service-account flows). On userinfo **400/401**: invalidate the provider →
  re-mint → **validate the fresh credential with a second userinfo roundtrip
  before the caller proceeds** → retry once → on a second rejection, surface
  `AuthDegraded { retryable: false }` carrying the upstream rejection body.
  Rationale: re-mint alone was proven insufficient — during the 2026-10-20
  payam write-leg outage, eight fresh ~900s tokens were rejected within ~40ms
  of mint and the SAME generation succeeded 69s later with no new mint
  (journal 711f2688: a bounded upstream validation window). A fresh-valid
  token rejected at the store leg therefore surfaces UPSTREAM-degraded
  (terminal loud), never a burned send, never silent success. 5xx/429/
  transport failures are not token rejections: no re-mint on either leg;
  they surface retryable (503-class) as before.

### Compatibility (semver ruling, checklist v2 step 3)

- **0.5.10 is PATCH-CLASS for pinned consumers** (same ruling as 0.5.8/0.5.9):
  consumers pin `pep = "0.5"` and adopt by bump. The new method is purely
  additive; `PepError` remains `#[non_exhaustive]`; the existing
  `enrich_claims_with_userinfo` (foreign-token path) is BYTE-IDENTICAL in
  behavior — its tests pass unchanged, and the old API gained no retry or
  re-mint behavior. Existing callers change nothing; services that mint
  their own tokens adopt the composition by calling the new method.

## 0.5.9 — 2026-10-19

### Added

- **PROACTIVE TOKEN REFRESH at T-90s (order payam ece49472, clause 1)**:
  `ServiceAccountTokenProvider` no longer serves a cached token whose
  remaining life is at or below `ServiceAccountTokenProvider::
  PROACTIVE_REFRESH_SECS` (90s) — the next `get_token()` exchanges instead.
  New `spawn_proactive_refresh()` runs a background task that exchanges at
  the horizon WITHOUT caller pressure, so long-idle processes always hold a
  live token. Failure posture: refresh failures log (warn) and retry after a
  5s backoff; `get_token()` still fails LOUD if the IdP stays down —
  fail-closed, never a lying success. Closes the payam v0.2.5 send-path
  outage wire at the provider layer (nghr 374803e5: activity does not
  trigger refresh, so the provider must not need activity).
  Effective lazy horizon is `exp − 210s` (120s skew/transit buffer + 90s
  proactive horizon compose).

- **UNIVERSAL 401 RETRY driver (order payam ece49472, clause 2)**:
  `with_token_retry(provider, attempt)` + `Attempt<T>` (`Served` /
  `StaleToken` / `Failed`). One driver for reads AND writes — the closure
  picks the verb. On a 401 the driver invalidates the cached token, re-mints,
  and retries EXACTLY once. Why retrying writes is safe: `StaleToken` is only
  for 401 responses, which arrive INSTEAD of execution — a 401'd request was
  never authenticated, hence never executed. 403 is authorization, not
  staleness: map it to `Attempt::Failed` so it stays terminal. Double-401 is
  terminal: `PepError::AuthDegraded { retryable: false }`. Non-401 errors
  pass through untouched, never retried.

- **REAL-EXP AUDIT fixes (order payam ece49472, clause 3; nghr 849e7528
  class)**: `InteractiveTokenProvider`'s refresh path persisted the
  `expires_in` ESTIMATE as the stored token's `expires_at`, disagreeing with
  the in-memory cache (which honors the real JWT `exp` since 1059cad). A
  restart therefore resurrected an over-lived token. The stored record now
  uses `compute_expires_at_from_jwt` — real `exp` when decodable, estimate
  only for opaque tokens. Service-account path audited: correct since 0.5.5
  (1059cad), tests present.

### Semver ruling (recorded per checklist v2)

0.5.9, NOT 0.6.0: consumers pin `pep = "0.5"`; a patch release is adopted by
a plain version bump. The new API is purely additive; the one behavior change
(never serve a token inside the T-90s horizon) is the fix itself — a token
that can die mid-request must not be handed out. `PepError` remains
`#[non_exhaustive]` (since 0.5.8); consumers must not exhaustive-match.

### Tests

`tests/token_hardening.rs` (9): T-90 lazy gate + no-churn control; proactive
refresher with no caller pressure + no-churn-when-fresh control; IdP outage
fail-loud (refresher survives, get_token errors); 401→re-mint→retry-once on a
write path (and reads take the identical path); double-401 terminal
AuthDegraded (bounded at two attempts); non-401 pass-through (no retry, no
re-mint); static-provider participation; real-exp persistence on Interactive
refresh (stored record = real exp, NOT the estimate). 181 total green,
including lib + doc suites.

### Honesty flags

- The order cites thq v0.9.2 as the live-proven reference for the T-90s
  pattern; the thq source was NOT available locally (no clone at
  /Projects/Podtan/thq, no thq crate in the trustee workspace). Implemented
  from the order's specification (T-90s horizon + background refresher +
  fail-loud posture). Pattern-parity with thq v0.9.2: UNVERIFIED — flagged
  for whoever holds the thq tree.

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
