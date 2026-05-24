# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-06-09

### Added
- feat(token-provider): new `token_provider` module for managing authentication token lifecycle
  - `TokenProvider` trait with native Rust 1.75+ async fn (no `async-trait` crate)
  - `StaticTokenProvider` — wraps a static string token
  - `ServiceAccountTokenProvider` — RFC 8693 token exchange with automatic caching and refresh
  - `InteractiveTokenProvider` — stub for future browser PKCE flow
  - `TokenProviderEnum` — enum dispatch over all variants (no `Box<dyn>` needed)
  - `ServiceAccountConfig` struct for configuring service account token exchange
  - Gated behind `token-provider` feature (requires `oidc-client` feature)
  - 10 unit tests, all passing

### Fixed
- fix(oidc): `exchange_token()` now accepts and sends optional `scope` parameter in the token exchange request body (was missing, causing `invalid_request` errors from Kanidm)

## [0.3.0] - 2026-03-08

### Added
- feat(rfc9728): add RFC 9728 Protected Resource Metadata support
  - `ProtectedResourceMetadata` struct for resource metadata responses
  - `PrmConfig` for configuration-based setup
  - Axum handler `prm_handler` and convenience function `prm_route`
  - `resource_metadata` parameter support in WWW-Authenticate headers
- feat(oidc): add `get_discovery_document_raw()` with caching
  - Returns raw discovery JSON for proxying OAuth metadata
  - 1-hour TTL caching to reduce HTTP requests
- feat(oidc): add `CachedDiscoveryRaw` type for caching raw discovery documents

### Changed
- Export `CachedDiscoveryRaw` from crate root for downstream use

## [0.2.1] - 2025-12-26

### Fixed
- config: add missing OidcClientConfig import in configuration module

## [0.2.0] - 2025-12-20

### Added
- feat(auth): add authorization helpers and middleware for role/scope verification
- feat(config): add standardized configuration module with support for OIDC client configuration
- feat(oidc): add axum integration for web framework support
- feat(oidc): add development claims builder for testing
- feat(oidc): add OIDC authentication and authorization library

### Documentation
- docs: add sample configuration file and update README with usage examples

## [0.1.0] - 2025-12-15

### Added
- Initial release of PEP (Policy Enforcement Point)
- Core OIDC authentication support
- JWT token validation
- Basic authorization framework
