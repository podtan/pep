# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
