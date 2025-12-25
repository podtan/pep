# PEP - Policy Enforcement Point

[![Crates.io](https://img.shields.io/crates/v/pep.svg)](https://crates.io/crates/pep)
[![Documentation](https://docs.rs/pep/badge.svg)](https://docs.rs/pep)
[![License](https://img.shields.io/crates/l/pep.svg)](LICENSE)

A Rust library providing OIDC (OpenID Connect) authentication and authorization functionality for both client-side web applications and resource server API protection.

## Features

- **`oidc-client`**: OIDC client functionality for web applications
  - Authorization code flow with PKCE
  - Token exchange
  - OIDC discovery document handling
  - State and nonce generation

- **`oidc-resource-server`**: JWT validation for API protection
  - JWT token validation with JWKS
  - Configurable validation options (skip issuer/audience validation)
  - Automatic key rotation handling
  - Caching for performance

- **`axum`** (optional): Axum web framework integration
  - `JwtClaimsExtractor` for easy claims extraction in handlers
  - `extract_bearer_token` utility for Authorization header parsing

- **Development Mode**: Built-in support for local development
  - `DevConfig.create_dev_claims()` for mock JWT claims

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
# Full OIDC support (client + resource server)
pep = { version = "0.1", features = ["oidc"] }

# Or enable specific features
pep = { version = "0.1", features = ["oidc-resource-server"] }

# With Axum integration (requires axum 0.8+)
pep = { version = "0.1", features = ["oidc-resource-server", "axum"] }

# With configuration file parsing support
pep = { version = "0.1", features = ["oidc", "config"] }
```

## Usage

### Resource Server (JWT Validation)

```rust
use pep::oidc_resource_server::ResourceServerClient;
use pep::JwtValidationOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ResourceServerClient::new();

    let validation_options = JwtValidationOptions {
        skip_issuer_validation: false,
        skip_audience_validation: false,
        expected_audience: None, // Uses client_id by default
    };

    // Validate JWT token
    let claims = client.validate_jwt_with_options(
        "jwt-token-here",
        "https://your-oidc-provider.com",
        "your-client-id",
        &validation_options,
    ).await?;

    println!("User ID: {}", claims.sub);
    println!("Email: {:?}", claims.email);

    Ok(())
}
```

### OIDC Client (Web Authentication Flow)

```rust
use pep::oidc_client::OidcClient;
use pep::OidcClientConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OidcClientConfig {
        issuer_url: "https://your-oidc-provider.com".to_string(),
        client_id: "your-client-id".to_string(),
        client_secret: Some("your-client-secret".to_string()),
        redirect_uri: "https://your-app.com/callback".to_string(),
        scope: "openid email profile".to_string(),
        code_challenge_method: "S256".to_string(),
    };

    let client = OidcClient::new();

    // Generate PKCE values
    let code_verifier = OidcClient::generate_code_verifier();
    let code_challenge = OidcClient::generate_code_challenge(&code_verifier);
    let state = OidcClient::generate_state();

    // Build authorization URL
    let auth_url = client.build_authorization_url(&config, &state, Some(&code_challenge)).await?;

    // Redirect user to auth_url...
    // After user returns with code:
    let token_response = client.exchange_code_for_tokens(
        &config, 
        "auth-code", 
        Some(&code_verifier)
    ).await?;

    println!("Access token: {}", token_response.access_token);

    Ok(())
}
```

### Axum Integration

When using the `axum` feature with Axum 0.8+:

```rust
use axum::{routing::get, Router};
use pep::axum::{JwtClaimsExtractor, extract_bearer_token};

async fn protected_handler(claims: JwtClaimsExtractor) -> String {
    format!("Hello, {}!", claims.sub)
}

let app = Router::new()
    .route("/protected", get(protected_handler));
```

### Development Mode

Create mock JWT claims for local development without a real OIDC provider:

```rust
use pep::DevConfig;

// Create dev config
let dev_config = DevConfig {
    local_dev_mode: true,
    local_dev_email: Some("dev@localhost".to_string()),
    local_dev_name: Some("Dev User".to_string()),
    local_dev_username: Some("devuser".to_string()),
};

// Generate mock claims
let claims = dev_config.create_dev_claims();

// Or use the convenience constructor
let dev = DevConfig::enabled();
let claims = dev.create_dev_claims();

assert_eq!(claims.iss, "dev");
assert_eq!(claims.email, Some("dev@localhost".to_string()));
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `oidc` | Enables both `oidc-client` and `oidc-resource-server` |
| `oidc-client` | OIDC client for web authentication flows |
| `oidc-resource-server` | JWT validation for API protection |
| `axum` | Axum 0.8+ integration (extractors, utilities) |
| `config` | TOML configuration file parsing support |

## JWT Claims Structure

The `JwtClaims` struct provides access to standard OIDC claims:

```rust
pub struct JwtClaims {
    pub sub: String,                          // Subject (user ID)
    pub iss: String,                          // Issuer
    pub aud: Option<String>,                  // Audience
    pub exp: i64,                             // Expiration time
    pub iat: Option<i64>,                     // Issued at
    pub email: Option<String>,                // Email address
    pub name: Option<String>,                 // Full name
    pub preferred_username: Option<String>,   // Username
    pub extra: HashMap<String, Value>,        // Additional claims
}
```

## Error Handling

PEP uses a custom `PepError` type with HTTP status code support:

```rust
use pep::{PepError, Result};

fn handle_error(error: PepError) {
    let status = error.status_code(); // Returns http::StatusCode
    eprintln!("Error ({}): {}", status, error);
}
```

## Configuration

PEP can be configured using OIDC and Development settings. The `config` feature provides utilities for loading configuration from TOML files.

### Configuration File Format

Create a `config.toml` file:

```toml
# OIDC configuration for authentication and resource server protection
[oidc]
provider = "kanidm"
issuer_url = "https://idm.example.com"
client_id = "your-client-id"
client_secret = "your-client-secret"
redirect_url = "https://your-app.com/auth/callback"
code_challenge_method = "S256"
scope = "openid email profile offline_access"

# Local development configuration
[dev]
local_dev_mode = false  # Set to true to bypass real OIDC and use mock claims
local_dev_email = "developer@example.com"
local_dev_name = "Local Developer"
local_dev_username = "developer"
```

### Loading Configuration (requires `config` feature)

```rust
use pep::config::load_config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from file
    let config = load_config("config.toml")?;
    
    // Get OIDC configuration
    let oidc_config = config.oidc_config()?;
    
    // Convert to internal types for use with OIDC client
    let client_config = oidc_config.to_oidc_client_config();
    let resource_config = oidc_config.to_resource_server_config();
    
    // Use with OIDC client
    let client = pep::oidc_client::OidcClient::new();
    
    // Use with resource server
    let resource_client = pep::oidc_resource_server::ResourceServerClient::new();
    
    Ok(())
}
```

A sample configuration file is available at [config-sample.toml](config-sample.toml).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
