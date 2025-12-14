# PEP - Policy Enforcement Point

A Rust library providing OIDC (OpenID Connect) authentication and authorization functionality for both client-side web applications and resource server API protection.

## Features

- **`oidc-client`**: OIDC client functionality for web applications
  - Authorization code flow with PKCE
  - Token exchange
  - OIDC discovery document handling
  - Development mode support

- **`oidc-resource-server`**: JWT validation for API protection
  - JWT token validation with JWKS
  - Configurable validation options
  - Automatic key rotation handling
  - Caching for performance

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
pep = { version = "0.1", features = ["oidc"] }
```

Or enable specific features:

```toml
[dependencies]
pep = { version = "0.1", features = ["oidc-client", "oidc-resource-server"] }
```

## Usage

### OIDC Client

```rust
use pep::oidc_client::{OidcClient, OidcClientConfig};

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

    // After user returns with code, exchange for tokens
    let token_response = client.exchange_code_for_tokens(&config, "auth-code", Some(&code_verifier)).await?;

    println!("Access token: {}", token_response.access_token);

    Ok(())
}
```

### Resource Server

```rust
use pep::oidc_resource_server::{ResourceServerClient, JwtValidationOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ResourceServerClient::new();

    let validation_options = JwtValidationOptions {
        skip_issuer_validation: false,
        skip_audience_validation: false,
        expected_audience: None,
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

## Development Mode

Both client and resource server support development mode for local testing:

```rust
use pep::oidc_client::{DevAuthHelper, DevConfig};

let dev_config = DevConfig {
    local_dev_mode: true,
    local_dev_email: Some("dev@example.com".to_string()),
    local_dev_name: Some("Dev User".to_string()),
    local_dev_username: Some("devuser".to_string()),
};

let session_data = DevAuthHelper::create_dev_session(&dev_config);
```

## License

MIT OR Apache-2.0
