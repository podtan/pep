//! OAuth callback HTTP server for interactive authentication flows.
//!
//! Provides a minimal HTTP server that listens on `localhost:{port}` for the
//! OAuth authorization code redirect, extracts the `code` and `state` query
//! parameters, and then shuts down.
//!
//! This completes PEP's PKCE + token-exchange toolkit:
//! - `generate_code_verifier()` / `generate_code_challenge()`
//! - `build_authorization_url()`
//! - `exchange_code_for_tokens()`
//! - **`CallbackServer`** ← catches the redirect

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time;

use crate::error::{PepError, Result};

/// The result of waiting for the OAuth redirect.
#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    /// The authorization code returned by the IdP.
    pub code: String,
    /// The `state` value, if the IdP included one.
    pub state: Option<String>,
}

/// A tiny one-shot HTTP server that catches the OAuth `/callback` redirect.
///
/// Typical usage (orchestrated by the caller — usually Trustee CLI):
///
/// ```text
/// 1. CallbackServer::new(port)
/// 2. caller builds auth URL with redirect_uri = server.redirect_uri()
/// 3. caller opens browser
/// 4. server.wait_for_code().await  → AuthorizationCode
/// 5. caller exchanges code for tokens via OidcClient
/// ```
pub struct CallbackServer {
    port: u16,
    timeout: Duration,
}

impl CallbackServer {
    /// Create a new callback server bound to `127.0.0.1:{port}`.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            timeout: Duration::from_secs(120),
        }
    }

    /// Set a custom timeout (default: 120 seconds).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the redirect URI that should be passed to the authorization endpoint.
    pub fn redirect_uri(&self) -> String {
        format!("http://localhost:{}/callback", self.port)
    }

    /// Start listening and block until the authorization code arrives.
    ///
    /// Listens for exactly ONE HTTP GET request to `/callback?code=xxx&state=yyy`,
    /// parses the query parameters, responds with a minimal success page, then
    /// returns the extracted [`AuthorizationCode`].
    ///
    /// Returns an error if:
    /// - The port cannot be bound
    /// - No request arrives within the timeout period
    /// - The IdP returns an `error` parameter instead of a `code`
    pub async fn wait_for_code(&self) -> Result<AuthorizationCode> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))
            .await
            .map_err(|e| {
                PepError::BadRequest(format!(
                    "Failed to bind callback server on port {}: {}",
                    self.port, e
                ))
            })?;

        tracing::debug!(
            "OAuth callback server listening on 127.0.0.1:{}",
            self.port
        );

        // Wait for a single connection, with timeout
        let (mut socket, addr) = tokio::select! {
            result = listener.accept() => {
                tracing::debug!("Callback connection from {}", result.as_ref().map(|(_, a)| a).map(|a| a.to_string()).unwrap_or_default());
                result.map_err(|e| PepError::BadRequest(format!("Failed to accept callback connection: {}", e)))?
            }
            _ = time::sleep(self.timeout) => {
                return Err(PepError::BadRequest(
                    "OAuth callback timed out — no redirect received within the timeout period".to_string(),
                ));
            }
        };

        // Read the HTTP request
        let mut buf = vec![0u8; 4096];
        let n = socket
            .read(&mut buf)
            .await
            .map_err(|e| PepError::BadRequest(format!("Failed to read callback request: {}", e)))?;

        let request = String::from_utf8_lossy(&buf[..n]).to_string();

        tracing::debug!("Callback request from {} ({} bytes)", addr, n);

        // Parse the request line to extract the path + query string
        // Expected: GET /callback?code=xxx&state=yyy HTTP/1.1
        let (query_params, is_error) = parse_callback_request(&request);

        // Build the HTTP response
        let response_body = if is_error {
            build_error_page()
        } else {
            build_success_page()
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );

        socket
            .write_all(response.as_bytes())
            .await
            .map_err(|e| PepError::BadRequest(format!("Failed to write callback response: {}", e)))?;

        let _ = socket.flush().await;

        // Process query params
        if is_error {
            let error = query_params
                .get("error")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let error_desc = query_params
                .get("error_description")
                .cloned()
                .unwrap_or_default();
            return Err(PepError::BadRequest(format!(
                "OAuth provider returned error: {} — {}",
                error, error_desc
            )));
        }

        let code = query_params
            .get("code")
            .ok_or_else(|| PepError::BadRequest("No 'code' parameter in OAuth callback".to_string()))?
            .clone();

        let state = query_params.get("state").cloned();

        Ok(AuthorizationCode { code, state })
    }
}

/// Parse query parameters from the HTTP request line.
///
/// Returns a `(HashMap<String, String>, is_error)` tuple where `is_error`
/// is `true` if the query contains an `error` parameter.
fn parse_callback_request(request: &str) -> (std::collections::HashMap<String, String>, bool) {
    let mut params = std::collections::HashMap::new();

    // Find the request line: "GET /callback?code=xxx&state=yyy HTTP/1.1"
    let request_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return (params, false);
    }

    let path = parts[1]; // e.g. "/callback?code=xxx&state=yyy"

    // Split path and query string
    if let Some(query_start) = path.find('?') {
        let query = &path[query_start + 1..];
        for pair in query.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let key = percent_decode(&pair[..eq_pos]);
                let value = percent_decode(&pair[eq_pos + 1..]);
                params.insert(key, value);
            } else {
                // Key without value
                params.insert(percent_decode(pair), String::new());
            }
        }
    }

    let is_error = params.contains_key("error");
    (params, is_error)
}

/// Minimal percent-decoding for query parameter values.
///
/// Handles `%XX` hex escapes and `+` → space.
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '%' => {
                let h1 = chars.next();
                let h2 = chars.next();
                if let (Some(h1), Some(h2)) = (h1, h2) {
                    if let Ok(byte) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                        result.push(byte as char);
                    } else {
                        result.push('%');
                        result.push(h1);
                        result.push(h2);
                    }
                } else {
                    result.push('%');
                }
            }
            '+' => result.push(' '),
            _ => result.push(c),
        }
    }

    result
}

fn build_success_page() -> String {
    r#"<html>
<head><title>Authentication Successful</title></head>
<body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
<h2>✅ Authentication successful</h2>
<p>You can close this browser tab now.</p>
</body>
</html>"#
        .to_string()
}

fn build_error_page() -> String {
    r#"<html>
<head><title>Authentication Failed</title></head>
<body style="font-family: sans-serif; text-align: center; margin-top: 50px;">
<h2>❌ Authentication failed</h2>
<p>Please try again from the terminal.</p>
</body>
</html>"#
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_callback_request_success() {
        let request = "GET /callback?code=abc123&state=xyz789 HTTP/1.1\r\nHost: localhost:8765\r\n\r\n";
        let (params, is_error) = parse_callback_request(request);

        assert!(!is_error);
        assert_eq!(params.get("code").unwrap(), "abc123");
        assert_eq!(params.get("state").unwrap(), "xyz789");
    }

    #[test]
    fn test_parse_callback_request_error() {
        let request = "GET /callback?error=access_denied&error_description=User+cancelled HTTP/1.1\r\nHost: localhost:8765\r\n\r\n";
        let (params, is_error) = parse_callback_request(request);

        assert!(is_error);
        assert_eq!(params.get("error").unwrap(), "access_denied");
        assert_eq!(params.get("error_description").unwrap(), "User cancelled");
    }

    #[test]
    fn test_parse_callback_request_percent_encoded() {
        let request = "GET /callback?code=ab%2Fcd&state=x%26y HTTP/1.1\r\n\r\n";
        let (params, _) = parse_callback_request(request);

        assert_eq!(params.get("code").unwrap(), "ab/cd");
        assert_eq!(params.get("state").unwrap(), "x&y");
    }

    #[test]
    fn test_parse_callback_request_no_query() {
        let request = "GET /callback HTTP/1.1\r\n\r\n";
        let (params, is_error) = parse_callback_request(request);

        assert!(params.is_empty());
        assert!(!is_error);
    }

    #[test]
    fn test_parse_callback_request_malformed() {
        let (params, is_error) = parse_callback_request("garbage");
        assert!(params.is_empty());
        assert!(!is_error);
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello+world"), "hello world");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("100%25"), "100%");
    }

    #[test]
    fn test_redirect_uri() {
        let server = CallbackServer::new(8765);
        assert_eq!(server.redirect_uri(), "http://localhost:8765/callback");
    }

    #[tokio::test]
    async fn test_callback_server_receives_code() {
        // Pick a random free port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // Free it for the CallbackServer

        let server = CallbackServer::new(port).with_timeout(Duration::from_secs(5));

        // Spawn a task that connects and sends the callback
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            let request = "GET /callback?code=test_code_123&state=test_state HTTP/1.1\r\nHost: localhost\r\n\r\n";
            stream.write_all(request.as_bytes()).await.unwrap();
            let _ = stream.flush().await;

            // Read response (we don't care about the content for this test)
            let mut buf = vec![0u8; 1024];
            let _ = stream.read(&mut buf).await;
        });

        let result = server.wait_for_code().await.unwrap();
        assert_eq!(result.code, "test_code_123");
        assert_eq!(result.state.as_deref(), Some("test_state"));
    }

    #[tokio::test]
    async fn test_callback_server_error_param() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let server = CallbackServer::new(port).with_timeout(Duration::from_secs(5));

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            let request = "GET /callback?error=access_denied HTTP/1.1\r\nHost: localhost\r\n\r\n";
            stream.write_all(request.as_bytes()).await.unwrap();
            let _ = stream.flush().await;
            let mut buf = vec![0u8; 1024];
            let _ = stream.read(&mut buf).await;
        });

        let result = server.wait_for_code().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("access_denied"));
    }

    #[tokio::test]
    async fn test_callback_server_timeout() {
        // Use a port that nobody connects to
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let server = CallbackServer::new(port).with_timeout(Duration::from_millis(100));

        let result = server.wait_for_code().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }
}
