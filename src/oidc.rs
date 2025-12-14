//! OIDC authentication and authorization functionality
//!
//! This module provides both OIDC client functionality for web applications
//! and resource server protection for APIs.

pub mod types;
pub mod client;
pub mod resource_server;

pub use types::*;
pub use client::*;
pub use resource_server::*;