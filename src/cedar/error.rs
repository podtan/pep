//! Error types for Cedar authorization operations



/// Cedar-specific error type
#[derive(Debug, thiserror::Error)]
pub enum CedarError {
    /// Failed to parse a Cedar policy
    #[error("Cedar policy parse error: {0}")]
    PolicyParse(String),

    /// Failed to parse the Cedar schema
    #[error("Cedar schema parse error: {0}")]
    SchemaParse(String),

    /// Failed to load policies from file/directory
    #[error("Policy load error: {0}")]
    PolicyLoad(String),

    /// Failed to validate policies against schema
    #[error("Policy validation error: {0}")]
    Validation(String),

    /// Failed to build Cedar entities
    #[error("Entity build error: {0}")]
    EntityBuildFailed(String),

    /// Authorization evaluation error
    #[error("Authorization evaluation error: {0}")]
    Evaluation(String),

    /// Configuration error
    #[error("Cedar configuration error: {0}")]
    Config(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Cedar policy set error
    #[error("Policy set error: {0}")]
    PolicySet(String),
}

/// HTTP status code mapping for Cedar errors
impl CedarError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            CedarError::Config(_) | CedarError::PolicyParse(_) | CedarError::SchemaParse(_) => 500,
            CedarError::PolicyLoad(_) | CedarError::Validation(_) => 500,
            CedarError::EntityBuildFailed(_) | CedarError::Evaluation(_) => 500,
            CedarError::Io(_) | CedarError::PolicySet(_) => 500,
        }
    }
}

pub type CedarResult<T> = std::result::Result<T, CedarError>;
