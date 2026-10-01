use thiserror::Error;

/// Errors returned while provisioning or syncing certificates.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid local configuration or certificate material.
    #[error("configuration error: {0}")]
    Config(String),
    /// An HTTP request failed or a remote API returned an error status.
    #[error("HTTP error: {0}")]
    HttpClient(String),
    /// The ACME server returned a malformed response.
    #[error("ACME protocol error: {0}")]
    AcmeProtocol(String),
    /// Account creation or account-key handling failed.
    #[error("ACME account error: {0}")]
    Account(String),
    /// An ACME order failed or entered an unsupported state.
    #[error("ACME order error: {0}")]
    Order(String),
    /// An authorization or DNS challenge failed.
    #[error("ACME challenge error: {0}")]
    Challenge(String),
    /// The CA response did not contain a PEM certificate chain.
    #[error("PEM error: {0}")]
    Pem(String),
    /// A renewal was cancelled.
    #[error("renewal cancelled")]
    Cancelled,
    /// A filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Result type used throughout this crate.
pub type Result<T> = std::result::Result<T, Error>;
