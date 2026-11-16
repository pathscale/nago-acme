use thiserror::Error;

/// Why startup could not use restored ACME credentials.
#[derive(Debug, Error)]
pub enum RestoreError {
    /// The caller reported that restoration did not complete successfully.
    #[error("the application could not restore ACME credentials")]
    Failed,
    /// No certificate chain with a matching private key was restored.
    #[error("restored certificate material is missing")]
    MissingCertificate,
    /// No ACME account key was restored.
    #[error("restored ACME account key is missing")]
    MissingAccountKey,
}

/// Errors returned while provisioning or syncing certificates.
#[derive(Debug, Error)]
pub enum Error {
    /// Startup requires credentials restored by the application.
    #[error("ACME restore error: {0}")]
    Restore(#[from] RestoreError),
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
