use thiserror::Error;

/// Unified result alias across core Operquay crates.
pub type Result<T, E = OperquayError> = std::result::Result<T, E>;

/// Core domain error variants emitted across protocol engines and control plane stores.
#[derive(Debug, Error)]
pub enum OperquayError {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("security policy rejected connection: {0}")]
    SecurityPolicy(String),

    #[error("recording failed in fail-closed mode: {0}")]
    RecordingRequired(String),

    #[error("unsupported protocol '{0}'")]
    UnsupportedProtocol(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
