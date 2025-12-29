use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Result type for sandbox operations
pub type SandboxResult<T> = Result<T, SandboxError>;

/// Errors that can occur during sandbox operations
#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("unsupported platform")]
    UnsupportedPlatform,

    #[error("platform {platform} requires version {minimum}, found {current}")]
    UnsupportedPlatformVersion {
        platform: &'static str,
        minimum: &'static str,
        current: String,
    },

    #[error("sandbox initialization failed: {0}")]
    SandboxInitFailed(String),

    #[error("sandbox not enforced: {0}")]
    SandboxNotEnforced(&'static str),

    #[error("sandbox only partially enforced: {0}")]
    PartialEnforcement(&'static str),

    #[error("invalid sandbox profile: {0}")]
    InvalidProfile(String),

    #[error("path does not exist: {0}")]
    PathNotFound(PathBuf),

    #[error("python not found on system")]
    PythonNotFound,

    #[error("python venv not found at: {0}")]
    VenvNotFound(PathBuf),

    #[error("python venv creation failed: {0}")]
    VenvCreationFailed(String),

    #[error("package installation failed: {0}")]
    PackageInstallFailed(String),

    #[error("network proxy error: {0}")]
    ProxyError(String),

    #[error("process execution failed: {0}")]
    ProcessError(#[from] io::Error),

    #[error("command failed with exit code {code}: {message}")]
    CommandFailed { code: i32, message: String },

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("FFI error: {0}")]
    FfiError(String),
}
