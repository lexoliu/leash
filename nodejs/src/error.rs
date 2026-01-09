use napi::bindgen_prelude::*;

/// Convert leash errors to NAPI errors with descriptive codes
pub fn convert_error(err: leash::Error) -> Error {
    let (code, message) = match &err {
        leash::Error::UnsupportedPlatform => ("ERR_UNSUPPORTED_PLATFORM", err.to_string()),
        leash::Error::UnsupportedPlatformVersion { .. } => {
            ("ERR_UNSUPPORTED_PLATFORM_VERSION", err.to_string())
        }
        leash::Error::InitFailed(msg) => ("ERR_INIT_FAILED", msg.clone()),
        leash::Error::NotEnforced(msg) => ("ERR_NOT_ENFORCED", msg.to_string()),
        leash::Error::PartialEnforcement(msg) => ("ERR_PARTIAL_ENFORCEMENT", msg.to_string()),
        leash::Error::InvalidProfile(msg) => ("ERR_INVALID_PROFILE", msg.clone()),
        leash::Error::PathNotFound(path) => (
            "ERR_PATH_NOT_FOUND",
            format!("Path not found: {}", path.display()),
        ),
        leash::Error::PythonNotFound => ("ERR_PYTHON_NOT_FOUND", err.to_string()),
        leash::Error::VenvNotFound(path) => (
            "ERR_VENV_NOT_FOUND",
            format!("Venv not found: {}", path.display()),
        ),
        leash::Error::VenvCreationFailed(msg) => ("ERR_VENV_CREATION", msg.clone()),
        leash::Error::PackageInstallFailed(msg) => ("ERR_PACKAGE_INSTALL", msg.clone()),
        leash::Error::ProxyError(msg) => ("ERR_PROXY", msg.clone()),
        leash::Error::ProcessError(e) => ("ERR_PROCESS", e.to_string()),
        leash::Error::CommandFailed { code, message } => (
            "ERR_COMMAND_FAILED",
            format!("Exit code {}: {}", code, message),
        ),
        leash::Error::ConfigError(msg) => ("ERR_CONFIG", msg.clone()),
        leash::Error::FfiError(msg) => ("ERR_FFI", msg.clone()),
        leash::Error::IoError(msg) => ("ERR_IO", msg.clone()),
        leash::Error::IpcError(e) => ("ERR_IPC", e.to_string()),
        leash::Error::PtyError(msg) => ("ERR_PTY", msg.clone()),
    };

    Error::new(Status::GenericFailure, format!("[{}] {}", code, message))
}

/// Extension trait for converting leash Results to NAPI Results
pub trait IntoNapiResult<T> {
    fn into_napi(self) -> Result<T>;
}

impl<T> IntoNapiResult<T> for leash::Result<T> {
    fn into_napi(self) -> Result<T> {
        self.map_err(convert_error)
    }
}
