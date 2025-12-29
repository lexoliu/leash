use std::process::Output;

use crate::command::Command;
use crate::config::SandboxConfig;
use crate::error::Result;
use crate::network::{DenyAll, NetworkPolicy};
use crate::platform;

#[cfg(target_os = "macos")]
type NativeBackend = platform::macos::MacOSBackend;

#[cfg(target_os = "linux")]
type NativeBackend = platform::linux::LinuxBackend;

#[cfg(target_os = "windows")]
type NativeBackend = platform::windows::WindowsBackend;

/// A sandbox for running untrusted code with restricted permissions
pub struct Sandbox<N: NetworkPolicy = DenyAll> {
    config: SandboxConfig<N>,
    backend: NativeBackend,
}

impl Sandbox<DenyAll> {
    /// Create a new sandbox with default configuration
    ///
    /// Creates a random working directory in the current directory
    /// using four English words connected by hyphens.
    pub fn new() -> Result<Self> {
        let backend = platform::create_native_backend()?;
        let config = SandboxConfig::new()?;
        Ok(Self { config, backend })
    }
}

impl<N: NetworkPolicy> Sandbox<N> {
    /// Create a sandbox with custom configuration
    pub fn with_config(config: SandboxConfig<N>) -> Result<Self> {
        let backend = platform::create_native_backend()?;
        Ok(Self { config, backend })
    }

    /// Create a command builder for running a program in the sandbox
    pub fn command(&self, program: impl Into<String>) -> Command<'_, N> {
        Command::new(&self.config, &self.backend, program)
    }

    /// Run a Python script in the sandbox
    ///
    /// The script will be executed using the Python interpreter from the configured
    /// virtual environment, or the system Python if no venv is configured.
    pub async fn run_python(&self, script: &str) -> Result<Output> {
        // Determine the Python interpreter to use
        let python = if let Some(python_config) = self.config.python() {
            // Use venv Python if configured
            let venv_path = python_config.venv().path();
            if cfg!(windows) {
                venv_path.join("Scripts").join("python.exe")
            } else {
                venv_path.join("bin").join("python")
            }
        } else {
            // Use system Python
            which::which("python3")
                .or_else(|_| which::which("python"))
                .map_err(|_| crate::error::Error::PythonNotFound)?
        };

        self.command(python.to_string_lossy().to_string())
            .arg("-c")
            .arg(script)
            .output()
            .await
    }

    /// Get a reference to the sandbox configuration
    pub fn config(&self) -> &SandboxConfig<N> {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_creation() {
        let result = Sandbox::new();
        // This may fail on non-macOS platforms currently
        if cfg!(target_os = "macos") {
            assert!(result.is_ok());
        }
    }
}
