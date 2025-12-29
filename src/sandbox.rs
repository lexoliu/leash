use std::path::PathBuf;
use std::process::Output;
use std::sync::{Arc, Mutex};

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

/// Tracks child processes spawned within the sandbox
#[derive(Debug, Clone, Default)]
pub(crate) struct ProcessTracker {
    pids: Arc<Mutex<Vec<u32>>>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            pids: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a new child process
    pub fn register(&self, pid: u32) {
        if let Ok(mut pids) = self.pids.lock() {
            pids.push(pid);
            tracing::debug!(pid = pid, "registered child process");
        }
    }

    /// Unregister a process (when it exits normally)
    pub fn unregister(&self, pid: u32) {
        if let Ok(mut pids) = self.pids.lock() {
            pids.retain(|&p| p != pid);
            tracing::debug!(pid = pid, "unregistered child process");
        }
    }

    /// Kill all tracked processes
    pub fn kill_all(&self) {
        if let Ok(pids) = self.pids.lock() {
            for &pid in pids.iter() {
                tracing::debug!(pid = pid, "killing child process");
                #[cfg(unix)]
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
                #[cfg(windows)]
                {
                    use std::process::Command;
                    let _ = Command::new("taskkill")
                        .args(["/F", "/PID", &pid.to_string()])
                        .output();
                }
            }
        }
    }
}

/// A sandbox for running untrusted code with restricted permissions
///
/// When dropped, the sandbox will:
/// - Kill all child processes that were spawned within it
/// - Delete the working directory (unless `keep_working_dir()` was called)
pub struct Sandbox<N: NetworkPolicy = DenyAll> {
    config: SandboxConfig<N>,
    backend: NativeBackend,
    process_tracker: ProcessTracker,
    working_dir_path: PathBuf,
    keep_working_dir: bool,
}

impl Sandbox<DenyAll> {
    /// Create a new sandbox with default configuration
    ///
    /// Creates a random working directory in the current directory
    /// using four English words connected by hyphens.
    pub fn new() -> Result<Self> {
        let backend = platform::create_native_backend()?;
        let config = SandboxConfig::new()?;
        let working_dir_path = config.working_dir().to_path_buf();
        Ok(Self {
            config,
            backend,
            process_tracker: ProcessTracker::new(),
            working_dir_path,
            keep_working_dir: false,
        })
    }
}

impl<N: NetworkPolicy> Sandbox<N> {
    /// Create a sandbox with custom configuration
    pub fn with_config(config: SandboxConfig<N>) -> Result<Self> {
        let backend = platform::create_native_backend()?;
        let working_dir_path = config.working_dir().to_path_buf();
        Ok(Self {
            config,
            backend,
            process_tracker: ProcessTracker::new(),
            working_dir_path,
            keep_working_dir: false,
        })
    }

    /// Keep the working directory after the sandbox is dropped
    ///
    /// By default, the working directory is deleted when the sandbox is dropped.
    /// Call this method to preserve the working directory for inspection or reuse.
    ///
    /// Note: Child processes are always killed when the sandbox is dropped,
    /// regardless of this setting.
    pub fn keep_working_dir(&mut self) -> &mut Self {
        self.keep_working_dir = true;
        self
    }

    /// Create a command builder for running a program in the sandbox
    pub fn command(&self, program: impl Into<String>) -> Command<'_, N> {
        Command::new(
            &self.config,
            &self.backend,
            &self.process_tracker,
            program,
        )
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

    /// Get the path to the working directory
    pub fn working_dir(&self) -> &std::path::Path {
        &self.working_dir_path
    }
}

impl<N: NetworkPolicy> Drop for Sandbox<N> {
    fn drop(&mut self) {
        // Always kill all child processes
        self.process_tracker.kill_all();
        tracing::debug!("killed all sandbox child processes");

        // Delete working directory unless keep_working_dir was called
        if !self.keep_working_dir {
            if let Err(e) = remove_dir_all::remove_dir_all(&self.working_dir_path) {
                tracing::warn!(
                    path = %self.working_dir_path.display(),
                    error = %e,
                    "failed to remove working directory"
                );
            } else {
                tracing::debug!(
                    path = %self.working_dir_path.display(),
                    "removed working directory"
                );
            }
        } else {
            tracing::debug!(
                path = %self.working_dir_path.display(),
                "keeping working directory"
            );
        }
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
            let sandbox = result.unwrap();
            let working_dir = sandbox.working_dir().to_path_buf();
            assert!(working_dir.exists());
            drop(sandbox);
            // Working dir should be deleted after drop
            assert!(!working_dir.exists());
        }
    }

    #[test]
    fn test_keep_working_dir() {
        if cfg!(target_os = "macos") {
            let working_dir = {
                let mut sandbox = Sandbox::new().unwrap();
                sandbox.keep_working_dir();
                sandbox.working_dir().to_path_buf()
            };
            // Working dir should still exist after drop
            assert!(working_dir.exists());
            // Clean up manually
            std::fs::remove_dir(&working_dir).ok();
        }
    }
}
