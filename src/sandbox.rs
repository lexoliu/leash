use std::path::PathBuf;
use std::process::Output;
use std::sync::{Arc, Mutex};

use executor_core::async_executor::AsyncExecutor;
use executor_core::{try_init_global_executor, DefaultExecutor, Executor};

use crate::command::Command;
use crate::config::{SandboxConfig, SandboxConfigData};
use crate::error::Result;
use crate::ipc::IpcServer;
use crate::network::{DenyAll, NetworkPolicy, NetworkProxy};
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
    #[allow(dead_code)]
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
/// All network traffic from sandboxed processes is routed through a local proxy
/// that applies the configured NetworkPolicy for filtering and logging.
///
/// When dropped, the sandbox will:
/// - Stop the network proxy
/// - Stop the IPC server (if enabled)
/// - Kill all child processes that were spawned within it
/// - Delete the working directory (unless `keep_working_dir()` was called)
pub struct Sandbox<N: NetworkPolicy = DenyAll> {
    config_data: SandboxConfigData,
    backend: NativeBackend,
    proxy: NetworkProxy<N>,
    ipc_server: Option<IpcServer>,
    process_tracker: ProcessTracker,
    working_dir_path: PathBuf,
    keep_working_dir: bool,
}

impl Sandbox<DenyAll> {
    /// Create a new sandbox with default configuration
    ///
    /// Uses the global executor from executor-core (initialized with AsyncExecutor if not set).
    /// Creates a random working directory in the current directory
    /// using four English words connected by hyphens.
    ///
    /// By default, all network access is denied (DenyAll policy).
    pub async fn new() -> Result<Self> {
        let _ = try_init_global_executor(AsyncExecutor::new());
        Self::with_config_and_executor(SandboxConfig::new()?, DefaultExecutor).await
    }

    /// Create a new sandbox with a custom executor
    ///
    /// Use this when you want to integrate with a specific async runtime
    /// (e.g., tokio, async-std) instead of the default executor.
    pub async fn with_executor<E: Executor + Clone + 'static>(executor: E) -> Result<Self> {
        Self::with_config_and_executor(SandboxConfig::new()?, executor).await
    }
}

impl<N: NetworkPolicy + 'static> Sandbox<N> {
    /// Create a sandbox with custom configuration
    ///
    /// Uses the global executor from executor-core (initialized with AsyncExecutor if not set).
    pub async fn with_config(config: SandboxConfig<N>) -> Result<Self> {
        let _ = try_init_global_executor(AsyncExecutor::new());
        Self::with_config_and_executor(config, DefaultExecutor).await
    }

    /// Create a sandbox with custom configuration and executor
    ///
    /// Use this when you want full control over both the configuration
    /// and the async runtime executor.
    pub async fn with_config_and_executor<E: Executor + Clone + 'static>(
        config: SandboxConfig<N>,
        executor: E,
    ) -> Result<Self> {
        let backend = platform::create_native_backend()?;

        // Extract the network policy for the proxy
        let (policy, mut config_data) = config.into_parts();
        let working_dir_path = config_data.working_dir.clone();

        // Create and start the network proxy
        let proxy = NetworkProxy::new(policy, executor.clone()).await?;

        // Start IPC server if configured
        let ipc_server = if let Some(router) = config_data.ipc.take() {
            let socket_path = working_dir_path.join(".leash").join("ipc.sock");
            let server = IpcServer::new(router, &socket_path, executor).await?;
            tracing::info!(socket_path = %socket_path.display(), "IPC server started");
            Some(server)
        } else {
            None
        };

        tracing::info!(
            proxy_addr = %proxy.addr(),
            working_dir = %working_dir_path.display(),
            "sandbox created"
        );

        Ok(Self {
            config_data,
            backend,
            proxy,
            ipc_server,
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

    /// Get the proxy URL for environment variables
    ///
    /// This URL should be set as HTTP_PROXY and HTTPS_PROXY for processes
    /// that need network access through the sandbox's proxy.
    pub fn proxy_url(&self) -> String {
        self.proxy.proxy_url()
    }

    /// Create a command builder for running a program in the sandbox
    ///
    /// The command will automatically have HTTP_PROXY and HTTPS_PROXY
    /// environment variables set to route traffic through the sandbox's proxy.
    /// If IPC is configured, LEASH_IPC_SOCKET will also be set.
    pub fn command(&self, program: impl Into<String>) -> Command<'_> {
        let ipc_socket_path = self
            .ipc_server
            .as_ref()
            .map(|s| s.socket_path().to_path_buf());
        Command::new(
            &self.config_data,
            &self.backend,
            &self.process_tracker,
            &self.proxy,
            ipc_socket_path,
            program,
        )
    }

    /// Run a Python script in the sandbox
    ///
    /// The script will be executed using the Python interpreter from the configured
    /// virtual environment, or the system Python if no venv is configured.
    pub async fn run_python(&self, script: &str) -> Result<Output> {
        // Determine the Python interpreter to use
        let python = if let Some(python_config) = self.config_data.python() {
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

    /// Get a reference to the sandbox configuration data
    pub fn config(&self) -> &SandboxConfigData {
        &self.config_data
    }

    /// Get the path to the working directory
    pub fn working_dir(&self) -> &std::path::Path {
        &self.working_dir_path
    }

    /// Run an interactive command with PTY support
    ///
    /// This method spawns the command with a proper pseudo-terminal, enabling
    /// interactive shell sessions with line editing, job control, and proper
    /// terminal handling. Use this for `leash shell` or any interactive command.
    ///
    /// # Arguments
    /// * `program` - The program to run
    /// * `args` - Arguments to pass to the program
    /// * `envs` - Additional environment variables to set
    ///
    /// # Returns
    /// The exit status of the command
    #[cfg(target_os = "macos")]
    pub fn run_interactive(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
    ) -> Result<crate::pty::PtyExitStatus> {
        crate::pty::run_with_pty(
            &self.config_data,
            &self.proxy,
            program,
            args,
            envs,
            None,
        )
    }
}

impl<N: NetworkPolicy> Drop for Sandbox<N> {
    fn drop(&mut self) {
        // Stop the IPC server and remove socket file
        if let Some(ref ipc_server) = self.ipc_server {
            ipc_server.stop();
            tracing::debug!("stopped IPC server");
        }
        // Drop the IPC server to remove socket file before removing working dir
        self.ipc_server.take();

        // Stop the network proxy
        self.proxy.stop();
        tracing::debug!("stopped network proxy");

        // Kill all child processes
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

    #[tokio::test]
    async fn test_sandbox_creation() {
        // This may fail on non-macOS platforms currently
        if cfg!(target_os = "macos") {
            let sandbox = Sandbox::new().await.unwrap();
            let working_dir = sandbox.working_dir().to_path_buf();
            assert!(working_dir.exists());
            drop(sandbox);
            // Working dir should be deleted after drop
            assert!(!working_dir.exists());
        }
    }

    #[tokio::test]
    async fn test_keep_working_dir() {
        if cfg!(target_os = "macos") {
            let working_dir = {
                let mut sandbox = Sandbox::new().await.unwrap();
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
