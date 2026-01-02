use std::future::Future;
use std::process::{ExitStatus, Output, Stdio};

use crate::config::SandboxConfigData;
use crate::error::Result;
use crate::sandbox::ProcessTracker;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

/// A spawned child process in the sandbox
pub struct Child {
    inner: std::process::Child,
    tracker: Option<ProcessTracker>,
}

impl Child {
    pub(crate) fn new(inner: std::process::Child) -> Self {
        Self {
            inner,
            tracker: None,
        }
    }

    pub(crate) fn with_tracker(mut self, tracker: ProcessTracker) -> Self {
        self.tracker = Some(tracker);
        self
    }

    fn unregister_if_tracked(&mut self) {
        if let Some(tracker) = self.tracker.take() {
            tracker.unregister(self.id());
        }
    }

    /// Access the child's stdin
    pub fn stdin(&mut self) -> Option<&mut std::process::ChildStdin> {
        self.inner.stdin.as_mut()
    }

    /// Access the child's stdout
    pub fn stdout(&mut self) -> Option<&mut std::process::ChildStdout> {
        self.inner.stdout.as_mut()
    }

    /// Access the child's stderr
    pub fn stderr(&mut self) -> Option<&mut std::process::ChildStderr> {
        self.inner.stderr.as_mut()
    }

    /// Take ownership of the child's stdin
    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.inner.stdin.take()
    }

    /// Take ownership of the child's stdout
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.inner.stdout.take()
    }

    /// Take ownership of the child's stderr
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.inner.stderr.take()
    }

    /// Get the process ID
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Wait for the child to exit
    pub async fn wait(&mut self) -> Result<ExitStatus> {
        // For now, use blocking wait wrapped in a poll
        // In a real implementation, this would use async I/O
        let status = self.inner.wait()?;
        self.unregister_if_tracked();
        Ok(status)
    }

    /// Wait for the child to exit and collect all output
    pub async fn wait_with_output(self) -> Result<Output> {
        // For now, use blocking wait_with_output
        // In a real implementation, this would use async I/O
        let pid = self.inner.id();
        let output = self.inner.wait_with_output()?;
        if let Some(tracker) = self.tracker {
            tracker.unregister(pid);
        }
        Ok(output)
    }

    /// Attempt to kill the child process
    pub fn kill(&mut self) -> Result<()> {
        Ok(self.inner.kill()?)
    }

    /// Check if the child has exited without blocking
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        let status = self.inner.try_wait()?;
        if status.is_some() {
            self.unregister_if_tracked();
        }
        Ok(status)
    }
}

/// Internal trait for platform-specific sandbox backends
pub(crate) trait Backend: Sized + Send + Sync {
    /// Execute a command and wait for completion
    fn execute(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        current_dir: Option<&std::path::Path>,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> impl Future<Output = Result<Output>> + Send;

    /// Spawn a command as a child process
    fn spawn(
        &self,
        config: &SandboxConfigData,
        proxy_port: u16,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
        current_dir: Option<&std::path::Path>,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
    ) -> impl Future<Output = Result<Child>> + Send;
}

/// Create the native backend for the current platform
#[cfg(target_os = "macos")]
pub(crate) fn create_native_backend() -> Result<macos::MacOSBackend> {
    macos::MacOSBackend::new()
}

#[cfg(target_os = "linux")]
pub(crate) fn create_native_backend() -> Result<linux::LinuxBackend> {
    linux::LinuxBackend::new()
}

#[cfg(target_os = "windows")]
pub(crate) fn create_native_backend() -> Result<windows::WindowsBackend> {
    windows::WindowsBackend::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub(crate) fn create_native_backend() -> Result<()> {
    Err(crate::error::Error::UnsupportedPlatform)
}
