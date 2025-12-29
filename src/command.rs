use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output, Stdio};

use crate::config::SandboxConfig;
use crate::error::SandboxResult;
use crate::network::NetworkPolicy;
use crate::platform::{Backend, Child};

#[cfg(target_os = "macos")]
type NativeBackend = crate::platform::macos::MacOSBackend;

#[cfg(target_os = "linux")]
type NativeBackend = crate::platform::linux::LinuxBackend;

#[cfg(target_os = "windows")]
type NativeBackend = crate::platform::windows::WindowsBackend;

/// Standard I/O configuration for a sandboxed command
#[derive(Debug, Clone, Copy)]
pub enum StdioConfig {
    /// Inherit from parent process
    Inherit,
    /// Create a new pipe
    Piped,
    /// Redirect to null
    Null,
}

impl From<StdioConfig> for Stdio {
    fn from(config: StdioConfig) -> Self {
        match config {
            StdioConfig::Inherit => Stdio::inherit(),
            StdioConfig::Piped => Stdio::piped(),
            StdioConfig::Null => Stdio::null(),
        }
    }
}

/// A builder for sandboxed commands, similar to smol::process::Command
pub struct Command<'a, N: NetworkPolicy> {
    sandbox_config: &'a SandboxConfig<N>,
    backend: &'a NativeBackend,
    program: String,
    args: Vec<String>,
    envs: Vec<(String, String)>,
    current_dir: Option<PathBuf>,
    stdin: StdioConfig,
    stdout: StdioConfig,
    stderr: StdioConfig,
}

impl<'a, N: NetworkPolicy> Command<'a, N> {
    /// Create a new command builder (internal use)
    pub(crate) fn new(
        sandbox_config: &'a SandboxConfig<N>,
        backend: &'a NativeBackend,
        program: impl Into<String>,
    ) -> Self {
        Self {
            sandbox_config,
            backend,
            program: program.into(),
            args: Vec::new(),
            envs: Vec::new(),
            current_dir: None,
            stdin: StdioConfig::Inherit,
            stdout: StdioConfig::Inherit,
            stderr: StdioConfig::Inherit,
        }
    }

    /// Add a single argument
    pub fn arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    /// Add multiple arguments
    pub fn args(mut self, args: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_string()));
        self
    }

    /// Set an environment variable
    pub fn env(mut self, key: impl AsRef<str>, val: impl AsRef<str>) -> Self {
        self.envs
            .push((key.as_ref().to_string(), val.as_ref().to_string()));
        self
    }

    /// Set multiple environment variables
    pub fn envs(
        mut self,
        envs: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>,
    ) -> Self {
        self.envs.extend(
            envs.into_iter()
                .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string())),
        );
        self
    }

    /// Set the working directory
    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.current_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Configure stdin
    pub fn stdin(mut self, cfg: StdioConfig) -> Self {
        self.stdin = cfg;
        self
    }

    /// Configure stdout
    pub fn stdout(mut self, cfg: StdioConfig) -> Self {
        self.stdout = cfg;
        self
    }

    /// Configure stderr
    pub fn stderr(mut self, cfg: StdioConfig) -> Self {
        self.stderr = cfg;
        self
    }

    /// Run the command and wait for completion, collecting all output
    pub async fn output(self) -> SandboxResult<Output> {
        self.backend
            .execute(
                self.sandbox_config,
                &self.program,
                &self.args,
                &self.envs,
                self.current_dir.as_deref(),
                Stdio::null(),
                Stdio::piped(),
                Stdio::piped(),
            )
            .await
    }

    /// Run the command and wait for completion, returning only the exit status
    pub async fn status(self) -> SandboxResult<ExitStatus> {
        let output = self
            .backend
            .execute(
                self.sandbox_config,
                &self.program,
                &self.args,
                &self.envs,
                self.current_dir.as_deref(),
                self.stdin.into(),
                self.stdout.into(),
                self.stderr.into(),
            )
            .await?;
        Ok(output.status)
    }

    /// Spawn the command as a child process for streaming I/O
    pub async fn spawn(self) -> SandboxResult<Child> {
        self.backend
            .spawn(
                self.sandbox_config,
                &self.program,
                &self.args,
                &self.envs,
                self.current_dir.as_deref(),
                self.stdin.into(),
                self.stdout.into(),
                self.stderr.into(),
            )
            .await
    }
}
