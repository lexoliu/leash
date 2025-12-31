use std::path::Path;
use std::process::Output;

use anyhow::Result;

use leash::{
    AllowAll, AllowList, Command, DenyAll, PtyExitStatus, PythonConfig, Sandbox, SandboxConfig,
    SandboxConfigBuilder, VenvConfig,
};

use crate::cli::NetworkMode;
use crate::config::MergedConfig;

/// Type-erased sandbox handle for CLI use
///
/// This enum dispatches to the appropriate generic Sandbox type at runtime,
/// bridging the CLI's runtime configuration to the library's compile-time generics.
pub enum SandboxHandle {
    DenyAll(Sandbox<DenyAll>),
    AllowAll(Sandbox<AllowAll>),
    AllowList(Sandbox<AllowList>),
}

impl SandboxHandle {
    /// Create a command builder for running a program in the sandbox
    pub fn command(&self, program: impl Into<String>) -> Command<'_> {
        match self {
            Self::DenyAll(s) => s.command(program),
            Self::AllowAll(s) => s.command(program),
            Self::AllowList(s) => s.command(program),
        }
    }

    /// Get the path to the working directory
    pub fn working_dir(&self) -> &Path {
        match self {
            Self::DenyAll(s) => s.working_dir(),
            Self::AllowAll(s) => s.working_dir(),
            Self::AllowList(s) => s.working_dir(),
        }
    }

    /// Keep the working directory after the sandbox is dropped
    pub fn keep_working_dir(&mut self) {
        match self {
            Self::DenyAll(s) => {
                s.keep_working_dir();
            }
            Self::AllowAll(s) => {
                s.keep_working_dir();
            }
            Self::AllowList(s) => {
                s.keep_working_dir();
            }
        }
    }

    /// Run a Python script in the sandbox
    pub async fn run_python(&self, script: &str) -> leash::Result<Output> {
        match self {
            Self::DenyAll(s) => s.run_python(script).await,
            Self::AllowAll(s) => s.run_python(script).await,
            Self::AllowList(s) => s.run_python(script).await,
        }
    }

    /// Get the proxy URL
    pub fn proxy_url(&self) -> String {
        match self {
            Self::DenyAll(s) => s.proxy_url(),
            Self::AllowAll(s) => s.proxy_url(),
            Self::AllowList(s) => s.proxy_url(),
        }
    }

    /// Run an interactive command with PTY support
    #[cfg(target_os = "macos")]
    pub fn run_interactive(
        &self,
        program: &str,
        args: &[String],
        envs: &[(String, String)],
    ) -> leash::Result<PtyExitStatus> {
        match self {
            Self::DenyAll(s) => s.run_interactive(program, args, envs),
            Self::AllowAll(s) => s.run_interactive(program, args, envs),
            Self::AllowList(s) => s.run_interactive(program, args, envs),
        }
    }
}

/// Create a sandbox from merged configuration
pub async fn create_sandbox(config: &MergedConfig) -> Result<SandboxHandle> {
    match config.network_mode {
        NetworkMode::Deny => {
            let sandbox_config = build_config(SandboxConfigBuilder::default(), config)?;
            let sandbox = Sandbox::with_config(sandbox_config).await?;
            Ok(SandboxHandle::DenyAll(sandbox))
        }
        NetworkMode::Allow => {
            let sandbox_config =
                build_config(SandboxConfigBuilder::default().network(AllowAll), config)?;
            let sandbox = Sandbox::with_config(sandbox_config).await?;
            Ok(SandboxHandle::AllowAll(sandbox))
        }
        NetworkMode::AllowList => {
            if config.allow_domains.is_empty() {
                anyhow::bail!("--network allow-list requires at least one --allow-domain");
            }
            let policy = AllowList::new(config.allow_domains.iter().cloned());
            let sandbox_config =
                build_config(SandboxConfigBuilder::default().network(policy), config)?;
            let sandbox = Sandbox::with_config(sandbox_config).await?;
            Ok(SandboxHandle::AllowList(sandbox))
        }
    }
}

/// Build a SandboxConfig from merged CLI/file configuration
fn build_config<N: leash::NetworkPolicy>(
    builder: SandboxConfigBuilder<N>,
    config: &MergedConfig,
) -> Result<SandboxConfig<N>> {
    let mut builder = builder
        .security(config.security.clone())
        .limits(config.limits.clone())
        .readable_paths(config.readable_paths.iter().cloned())
        .writable_paths(config.writable_paths.iter().cloned())
        .executable_paths(config.executable_paths.iter().cloned())
        .env_passthroughs(config.env_passthroughs.iter().cloned());

    // Set working directory if specified
    if let Some(ref dir) = config.working_dir {
        builder = builder.working_dir(dir);
    }

    // Add Python config if venv or packages are specified
    if config.python.venv.is_some() || !config.python.packages.is_empty() {
        let mut venv_builder = VenvConfig::builder();

        if let Some(ref venv_path) = config.python.venv {
            venv_builder = venv_builder.path(venv_path);
        }
        if let Some(ref interpreter) = config.python.interpreter {
            venv_builder = venv_builder.python(interpreter);
        }
        if !config.python.packages.is_empty() {
            venv_builder = venv_builder.packages(config.python.packages.iter().cloned());
        }
        venv_builder = venv_builder
            .system_site_packages(config.python.system_site_packages)
            .use_uv(config.python.use_uv);

        let python_config = PythonConfig::builder()
            .venv(venv_builder.build())
            .allow_pip_install(config.python.allow_pip_install)
            .build();

        builder = builder.python(python_config);
    }

    Ok(builder.build()?)
}
