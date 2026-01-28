use std::any::TypeId;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::ipc::IpcRouter;
use crate::network::{DenyAll, NetworkPolicy};
use crate::security::SecurityConfig;
use crate::workdir::WorkingDir;

/// Resource limits for sandboxed processes
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    max_memory_bytes: Option<u64>,
    max_cpu_time_secs: Option<u64>,
    max_file_size_bytes: Option<u64>,
    max_processes: Option<u32>,
}

impl ResourceLimits {
    /// Create a new builder for resource limits
    pub fn builder() -> ResourceLimitsBuilder {
        ResourceLimitsBuilder::default()
    }

    pub fn max_memory_bytes(&self) -> Option<u64> {
        self.max_memory_bytes
    }

    pub fn max_cpu_time_secs(&self) -> Option<u64> {
        self.max_cpu_time_secs
    }

    pub fn max_file_size_bytes(&self) -> Option<u64> {
        self.max_file_size_bytes
    }

    pub fn max_processes(&self) -> Option<u32> {
        self.max_processes
    }
}

/// Builder for ResourceLimits
#[derive(Debug, Default)]
pub struct ResourceLimitsBuilder {
    inner: ResourceLimits,
}

impl ResourceLimitsBuilder {
    pub fn max_memory_bytes(mut self, bytes: u64) -> Self {
        self.inner.max_memory_bytes = Some(bytes);
        self
    }

    pub fn max_cpu_time_secs(mut self, secs: u64) -> Self {
        self.inner.max_cpu_time_secs = Some(secs);
        self
    }

    pub fn max_file_size_bytes(mut self, bytes: u64) -> Self {
        self.inner.max_file_size_bytes = Some(bytes);
        self
    }

    pub fn max_processes(mut self, count: u32) -> Self {
        self.inner.max_processes = Some(count);
        self
    }

    pub fn build(self) -> ResourceLimits {
        self.inner
    }
}

/// Configuration for Python virtual environment
#[derive(Debug, Clone)]
pub struct VenvConfig {
    path: PathBuf,
    python: Option<PathBuf>,
    packages: Vec<String>,
    system_site_packages: bool,
    use_uv: bool,
}

impl Default for VenvConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(".sandbox-venv"),
            python: None,
            packages: Vec::new(),
            system_site_packages: true,
            use_uv: true,
        }
    }
}

impl VenvConfig {
    /// Create a new builder for VenvConfig
    pub fn builder() -> VenvConfigBuilder {
        VenvConfigBuilder::default()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn python(&self) -> Option<&Path> {
        self.python.as_deref()
    }

    pub fn packages(&self) -> &[String] {
        &self.packages
    }

    pub fn system_site_packages(&self) -> bool {
        self.system_site_packages
    }

    pub fn use_uv(&self) -> bool {
        self.use_uv
    }
}

/// Builder for VenvConfig
#[derive(Debug, Default)]
pub struct VenvConfigBuilder {
    inner: VenvConfig,
}

impl VenvConfigBuilder {
    pub fn path(mut self, path: impl AsRef<Path>) -> Self {
        self.inner.path = path.as_ref().to_path_buf();
        self
    }

    pub fn python(mut self, python: impl AsRef<Path>) -> Self {
        self.inner.python = Some(python.as_ref().to_path_buf());
        self
    }

    pub fn package(mut self, pkg: impl Into<String>) -> Self {
        self.inner.packages.push(pkg.into());
        self
    }

    pub fn packages(mut self, pkgs: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inner.packages.extend(pkgs.into_iter().map(Into::into));
        self
    }

    pub fn system_site_packages(mut self, enabled: bool) -> Self {
        self.inner.system_site_packages = enabled;
        self
    }

    pub fn use_uv(mut self, enabled: bool) -> Self {
        self.inner.use_uv = enabled;
        self
    }

    pub fn build(self) -> VenvConfig {
        self.inner
    }
}

/// Python sandbox configuration
#[derive(Debug, Clone)]
pub struct PythonConfig {
    venv: VenvConfig,
    allow_pip_install: bool,
}

impl Default for PythonConfig {
    fn default() -> Self {
        Self {
            venv: VenvConfig::default(),
            allow_pip_install: true,
        }
    }
}

impl PythonConfig {
    /// Create a new builder for PythonConfig
    pub fn builder() -> PythonConfigBuilder {
        PythonConfigBuilder::default()
    }

    pub fn venv(&self) -> &VenvConfig {
        &self.venv
    }

    pub fn allow_pip_install(&self) -> bool {
        self.allow_pip_install
    }
}

/// Builder for PythonConfig
#[derive(Debug, Default)]
pub struct PythonConfigBuilder {
    inner: PythonConfig,
}

impl PythonConfigBuilder {
    pub fn venv(mut self, config: VenvConfig) -> Self {
        self.inner.venv = config;
        self
    }

    pub fn allow_pip_install(mut self, enabled: bool) -> Self {
        self.inner.allow_pip_install = enabled;
        self
    }

    pub fn build(self) -> PythonConfig {
        self.inner
    }
}

/// Sandbox configuration data (without network policy)
///
/// This is used internally after the network policy has been extracted
/// for the NetworkProxy.
pub struct SandboxConfigData {
    pub(crate) security: SecurityConfig,
    pub(crate) writable_paths: Vec<PathBuf>,
    pub(crate) readable_paths: Vec<PathBuf>,
    pub(crate) executable_paths: Vec<PathBuf>,
    pub(crate) network_deny_all: bool,
    pub(crate) python: Option<PythonConfig>,
    pub(crate) working_dir: PathBuf,
    pub(crate) working_dir_auto_created: bool,
    pub(crate) filesystem_strict: bool,
    pub(crate) writable_file_system: bool,
    pub(crate) env_passthrough: Vec<String>,
    pub(crate) limits: ResourceLimits,
    pub(crate) ipc: Option<IpcRouter>,
    /// Whether to allow writing to /dev/tty (controlling terminal).
    /// When false, all output must go through stdout/stderr pipes.
    pub(crate) allow_tty_write: bool,
}

impl SandboxConfigData {
    pub fn writable_file_system(&self) -> bool {
        self.writable_file_system
    }

    pub fn security(&self) -> &SecurityConfig {
        &self.security
    }

    pub fn writable_paths(&self) -> &[PathBuf] {
        &self.writable_paths
    }

    pub fn readable_paths(&self) -> &[PathBuf] {
        &self.readable_paths
    }

    pub fn executable_paths(&self) -> &[PathBuf] {
        &self.executable_paths
    }

    pub fn network_deny_all(&self) -> bool {
        self.network_deny_all
    }

    pub fn python(&self) -> Option<&PythonConfig> {
        self.python.as_ref()
    }

    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    pub fn filesystem_strict(&self) -> bool {
        self.filesystem_strict
    }

    pub fn env_passthrough(&self) -> &[String] {
        &self.env_passthrough
    }

    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    pub fn ipc(&self) -> Option<&IpcRouter> {
        self.ipc.as_ref()
    }

    pub fn allow_tty_write(&self) -> bool {
        self.allow_tty_write
    }
}

/// Main sandbox configuration
pub struct SandboxConfig<N: NetworkPolicy = DenyAll> {
    network: N,
    security: SecurityConfig,
    writable_paths: Vec<PathBuf>,
    readable_paths: Vec<PathBuf>,
    executable_paths: Vec<PathBuf>,
    network_deny_all: bool,
    python: Option<PythonConfig>,
    working_dir: PathBuf,
    working_dir_auto_created: bool,
    filesystem_strict: bool,
    writable_file_system: bool,
    env_passthrough: Vec<String>,
    limits: ResourceLimits,
    ipc: Option<IpcRouter>,
    allow_tty_write: bool,
}

impl SandboxConfig<DenyAll> {
    /// Create a new SandboxConfig with default settings
    ///
    /// This creates a random working directory in the current directory
    /// using four English words connected by hyphens.
    pub fn new() -> Result<Self> {
        SandboxConfigBuilder::default().build()
    }

    /// Create a new builder for SandboxConfig
    pub fn builder() -> SandboxConfigBuilder<DenyAll> {
        SandboxConfigBuilder::default()
    }
}

impl<N: NetworkPolicy> SandboxConfig<N> {
    /// Consume the config and return the network policy and remaining config data
    ///
    /// This is used internally by Sandbox to extract the policy for the NetworkProxy.
    pub(crate) fn into_parts(self) -> (N, SandboxConfigData) {
        (
            self.network,
            SandboxConfigData {
                security: self.security,
                writable_paths: self.writable_paths,
                readable_paths: self.readable_paths,
                executable_paths: self.executable_paths,
                network_deny_all: self.network_deny_all,
                python: self.python,
                working_dir: self.working_dir,
                working_dir_auto_created: self.working_dir_auto_created,
                filesystem_strict: self.filesystem_strict,
                writable_file_system: self.writable_file_system,
                env_passthrough: self.env_passthrough,
                limits: self.limits,
                ipc: self.ipc,
                allow_tty_write: self.allow_tty_write,
            },
        )
    }

    pub fn writable_file_system(&self) -> bool {
        self.writable_file_system
    }

    pub fn network(&self) -> &N {
        &self.network
    }

    pub fn security(&self) -> &SecurityConfig {
        &self.security
    }

    pub fn writable_paths(&self) -> &[PathBuf] {
        &self.writable_paths
    }

    pub fn readable_paths(&self) -> &[PathBuf] {
        &self.readable_paths
    }

    pub fn executable_paths(&self) -> &[PathBuf] {
        &self.executable_paths
    }

    pub fn python(&self) -> Option<&PythonConfig> {
        self.python.as_ref()
    }

    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    pub fn filesystem_strict(&self) -> bool {
        self.filesystem_strict
    }

    pub fn env_passthrough(&self) -> &[String] {
        &self.env_passthrough
    }

    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    pub fn ipc(&self) -> Option<&IpcRouter> {
        self.ipc.as_ref()
    }
}

/// Builder for SandboxConfig
pub struct SandboxConfigBuilder<N: NetworkPolicy = DenyAll> {
    network: N,
    security: SecurityConfig,
    writable_paths: Vec<PathBuf>,
    readable_paths: Vec<PathBuf>,
    executable_paths: Vec<PathBuf>,
    network_deny_all: bool,
    python: Option<PythonConfig>,
    working_dir: Option<PathBuf>,
    filesystem_strict: bool,
    writable_file_system: bool,
    env_passthrough: Vec<String>,
    limits: ResourceLimits,
    ipc: Option<IpcRouter>,
    allow_tty_write: bool,
}

impl Default for SandboxConfigBuilder<DenyAll> {
    fn default() -> Self {
        Self {
            network: DenyAll,
            security: SecurityConfig::default(),
            writable_paths: Vec::new(),
            readable_paths: Vec::new(),
            executable_paths: Vec::new(),
            network_deny_all: true,
            python: None,
            working_dir: None, // Will generate random name on build()
            filesystem_strict: false,
            writable_file_system: false,
            env_passthrough: Vec::new(),
            limits: ResourceLimits::default(),
            ipc: None,
            allow_tty_write: false, // Default: deny /dev/tty writes to capture all output
        }
    }
}

impl<N: NetworkPolicy> SandboxConfigBuilder<N> {
    /// Set the network policy (changes the generic type)
    pub fn network<M: NetworkPolicy>(self, policy: M) -> SandboxConfigBuilder<M> {
        SandboxConfigBuilder {
            network: policy,
            security: self.security,
            writable_paths: self.writable_paths,
            readable_paths: self.readable_paths,
            executable_paths: self.executable_paths,
            network_deny_all: TypeId::of::<M>() == TypeId::of::<DenyAll>(),
            python: self.python,
            working_dir: self.working_dir,
            filesystem_strict: self.filesystem_strict,
            writable_file_system: self.writable_file_system,
            env_passthrough: self.env_passthrough,
            limits: self.limits,
            ipc: self.ipc,
            allow_tty_write: self.allow_tty_write,
        }
    }

    /// Set the security configuration
    pub fn security(mut self, security: SecurityConfig) -> Self {
        self.security = security;
        self
    }

    pub fn writable_path(mut self, path: impl AsRef<Path>) -> Self {
        self.writable_paths.push(path.as_ref().to_path_buf());
        self
    }

    pub fn writable_paths(mut self, paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Self {
        self.writable_paths
            .extend(paths.into_iter().map(|p| p.as_ref().to_path_buf()));
        self
    }

    pub fn readable_path(mut self, path: impl AsRef<Path>) -> Self {
        self.readable_paths.push(path.as_ref().to_path_buf());
        self
    }

    pub fn readable_paths(mut self, paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Self {
        self.readable_paths
            .extend(paths.into_iter().map(|p| p.as_ref().to_path_buf()));
        self
    }

    pub fn executable_path(mut self, path: impl AsRef<Path>) -> Self {
        self.executable_paths.push(path.as_ref().to_path_buf());
        self
    }

    pub fn executable_paths(mut self, paths: impl IntoIterator<Item = impl AsRef<Path>>) -> Self {
        self.executable_paths
            .extend(paths.into_iter().map(|p| p.as_ref().to_path_buf()));
        self
    }

    pub fn python(mut self, config: PythonConfig) -> Self {
        self.python = Some(config);
        self
    }

    /// Enable strict filesystem mode (deny reads outside sandbox/allowlist).
    pub fn filesystem_strict(mut self, enabled: bool) -> Self {
        self.filesystem_strict = enabled;
        self
    }

    /// Enable globally writable filesystem
    pub fn writable_file_system(mut self, enabled: bool) -> Self {
        self.writable_file_system = enabled;
        self
    }

    /// Set the working directory path
    ///
    /// If not set, a random directory name will be generated in the current directory.
    /// The directory will be created if it doesn't exist.
    pub fn working_dir(mut self, path: impl AsRef<Path>) -> Self {
        self.working_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn env_passthrough(mut self, var: impl Into<String>) -> Self {
        self.env_passthrough.push(var.into());
        self
    }

    pub fn env_passthroughs(mut self, vars: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.env_passthrough
            .extend(vars.into_iter().map(Into::into));
        self
    }

    pub fn limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Set the IPC router for handling commands from sandboxed processes
    pub fn ipc(mut self, router: IpcRouter) -> Self {
        self.ipc = Some(router);
        self
    }

    /// Allow writing to /dev/tty (controlling terminal)
    ///
    /// When false (default), sandboxed processes cannot write directly to the terminal,
    /// ensuring all output goes through captured stdout/stderr.
    /// Enable this for interactive sessions that need terminal access.
    pub fn allow_tty_write(mut self, enabled: bool) -> Self {
        self.allow_tty_write = enabled;
        self
    }

    pub fn build(self) -> Result<SandboxConfig<N>> {
        // Resolve working directory: use specified path or create random one
        let working_dir_auto_created = self.working_dir.is_none();
        let working_dir = match self.working_dir {
            Some(path) => {
                // User specified a path - create if needed
                if !path.exists() {
                    std::fs::create_dir_all(&path).map_err(|e| {
                        Error::IoError(format!(
                            "Failed to create working directory '{}': {}",
                            path.display(),
                            e
                        ))
                    })?;
                    tracing::debug!(path = %path.display(), "created working directory");
                }
                path
            }
            None => {
                // Generate random working directory
                let work_dir = WorkingDir::random()?;
                tracing::info!(path = %work_dir.path().display(), "created random working directory");
                work_dir.path().to_path_buf()
            }
        };

        Ok(SandboxConfig {
            network: self.network,
            security: self.security,
            writable_paths: self.writable_paths,
            readable_paths: self.readable_paths,
            executable_paths: self.executable_paths,
            network_deny_all: self.network_deny_all,
            python: self.python,
            working_dir,
            working_dir_auto_created,
            filesystem_strict: self.filesystem_strict,
            writable_file_system: self.writable_file_system,
            env_passthrough: self.env_passthrough,
            limits: self.limits,
            ipc: self.ipc,
            allow_tty_write: self.allow_tty_write,
        })
    }
}

/// Create a strict sandbox config with no network and minimal access
///
/// Strict mode denies filesystem reads outside the sandbox/allowlist.
pub fn strict_preset() -> Result<SandboxConfig<DenyAll>> {
    SandboxConfigBuilder::default()
        .filesystem_strict(true)
        .build()
}

/// Create a sandbox config for Python development with pip install capability
pub fn python_dev_preset() -> Result<SandboxConfig<DenyAll>> {
    SandboxConfigBuilder::default()
        .python(PythonConfig::builder().allow_pip_install(true).build())
        .build()
}

/// Create a sandbox config for Python data science with common tools
pub fn python_data_science_preset() -> Result<SandboxConfig<DenyAll>> {
    SandboxConfigBuilder::default()
        .python(
            PythonConfig::builder()
                .venv(
                    VenvConfig::builder()
                        .packages(["numpy", "pandas", "matplotlib", "scikit-learn"])
                        .system_site_packages(true)
                        .build(),
                )
                .allow_pip_install(true)
                .build(),
        )
        .executable_path("/usr/bin/ffmpeg")
        .executable_path("/usr/local/bin/ffmpeg")
        .readable_path("/usr/share")
        .build()
}
