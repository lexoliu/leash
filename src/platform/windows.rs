use std::future::Future;
use std::process::{Output, Stdio};

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::platform::{Backend, Child};

pub struct WindowsBackend;

impl WindowsBackend {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

impl Backend for WindowsBackend {
    fn execute(
        &self,
        _config: &SandboxConfigData,
        _proxy_port: u16,
        _program: &str,
        _args: &[String],
        _envs: &[(String, String)],
        _current_dir: Option<&std::path::Path>,
        _stdin: Stdio,
        _stdout: Stdio,
        _stderr: Stdio,
    ) -> impl Future<Output = Result<Output>> + Send {
        async { Err(Error::UnsupportedPlatform) }
    }

    fn spawn(
        &self,
        _config: &SandboxConfigData,
        _proxy_port: u16,
        _program: &str,
        _args: &[String],
        _envs: &[(String, String)],
        _current_dir: Option<&std::path::Path>,
        _stdin: Stdio,
        _stdout: Stdio,
        _stderr: Stdio,
    ) -> impl Future<Output = Result<Child>> + Send {
        async { Err(Error::UnsupportedPlatform) }
    }
}
