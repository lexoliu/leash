//! SBPL profile generation using compile-time templates

use std::path::Path;

use askama::Template;

use crate::config::SandboxConfig;
use crate::error::SandboxResult;
use crate::network::NetworkPolicy;

/// Network mode for SBPL profile
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Deny all network access
    Deny,
    /// Allow all network access
    Allow,
    /// Allow only localhost (for proxy)
    Proxy,
}

/// SBPL profile template
#[derive(Template)]
#[template(path = "sandbox.txt", escape = "none")]
struct SandboxProfile {
    readable_paths: Vec<String>,
    writable_paths: Vec<String>,
    executable_paths: Vec<String>,
    working_dir: String,
    python_venv_path: Option<String>,
    network_mode: String,
    security_deny_rules: Vec<String>,
}

/// Generate an SBPL profile from sandbox configuration
pub fn generate_profile<N: NetworkPolicy>(config: &SandboxConfig<N>) -> SandboxResult<String> {
    generate_profile_with_mode(config, NetworkMode::Deny)
}

/// Generate a profile that allows network via localhost proxy
pub fn generate_profile_with_proxy<N: NetworkPolicy>(
    config: &SandboxConfig<N>,
    _proxy_port: u16,
) -> SandboxResult<String> {
    generate_profile_with_mode(config, NetworkMode::Proxy)
}

/// Generate a profile with the specified network mode
fn generate_profile_with_mode<N: NetworkPolicy>(
    config: &SandboxConfig<N>,
    network_mode: NetworkMode,
) -> SandboxResult<String> {
    // Log the configuration
    tracing::debug!("sandbox policy: deny all by default");

    for path in config.readable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow read");
    }

    for path in config.writable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow write");
    }

    for path in config.executable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow exec");
    }

    tracing::debug!(path = %config.working_dir().display(), "sandbox: allow write (working dir)");

    if let Some(python_config) = config.python() {
        tracing::debug!(path = %python_config.venv().path().display(), "sandbox: allow python venv");
    }

    match network_mode {
        NetworkMode::Deny => tracing::debug!("sandbox: deny network"),
        NetworkMode::Allow => tracing::debug!("sandbox: allow network"),
        NetworkMode::Proxy => tracing::debug!("sandbox: allow network to localhost proxy"),
    }

    // Prepare template data
    let template = SandboxProfile {
        readable_paths: config
            .readable_paths()
            .iter()
            .map(|p| escape_path(p))
            .collect(),
        writable_paths: config
            .writable_paths()
            .iter()
            .map(|p| escape_path(p))
            .collect(),
        executable_paths: config
            .executable_paths()
            .iter()
            .map(|p| escape_path(p))
            .collect(),
        working_dir: escape_path(config.working_dir()),
        python_venv_path: config.python().map(|p| escape_path(p.venv().path())),
        network_mode: match network_mode {
            NetworkMode::Deny => "deny".to_string(),
            NetworkMode::Allow => "allow".to_string(),
            NetworkMode::Proxy => "proxy".to_string(),
        },
        security_deny_rules: config
            .security()
            .sbpl_deny_rules()
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };

    let profile = template.render().map_err(|e| {
        crate::error::SandboxError::InvalidProfile(format!("Template render error: {}", e))
    })?;

    tracing::debug!("Generated SBPL profile:\n{}", profile);

    Ok(profile)
}

fn escape_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxConfig;
    use crate::network::DenyAll;

    #[test]
    fn test_generate_basic_profile() {
        let config = SandboxConfig::<DenyAll>::default();
        let profile = generate_profile(&config).unwrap();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn test_escape_path() {
        assert_eq!(escape_path(Path::new("/usr/bin")), "/usr/bin");
        assert_eq!(
            escape_path(Path::new("/path/with spaces")),
            "/path/with spaces"
        );
        assert_eq!(
            escape_path(Path::new(r#"/path/with"quote"#)),
            r#"/path/with\"quote"#
        );
    }
}
