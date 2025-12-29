use std::fmt::Write;
use std::path::Path;

use crate::config::SandboxConfig;
use crate::error::SandboxResult;
use crate::network::NetworkPolicy;

/// Generate an SBPL profile from sandbox configuration
pub fn generate_profile<N: NetworkPolicy>(config: &SandboxConfig<N>) -> SandboxResult<String> {
    let mut profile = String::new();

    // Version declaration (required)
    writeln!(profile, "(version 1)").unwrap();

    // Default deny - most secure approach
    writeln!(profile, "(deny default)").unwrap();

    tracing::debug!("sandbox policy: deny all by default");

    // Allow basic system operations needed for most programs
    write_system_basics(&mut profile);

    // Allow configured readable paths
    for path in config.readable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow read");
        write_read_path(&mut profile, path);
    }

    // Allow configured writable paths
    for path in config.writable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow write");
        write_write_path(&mut profile, path);
    }

    // Allow configured executable paths
    for path in config.executable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow exec");
        write_exec_path(&mut profile, path);
    }

    // Allow working directory access
    tracing::debug!(path = %config.working_dir().display(), "sandbox: allow write (working dir)");
    write_write_path(&mut profile, config.working_dir());

    // Python venv configuration
    if let Some(python_config) = config.python() {
        tracing::debug!(path = %python_config.venv().path().display(), "sandbox: allow python venv");
        write_python_paths(&mut profile, python_config.venv().path());
    }

    // Network configuration - deny all by default
    // TODO: Implement proxy-based network filtering for callback policies
    tracing::debug!("sandbox: deny network");
    writeln!(profile, "(deny network*)").unwrap();

    Ok(profile)
}

fn write_system_basics(profile: &mut String) {
    // Allow necessary Mach and sysctl operations
    writeln!(profile, "(allow mach*)").unwrap();
    writeln!(profile, "(allow sysctl-read)").unwrap();
    writeln!(profile, "(allow iokit-open)").unwrap();

    // Allow reading all files - macOS processes need access to dyld cache,
    // system libraries, and other paths that are hard to enumerate.
    // Security is enforced via write restrictions and network policy.
    writeln!(profile, "(allow file-read*)").unwrap();

    // Allow write to temp directories only
    writeln!(profile, r#"(allow file-write* (subpath "/private/tmp"))"#).unwrap();
    writeln!(profile, r#"(allow file-write* (subpath "/tmp"))"#).unwrap();
    writeln!(profile, r#"(allow file-write* (subpath "/var/folders"))"#).unwrap();
    writeln!(profile, r#"(allow file-write* (subpath "/private/var/folders"))"#).unwrap();

    // Allow write to /dev for stdio
    writeln!(profile, r#"(allow file-write* (subpath "/dev"))"#).unwrap();

    // Allow process operations
    writeln!(profile, "(allow process-fork)").unwrap();
    writeln!(profile, "(allow process-exec)").unwrap();

    // Allow signal operations
    writeln!(profile, "(allow signal)").unwrap();

    // Allow IPC
    writeln!(profile, "(allow ipc-posix*)").unwrap();

    // Allow file locking
    writeln!(profile, "(allow file-lock)").unwrap();
}

fn write_read_path(profile: &mut String, path: &Path) {
    let escaped = escape_path(path);
    writeln!(profile, r#"(allow file-read* (subpath "{}"))"#, escaped).unwrap();
}

fn write_write_path(profile: &mut String, path: &Path) {
    let escaped = escape_path(path);
    writeln!(profile, r#"(allow file-read* (subpath "{}"))"#, escaped).unwrap();
    writeln!(profile, r#"(allow file-write* (subpath "{}"))"#, escaped).unwrap();
}

fn write_exec_path(profile: &mut String, path: &Path) {
    let escaped = escape_path(path);
    writeln!(profile, r#"(allow file-read* (literal "{}"))"#, escaped).unwrap();
    writeln!(profile, r#"(allow process-exec (literal "{}"))"#, escaped).unwrap();
}

fn write_python_paths(profile: &mut String, venv_path: &Path) {
    let escaped = escape_path(venv_path);

    // Allow full access to venv directory (for pip install)
    writeln!(profile, r#"(allow file-read* (subpath "{}"))"#, escaped).unwrap();
    writeln!(profile, r#"(allow file-write* (subpath "{}"))"#, escaped).unwrap();
    writeln!(profile, r#"(allow process-exec (subpath "{}"))"#, escaped).unwrap();

    // Allow access to Homebrew python if present
    writeln!(
        profile,
        r#"(allow file-read* (subpath "/opt/homebrew/Cellar/python"))"#
    )
    .unwrap();
    writeln!(
        profile,
        r#"(allow process-exec (subpath "/opt/homebrew/Cellar/python"))"#
    )
    .unwrap();
    writeln!(
        profile,
        r#"(allow file-read* (subpath "/opt/homebrew/Frameworks/Python.framework"))"#
    )
    .unwrap();
    writeln!(
        profile,
        r#"(allow process-exec (subpath "/opt/homebrew/Frameworks/Python.framework"))"#
    )
    .unwrap();
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
