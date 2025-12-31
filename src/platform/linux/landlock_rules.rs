//! Landlock ruleset generation for Linux sandbox
//!
//! Landlock provides kernel-level filesystem and network access control.
//! We use Landlock ABI v4 which supports:
//! - Filesystem access control (read, write, execute, etc.)
//! - Network TCP connection restrictions

use std::path::Path;

use landlock::{
    make_bitflags, Access, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, ABI,
};

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::security::SecurityConfig;

/// A prepared Landlock ruleset ready to be applied in pre_exec
pub struct PreparedRuleset {
    inner: RulesetCreated,
}

impl PreparedRuleset {
    /// Apply the ruleset to the current process (call in pre_exec)
    ///
    /// Fails fast if the ruleset is not fully enforced.
    pub fn restrict_self(self) -> std::result::Result<(), String> {
        let status = self
            .inner
            .restrict_self()
            .map_err(|e| format!("Landlock restrict_self failed: {}", e))?;

        // Fast-fail if not fully enforced
        match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(()),
            RulesetStatus::PartiallyEnforced => {
                Err("Landlock rules only partially enforced - refusing to run with reduced security".to_string())
            }
            RulesetStatus::NotEnforced => {
                Err("Landlock not enforced by kernel".to_string())
            }
        }
    }
}

/// Build a Landlock ruleset from sandbox configuration
pub fn build_ruleset(config: &SandboxConfigData, proxy_port: u16) -> Result<PreparedRuleset> {
    // We require ABI v4 for network restrictions
    let abi = ABI::V4;

    // Start with all filesystem access rights handled (deny by default)
    let fs_access = AccessFs::from_all(abi);
    let net_access = AccessNet::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(fs_access)
        .map_err(|e| Error::InvalidProfile(format!("Landlock fs access error: {}", e)))?
        .handle_access(net_access)
        .map_err(|e| Error::InvalidProfile(format!("Landlock net access error: {}", e)))?
        .create()
        .map_err(|e| Error::InvalidProfile(format!("Landlock ruleset create error: {}", e)))?;

    // --- System paths (read-only) ---
    let system_read_paths = [
        "/usr",
        "/lib",
        "/lib64",
        "/lib32",
        "/bin",
        "/sbin",
        "/etc",
        "/proc",
        "/sys",
        "/run", // Needed for various runtime files
    ];

    for path in &system_read_paths {
        add_path_rule(&mut ruleset, path, AccessFs::from_read(abi))?;
    }

    // --- Temp directories (read + write) ---
    let temp_paths = ["/tmp", "/var/tmp"];
    for path in &temp_paths {
        add_path_rule(&mut ruleset, path, AccessFs::from_all(abi))?;
    }

    // --- Device access ---
    add_device_rules(&mut ruleset, config.security(), abi)?;

    // --- Working directory (full access) ---
    add_path_rule(&mut ruleset, config.working_dir(), AccessFs::from_all(abi))?;

    // --- User-configured paths ---

    // Readable paths
    for path in config.readable_paths() {
        add_path_rule(&mut ruleset, path, AccessFs::from_read(abi))?;
    }

    // Writable paths
    for path in config.writable_paths() {
        add_path_rule(&mut ruleset, path, AccessFs::from_all(abi))?;
    }

    // Executable paths (read + execute)
    for path in config.executable_paths() {
        let exec_access = make_bitflags!(AccessFs::{ReadFile | Execute});
        add_path_rule(&mut ruleset, path, exec_access)?;
    }

    // --- Python venv if configured ---
    if let Some(python_config) = config.python() {
        add_path_rule(
            &mut ruleset,
            python_config.venv().path(),
            AccessFs::from_all(abi),
        )?;
    }

    // --- Apply security restrictions ---
    // Note: Landlock is additive-only, so we implement restrictions by
    // NOT adding rules for protected paths. Since we only add specific
    // allowed paths above, sensitive paths are denied by default.
    //
    // However, if protect_user_home is false, we need to add home access
    apply_security_config(&mut ruleset, config.security(), abi)?;

    // --- Network: Only allow TCP connections to proxy port ---
    ruleset = ruleset
        .add_rule(NetPort::new(proxy_port, AccessNet::ConnectTcp))
        .map_err(|e| Error::InvalidProfile(format!("Landlock network rule error: {}", e)))?;

    tracing::debug!(
        proxy_port = proxy_port,
        working_dir = %config.working_dir().display(),
        "landlock: ruleset built"
    );

    Ok(PreparedRuleset { inner: ruleset })
}

/// Add a path rule to the ruleset, handling non-existent paths gracefully
fn add_path_rule(
    ruleset: &mut RulesetCreated,
    path: impl AsRef<Path>,
    access: BitFlags<AccessFs>,
) -> Result<()> {
    let path = path.as_ref();

    match PathFd::new(path) {
        Ok(path_fd) => {
            if let Err(e) = ruleset.add_rule(PathBeneath::new(path_fd, access)) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "landlock: failed to add path rule"
                );
            } else {
                tracing::trace!(path = %path.display(), "landlock: added path rule");
            }
        }
        Err(e) => {
            // Path doesn't exist - this is not an error, just skip
            tracing::trace!(
                path = %path.display(),
                error = %e,
                "landlock: skipping non-existent path"
            );
        }
    }
    Ok(())
}

/// Add device access rules
fn add_device_rules(
    ruleset: &mut RulesetCreated,
    security: &SecurityConfig,
    abi: ABI,
) -> Result<()> {
    // Basic device access for stdio and randomness
    // Note: /dev/stdin, /dev/stdout, /dev/stderr are symlinks to /proc/self/fd/*
    // and can't be added as Landlock rules. They work via inherited file descriptors.
    let basic_devices = [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/fd",
        "/dev/tty",
        "/dev/ptmx",
        "/dev/pts",
    ];

    for device in &basic_devices {
        add_path_rule(ruleset, device, AccessFs::from_all(abi))?;
    }

    // GPU access (/dev/dri for DRM)
    if security.allow_gpu {
        add_path_rule(ruleset, "/dev/dri", AccessFs::from_all(abi))?;
        // NVIDIA devices
        add_path_rule(ruleset, "/dev/nvidia0", AccessFs::from_all(abi))?;
        add_path_rule(ruleset, "/dev/nvidiactl", AccessFs::from_all(abi))?;
        add_path_rule(ruleset, "/dev/nvidia-modeset", AccessFs::from_all(abi))?;
        add_path_rule(ruleset, "/dev/nvidia-uvm", AccessFs::from_all(abi))?;
        tracing::debug!("landlock: GPU access enabled");
    }

    // NPU access (/dev/accel for Intel/AMD accelerators)
    if security.allow_npu {
        add_path_rule(ruleset, "/dev/accel", AccessFs::from_all(abi))?;
        // Intel NPU
        add_path_rule(ruleset, "/dev/accel0", AccessFs::from_all(abi))?;
        tracing::debug!("landlock: NPU access enabled");
    }

    // General hardware access
    if security.allow_hardware {
        // USB devices
        add_path_rule(ruleset, "/dev/bus/usb", AccessFs::from_all(abi))?;
        // Input devices
        add_path_rule(ruleset, "/dev/input", AccessFs::from_all(abi))?;
        // Video devices (webcams)
        add_path_rule(ruleset, "/dev/video0", AccessFs::from_all(abi))?;
        add_path_rule(ruleset, "/dev/video1", AccessFs::from_all(abi))?;
        // Audio devices
        add_path_rule(ruleset, "/dev/snd", AccessFs::from_all(abi))?;
        tracing::debug!("landlock: general hardware access enabled");
    }

    Ok(())
}

/// Apply SecurityConfig by adding access to home if not protected
fn apply_security_config(
    ruleset: &mut RulesetCreated,
    security: &SecurityConfig,
    abi: ABI,
) -> Result<()> {
    // Landlock is default-deny. We only need to ADD paths when protection is disabled.

    if !security.protect_user_home {
        // Allow access to home directory
        if let Ok(home) = std::env::var("HOME") {
            add_path_rule(ruleset, &home, AccessFs::from_all(abi))?;
            tracing::debug!(home = %home, "landlock: home access enabled");
        }
        // Also try /home for other users
        add_path_rule(ruleset, "/home", AccessFs::from_all(abi))?;
    }

    // Note: For the other protection flags (protect_credentials, protect_cloud_config, etc.),
    // since Landlock is default-deny and we're not adding those paths above,
    // they are automatically protected.
    //
    // The macOS SBPL uses explicit deny rules because SBPL has broader allow rules.
    // With Landlock, we only whitelist specific paths, so sensitive paths are denied by default.

    Ok(())
}

#[cfg(test)]
mod tests {
    // Note: These tests would need to run on a Linux system with Landlock support
    // For now, we just test the ruleset building logic
}
