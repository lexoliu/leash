//! Security configuration for sandbox profiles
//!
//! The sandbox profile is static (generated at creation time), so security
//! is configured via a builder with toggles for each protection category.
//!
//! # Presets
//!
//! - `SecurityConfig::privacy_first()` - Maximum privacy protection (default)
//! - `SecurityConfig::permissive()` - Minimal restrictions, only logging
//!
//! # Custom Configuration
//!
//! ```rust,ignore
//! use native_sandbox::SecurityConfig;
//!
//! let config = SecurityConfig::builder()
//!     .protect_credentials(true)
//!     .protect_browser_data(true)
//!     .protect_user_home(false)  // Allow access to home directory
//!     .build();
//! ```

/// Static security configuration for sandbox profile generation
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Protect user home directories (/Users, /home)
    pub protect_user_home: bool,
    /// Protect SSH/GPG credentials (.ssh, .gnupg)
    pub protect_credentials: bool,
    /// Protect cloud provider config (.aws, .kube, .docker)
    pub protect_cloud_config: bool,
    /// Protect browser data (cookies, history, passwords)
    pub protect_browser_data: bool,
    /// Protect system keychain
    pub protect_keychain: bool,
    /// Protect shell history (.bash_history, .zsh_history, etc.)
    pub protect_shell_history: bool,
    /// Protect package manager credentials (.npmrc, .pypirc, .netrc)
    pub protect_package_credentials: bool,
    /// Allow GPU access (Metal, CUDA, OpenCL, etc.)
    /// Enabled by default - essential for graphics and compute workloads
    pub allow_gpu: bool,
    /// Allow NPU/Neural Engine access (CoreML, ANE on Apple Silicon)
    /// Enabled by default - essential for ML/AI workloads
    pub allow_npu: bool,
    /// Allow general hardware access (USB, Bluetooth, cameras, etc.)
    /// Disabled by default in strict mode
    pub allow_hardware: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::strict()
    }
}

impl SecurityConfig {
    /// Strict preset - maximum protection (default)
    ///
    /// All sensitive data protection is enabled.
    /// GPU and NPU access allowed (essential for ML workloads).
    /// General hardware access is disabled.
    pub fn strict() -> Self {
        Self {
            protect_user_home: true,
            protect_credentials: true,
            protect_cloud_config: true,
            protect_browser_data: true,
            protect_keychain: true,
            protect_shell_history: true,
            protect_package_credentials: true,
            allow_gpu: true,
            allow_npu: true,
            allow_hardware: false,
        }
    }

    /// Permissive preset - minimal restrictions
    ///
    /// Use when you fully trust the sandboxed code.
    /// Logging still works for audit purposes.
    /// All hardware access is allowed.
    pub fn permissive() -> Self {
        Self {
            protect_user_home: false,
            protect_credentials: false,
            protect_cloud_config: false,
            protect_browser_data: false,
            protect_keychain: false,
            protect_shell_history: false,
            protect_package_credentials: false,
            allow_gpu: true,
            allow_npu: true,
            allow_hardware: true,
        }
    }

    /// Create a builder for custom configuration
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::default()
    }

    /// Generate SBPL deny rules based on configuration
    pub fn sbpl_deny_rules(&self) -> Vec<&'static str> {
        let mut rules = Vec::new();

        if self.protect_user_home {
            rules.push(r#"(deny file-read* (subpath "/Users") (with no-log))"#);
        }

        if self.protect_credentials {
            rules.push(r#"(deny file-read* (regex #"\.ssh") (with no-log))"#);
            rules.push(r#"(deny file-read* (regex #"\.gnupg") (with no-log))"#);
        }

        if self.protect_cloud_config {
            rules.push(r#"(deny file-read* (regex #"\.aws") (with no-log))"#);
            rules.push(r#"(deny file-read* (regex #"\.kube") (with no-log))"#);
            rules.push(r#"(deny file-read* (regex #"\.docker") (with no-log))"#);
        }

        if self.protect_browser_data {
            rules.push(
                r#"(deny file-read* (regex #"Library/Application Support/Google/Chrome") (with no-log))"#,
            );
            rules.push(
                r#"(deny file-read* (regex #"Library/Application Support/Firefox") (with no-log))"#,
            );
            rules.push(r#"(deny file-read* (regex #"Library/Safari") (with no-log))"#);
            rules.push(r#"(deny file-read* (regex #"Library/Cookies") (with no-log))"#);
        }

        if self.protect_keychain {
            rules.push(r#"(deny file-read* (regex #"Library/Keychains") (with no-log))"#);
        }

        if self.protect_shell_history {
            rules.push(r#"(deny file-read* (regex #"\.(bash|zsh|fish)_history") (with no-log))"#);
        }

        if self.protect_package_credentials {
            rules.push(r#"(deny file-read* (regex #"\.netrc") (with no-log))"#);
            rules.push(r#"(deny file-read* (regex #"\.npmrc") (with no-log))"#);
            rules.push(r#"(deny file-read* (regex #"\.pypirc") (with no-log))"#);
        }

        rules
    }
}

/// Builder for SecurityConfig
#[derive(Debug, Clone)]
pub struct SecurityConfigBuilder {
    config: SecurityConfig,
}

impl Default for SecurityConfigBuilder {
    fn default() -> Self {
        Self {
            config: SecurityConfig::strict(),
        }
    }
}

impl SecurityConfigBuilder {
    /// Start from permissive config
    pub fn from_permissive() -> Self {
        Self {
            config: SecurityConfig::permissive(),
        }
    }

    /// Protect user home directories
    pub fn protect_user_home(mut self, enabled: bool) -> Self {
        self.config.protect_user_home = enabled;
        self
    }

    /// Protect SSH/GPG credentials
    pub fn protect_credentials(mut self, enabled: bool) -> Self {
        self.config.protect_credentials = enabled;
        self
    }

    /// Protect cloud provider config
    pub fn protect_cloud_config(mut self, enabled: bool) -> Self {
        self.config.protect_cloud_config = enabled;
        self
    }

    /// Protect browser data
    pub fn protect_browser_data(mut self, enabled: bool) -> Self {
        self.config.protect_browser_data = enabled;
        self
    }

    /// Protect system keychain
    pub fn protect_keychain(mut self, enabled: bool) -> Self {
        self.config.protect_keychain = enabled;
        self
    }

    /// Protect shell history
    pub fn protect_shell_history(mut self, enabled: bool) -> Self {
        self.config.protect_shell_history = enabled;
        self
    }

    /// Protect package manager credentials
    pub fn protect_package_credentials(mut self, enabled: bool) -> Self {
        self.config.protect_package_credentials = enabled;
        self
    }

    /// Allow GPU access (Metal, CUDA, OpenCL)
    pub fn allow_gpu(mut self, enabled: bool) -> Self {
        self.config.allow_gpu = enabled;
        self
    }

    /// Allow NPU/Neural Engine access (CoreML, ANE)
    pub fn allow_npu(mut self, enabled: bool) -> Self {
        self.config.allow_npu = enabled;
        self
    }

    /// Allow general hardware access (USB, Bluetooth, cameras, etc.)
    pub fn allow_hardware(mut self, enabled: bool) -> Self {
        self.config.allow_hardware = enabled;
        self
    }

    /// Build the configuration
    pub fn build(self) -> SecurityConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_has_all_rules() {
        let config = SecurityConfig::strict();
        let rules = config.sbpl_deny_rules();

        assert!(rules.iter().any(|r| r.contains("/Users")));
        assert!(rules.iter().any(|r| r.contains(".ssh")));
        assert!(rules.iter().any(|r| r.contains(".aws")));
        assert!(rules.iter().any(|r| r.contains("Chrome")));
        assert!(rules.iter().any(|r| r.contains("Keychains")));
        assert!(rules.iter().any(|r| r.contains("history")));
        assert!(rules.iter().any(|r| r.contains(".npmrc")));
    }

    #[test]
    fn test_permissive_has_no_rules() {
        let config = SecurityConfig::permissive();
        let rules = config.sbpl_deny_rules();
        assert!(rules.is_empty());
    }

    #[test]
    fn test_builder_custom() {
        let config = SecurityConfig::builder()
            .protect_user_home(false)
            .protect_credentials(true)
            .protect_browser_data(false)
            .build();

        let rules = config.sbpl_deny_rules();

        // Should have credentials rules
        assert!(rules.iter().any(|r| r.contains(".ssh")));

        // Should NOT have user home or browser rules
        assert!(!rules.iter().any(|r| r.contains("/Users")));
        assert!(!rules.iter().any(|r| r.contains("Chrome")));
    }

    #[test]
    fn test_builder_from_permissive() {
        let config = SecurityConfigBuilder::from_permissive()
            .protect_credentials(true)
            .build();

        let rules = config.sbpl_deny_rules();

        // Only credentials should be protected
        assert!(rules.iter().any(|r| r.contains(".ssh")));
        assert!(!rules.iter().any(|r| r.contains("/Users")));
        assert!(!rules.iter().any(|r| r.contains("Chrome")));
    }
}
