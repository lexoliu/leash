// FFI bindings to macOS libsandbox.dylib
// These are currently unused but will be needed for in-process sandboxing
// For now we use sandbox-exec which applies the sandbox to a child process

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use crate::error::{Error, Result};

#[link(name = "sandbox", kind = "dylib")]
unsafe extern "C" {
    /// Initialize sandbox with a profile string and parameters
    /// Returns 0 on success, -1 on error
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;

    /// Free error buffer allocated by sandbox functions
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// A compiled sandbox profile ready to be applied
pub struct SandboxProfile {
    profile_string: CString,
}

impl SandboxProfile {
    /// Create a new sandbox profile from an SBPL string
    pub fn new(sbpl: &str) -> Result<Self> {
        let profile_string = CString::new(sbpl)
            .map_err(|_| Error::InvalidProfile("Profile contains null bytes".to_string()))?;
        Ok(Self { profile_string })
    }

    /// Apply this sandbox profile to the current process
    ///
    /// # Safety
    /// This permanently restricts the current process. Once applied,
    /// the sandbox cannot be removed or relaxed.
    #[allow(dead_code)]
    pub fn apply(&self) -> Result<()> {
        let mut error_buf: *mut c_char = std::ptr::null_mut();

        // Empty parameter array (null-terminated)
        let param_ptrs: [*const c_char; 1] = [std::ptr::null()];

        let result = unsafe {
            sandbox_init_with_parameters(
                self.profile_string.as_ptr(),
                0, // SANDBOX_NAMED = 0
                param_ptrs.as_ptr(),
                &mut error_buf,
            )
        };

        if result != 0 {
            let error_msg = if !error_buf.is_null() {
                let msg = unsafe { CStr::from_ptr(error_buf) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { sandbox_free_error(error_buf) };
                msg
            } else {
                "Unknown sandbox initialization error".to_string()
            };
            return Err(Error::InitFailed(error_msg));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_creation() {
        let profile = SandboxProfile::new("(version 1)(allow default)");
        assert!(profile.is_ok());
    }

    #[test]
    fn test_profile_with_null_byte() {
        let profile = SandboxProfile::new("(version 1)\0(allow default)");
        assert!(profile.is_err());
    }
}
