//! Working directory management for sandbox
//!
//! The sandbox operates within a dedicated working directory where it can
//! freely read and write files. By default, a random directory name is
//! generated using four English words connected by hyphens.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Word list for generating random directory names
const WORDS: &[&str] = &[
    "apple", "banana", "cherry", "dragon", "eagle", "falcon", "garden", "harbor",
    "island", "jungle", "kitten", "lemon", "mango", "night", "ocean", "planet",
    "queen", "river", "silver", "tiger", "umbrella", "violet", "winter", "yellow",
    "zebra", "anchor", "bridge", "castle", "desert", "ember", "forest", "glacier",
    "horizon", "ivory", "jasmine", "kingdom", "lantern", "meadow", "nebula", "orchid",
    "phoenix", "quartz", "rainbow", "shadow", "thunder", "urban", "velvet", "whisper",
    "crystal", "dolphin", "eclipse", "firefly", "granite", "hollow", "indigo", "journey",
    "karma", "lotus", "marble", "nomad", "oasis", "prism", "quest", "ripple",
    "sphinx", "temple", "unity", "vortex", "willow", "xenon", "yonder", "zenith",
    "amber", "blazer", "copper", "dusk", "ether", "flame", "golden", "haze",
    "iron", "jade", "kindle", "lunar", "mystic", "nova", "onyx", "pearl",
    "radiant", "storm", "tidal", "ultra", "vivid", "wave", "azure", "breeze",
];

/// Working directory for the sandbox
#[derive(Debug, Clone)]
pub struct WorkingDir {
    path: PathBuf,
    auto_created: bool,
}

impl WorkingDir {
    /// Create a working directory at the specified path
    ///
    /// The directory will be created if it doesn't exist.
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let auto_created = if !path.exists() {
            std::fs::create_dir_all(&path).map_err(|e| {
                Error::IoError(format!("Failed to create working directory: {}", e))
            })?;
            tracing::debug!(path = %path.display(), "created working directory");
            true
        } else {
            false
        };

        Ok(Self { path, auto_created })
    }

    /// Create a working directory with a random name in the current directory
    ///
    /// The name is generated using four random English words connected by hyphens,
    /// e.g., `./amber-forest-thunder-pearl`
    pub fn random() -> Result<Self> {
        let current_dir =
            std::env::current_dir().map_err(|e| Error::IoError(e.to_string()))?;
        Self::random_in(&current_dir)
    }

    /// Create a working directory with a random name in the specified parent directory
    ///
    /// Will retry with different names if the generated path already exists.
    pub fn random_in(parent: impl AsRef<Path>) -> Result<Self> {
        let parent = parent.as_ref();
        const MAX_ATTEMPTS: usize = 10;

        for attempt in 0..MAX_ATTEMPTS {
            let name = generate_random_name();
            let path = parent.join(&name);

            if !path.exists() {
                tracing::debug!(name = %name, "generated random working directory name");
                return Self::new(path);
            }

            tracing::debug!(
                name = %name,
                attempt = attempt + 1,
                "working directory already exists, retrying"
            );
        }

        Err(Error::IoError(format!(
            "Failed to generate unique working directory name after {} attempts",
            MAX_ATTEMPTS
        )))
    }

    /// Get the path to the working directory
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if the directory was auto-created
    pub fn auto_created(&self) -> bool {
        self.auto_created
    }

    /// Get the directory name (last component of the path)
    pub fn name(&self) -> Option<&str> {
        self.path.file_name().and_then(|s| s.to_str())
    }

    /// Get metadata/stats for the working directory
    pub fn stat(&self) -> Result<std::fs::Metadata> {
        std::fs::metadata(&self.path)
            .map_err(|e| Error::IoError(format!("Failed to stat working directory: {}", e)))
    }

    /// Get the size of the working directory in bytes
    ///
    /// This recursively calculates the total size of all files.
    pub fn size(&self) -> Result<u64> {
        fn dir_size(path: &Path) -> std::io::Result<u64> {
            let mut size = 0;
            if path.is_dir() {
                for entry in std::fs::read_dir(path)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        size += dir_size(&path)?;
                    } else {
                        size += entry.metadata()?.len();
                    }
                }
            }
            Ok(size)
        }

        dir_size(&self.path)
            .map_err(|e| Error::IoError(format!("Failed to calculate directory size: {}", e)))
    }

    /// Remove the working directory and all its contents
    pub fn remove(self) -> Result<()> {
        remove_dir_all::remove_dir_all(&self.path)
            .map_err(|e| Error::IoError(format!("Failed to remove working directory: {}", e)))?;
        tracing::debug!(path = %self.path.display(), "removed working directory");
        Ok(())
    }

    /// Check if the working directory is empty
    pub fn is_empty(&self) -> Result<bool> {
        let mut entries = std::fs::read_dir(&self.path)
            .map_err(|e| Error::IoError(format!("Failed to read working directory: {}", e)))?;
        Ok(entries.next().is_none())
    }
}

impl AsRef<Path> for WorkingDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

/// Generate a random name with four words connected by hyphens
fn generate_random_name() -> String {
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    let mut rng = thread_rng();
    let words: Vec<&str> = WORDS
        .choose_multiple(&mut rng, 4)
        .copied()
        .collect();

    words.join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_name() {
        let name = generate_random_name();
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 4);
        for part in parts {
            assert!(WORDS.contains(&part));
        }
    }

    #[test]
    fn test_random_names_are_unique() {
        let mut names = std::collections::HashSet::new();
        for _ in 0..100 {
            let name = generate_random_name();
            names.insert(name);
        }
        // With 96 words and 4 choices, collision is extremely unlikely
        assert!(names.len() >= 99, "Too many collisions in random names");
    }

    #[test]
    fn test_working_dir_in_temp() {
        let temp_dir = std::env::temp_dir();
        let work_dir = WorkingDir::random_in(&temp_dir).unwrap();

        assert!(work_dir.path().exists());
        assert!(work_dir.path().starts_with(&temp_dir));
        assert!(work_dir.auto_created());

        // Cleanup
        std::fs::remove_dir(work_dir.path()).ok();
    }

    #[test]
    fn test_working_dir_existing() {
        let temp_dir = std::env::temp_dir();
        let work_dir = WorkingDir::new(&temp_dir).unwrap();

        assert!(!work_dir.auto_created());
        assert_eq!(work_dir.path(), temp_dir);
    }
}
