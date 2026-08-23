//! Docker runner. Image build/smoke is not implemented; callers must fail closed.

use crate::LoomError;

/// Local docker daemon probe. Does not build or tag images.
#[derive(Debug, Clone)]
pub struct DockerRunner {
    available: bool,
}

impl DockerRunner {
    /// True when `/var/run/docker.sock` exists. That is not a successful deploy.
    #[must_use]
    pub fn detect() -> Self {
        let available = std::path::Path::new("/var/run/docker.sock").exists();
        Self { available }
    }

    /// True when a docker socket is present.
    #[must_use]
    pub const fn available(&self) -> bool {
        self.available
    }

    /// Image tagging is unimplemented. Always fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`LoomError::ImageMissing`].
    pub fn tag_digest(&self, digest: &str) -> Result<(), LoomError> {
        let _ = (self.available, digest);
        Err(LoomError::ImageMissing)
    }
}

impl Default for DockerRunner {
    fn default() -> Self {
        Self::detect()
    }
}
