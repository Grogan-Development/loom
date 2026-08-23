//! Process runners for lightning CI. The default is a local subprocess.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::LoomError;

/// Executes one CI argv in a working directory.
pub trait Runner {
    /// Runs `command` in `cwd` until it exits or `timeout` elapses.
    ///
    /// # Errors
    ///
    /// Returns when the argv is empty, the program path is unsafe, or the process
    /// cannot be spawned.
    fn run(
        &self,
        cwd: &Path,
        command: &[String],
        timeout: Duration,
    ) -> Result<(bool, String), LoomError>;
}

/// Host subprocess runner used by tests and the Phase 0 CI engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalProcessRunner;

impl Runner for LocalProcessRunner {
    fn run(
        &self,
        cwd: &Path,
        command: &[String],
        timeout: Duration,
    ) -> Result<(bool, String), LoomError> {
        let program = command.first().ok_or(LoomError::InvalidSourceCommit)?;
        if program.contains('/') || program.contains('\\') {
            return Err(LoomError::InvalidSourceCommit);
        }
        let mut child = Command::new(program)
            .args(&command[1..])
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| LoomError::StorageUnavailable)?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = String::new();
                    if let Some(mut pipe) = child.stdout.take() {
                        let _ = std::io::Read::read_to_string(&mut pipe, &mut stdout);
                    }
                    let mut stderr = String::new();
                    if let Some(mut pipe) = child.stderr.take() {
                        let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
                    }
                    return Ok((status.success(), format!("{stdout}{stderr}")));
                }
                Ok(None) if started.elapsed() > timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok((false, "ci.timeout".to_owned()));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(_) => return Err(LoomError::StorageUnavailable),
            }
        }
    }
}
