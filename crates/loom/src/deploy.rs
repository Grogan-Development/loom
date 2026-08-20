//! Host apply helpers invoked only after Origin SHA evidence has passed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::LoomError;
use crate::origin::OriginConfig;

/// Runs the allowlisted apply script for `repository` at `oid`.
///
/// Loom applies locally. Grid and Nero apply over SSH to the workstation host.
///
/// # Errors
///
/// Returns when the repository is unknown, the apply helper is missing, SSH is
/// unconfigured, the process fails, or the helper exceeds its timeout.
pub fn apply_release(
    config: &OriginConfig,
    repository: &str,
    oid: &str,
) -> Result<String, LoomError> {
    if config.apply_runner_noop {
        return Ok(format!("{repository}@{oid} apply noop"));
    }
    let script = apply_script(config, repository)?;
    if repository == "loom" {
        return run_local(&script, oid, config.apply_timeout);
    }
    run_ssh(config, &script, oid)
}

fn apply_script(config: &OriginConfig, repository: &str) -> Result<PathBuf, LoomError> {
    let path = match repository {
        "loom" => config.loom_apply.clone(),
        "grid" => config.grid_apply.clone(),
        "nero" => config.nero_apply.clone(),
        _ => {
            return Err(LoomError::OriginRepositoryDenied {
                repository: repository.to_owned(),
            });
        }
    };
    if path.as_os_str().is_empty() {
        return Err(LoomError::OriginUnavailable);
    }
    Ok(path)
}

fn run_local(script: &Path, oid: &str, timeout: Duration) -> Result<String, LoomError> {
    let mut child = Command::new(script)
        .arg(oid)
        .env("LOOM_DEPLOY_SHA", oid)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| LoomError::OriginUnavailable)?;
    wait_child(&mut child, timeout)
}

fn run_ssh(config: &OriginConfig, script: &Path, oid: &str) -> Result<String, LoomError> {
    let host = config
        .deploy_ssh_host
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(LoomError::OriginUnavailable)?;
    let user = config
        .deploy_ssh_user
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("root");
    let target = format!("{user}@{host}");
    let remote = format!("{} {oid}", script.display());
    let mut command = Command::new("ssh");
    command
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new");
    if let Some(key) = &config.deploy_ssh_key {
        command.arg("-i").arg(key);
    }
    command
        .arg(target)
        .arg("--")
        .arg(remote)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| LoomError::OriginUnavailable)?;
    wait_child(&mut child, config.apply_timeout)
}

fn wait_child(child: &mut std::process::Child, timeout: Duration) -> Result<String, LoomError> {
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
                let log = format!("{stdout}{stderr}");
                if status.success() {
                    return Ok(log);
                }
                return Err(LoomError::OriginUnavailable);
            }
            Ok(None) if started.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LoomError::OriginUnavailable);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return Err(LoomError::OriginUnavailable),
        }
    }
}
