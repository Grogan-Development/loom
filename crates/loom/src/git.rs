//! Bounded Git compatibility adapters over Loom's immutable source authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fmt::{self, Write as _},
    fs,
    io::{Read as _, Write as _},
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};

use crate::auth::AccessToken;
use crate::contracts::RepositoryRevision;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    LoomError, MAX_FILES_PER_COMMIT, NamespaceGrant, PendingSourceFile, PersistentLoomStore,
    SourceFileMode, authorize, ensure_private_directory, read_bounded, validate_repository,
    write_atomic,
};

const MAX_GIT_COMMAND_OUTPUT: u64 = 64 * 1024 * 1024;
const MAX_GIT_HTTP_BODY_BYTES: usize = 256 * 1024 * 1024;
const MAX_GIT_HTTP_RESPONSE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_GIT_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_GIT_TREE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_GIT_ERROR_BYTES: u64 = 64 * 1024;
const MAX_GIT_UPDATES: usize = 256;
const MAX_GIT_UPDATE_BYTES: usize = 64 * 1024;
const MAX_GIT_OID_BYTES: usize = 64;

/// Git transport or native-import failure. Every malformed or partial push fails closed.
#[derive(Debug, Error)]
pub enum GitError {
    /// Git executable or Loom hook configuration is unsafe.
    #[error("Git compatibility configuration is invalid")]
    InvalidConfiguration,
    /// Repository, object ID, ref, command, or tree input is invalid.
    #[error("Git request is invalid")]
    InvalidRequest,
    /// A protected or unsupported ref was targeted by a Git push.
    #[error("Git ref is not writable")]
    RefDenied,
    /// Git plumbing failed or exceeded a bound.
    #[error("Git backend is unavailable")]
    BackendUnavailable,
    /// Native Loom admission or durable mapping failed.
    #[error("Git source could not be admitted into Loom")]
    Loom(#[from] LoomError),
}

/// Exact Git service allowed through HTTPS or an SSH forced command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitOperation {
    /// Read-only clone and fetch service.
    UploadPack,
    /// Workspace/candidate branch push service.
    ReceivePack,
}

impl GitOperation {
    fn program_name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }
}

/// Strictly parsed `SSH_ORIGINAL_COMMAND` for an owner-configured forced command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshOriginalCommand {
    /// Requested Git service.
    pub operation: GitOperation,
    /// Validated Loom repository namespace without the `.git` suffix.
    pub repository: String,
}

impl SshOriginalCommand {
    /// Parses only Git's exact single-quoted upload/receive command shape.
    ///
    /// # Errors
    ///
    /// Rejects shell syntax, path traversal, unknown services, and unsafe namespaces.
    pub fn parse(value: &str) -> Result<Self, GitError> {
        let (operation, remainder) = if let Some(remainder) = value.strip_prefix("git-upload-pack ")
        {
            (GitOperation::UploadPack, remainder)
        } else if let Some(remainder) = value.strip_prefix("git-receive-pack ") {
            (GitOperation::ReceivePack, remainder)
        } else {
            return Err(GitError::InvalidRequest);
        };
        let repository = remainder
            .strip_prefix('\'')
            .and_then(|path| path.strip_suffix(".git'"))
            .ok_or(GitError::InvalidRequest)?;
        validate_repository(repository).map_err(|_| GitError::InvalidRequest)?;
        if repository.contains('/') || repository.contains('\\') {
            return Err(GitError::InvalidRequest);
        }
        Ok(Self {
            operation,
            repository: repository.to_owned(),
        })
    }
}

/// One ref transition supplied to Git's pre-receive hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRefUpdate {
    old_oid: String,
    new_oid: String,
    ref_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GitRevisionMapping {
    schema_version: String,
    repository: String,
    git_oid: String,
    revision: RepositoryRevision,
}

/// Durable Git repository and hook adapter rooted inside Loom's private dataset.
#[derive(Debug, Clone)]
pub struct GitBridge {
    store: PersistentLoomStore,
    git_program: PathBuf,
    hook_program: PathBuf,
    repositories: PathBuf,
    mappings: PathBuf,
}

/// Bearer-authenticated Smart HTTP gateway.
#[derive(Clone)]
pub struct GitHttpGateway {
    state: Arc<GitHttpState>,
}

/// SSH forced-command gateway backed by an owner-private repository grant file.
#[derive(Debug, Clone)]
pub struct GitSshGateway {
    bridge: GitBridge,
    repositories: BTreeSet<String>,
    expires_at: OffsetDateTime,
}

struct GitHttpState {
    bridge: GitBridge,
    token: AccessToken,
}

impl fmt::Debug for GitHttpGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHttpGateway")
            .field("bridge", &self.state.bridge)
            .field("token", &"[CONFIGURED]")
            .finish()
    }
}

impl GitHttpGateway {
    /// Creates a gateway that admits Git traffic with the owner bearer token.
    #[must_use]
    pub fn new(bridge: GitBridge, token: AccessToken) -> Self {
        Self {
            state: Arc::new(GitHttpState { bridge, token }),
        }
    }

    /// Builds bounded Smart HTTP routes. Every request authenticates at the token.
    pub fn router(self) -> Router {
        Router::new()
            .route("/{*git_path}", any(git_http_request))
            .layer(DefaultBodyLimit::max(MAX_GIT_HTTP_BODY_BYTES))
            .with_state(self.state)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SshGrantFile {
    repositories: BTreeSet<String>,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

impl GitSshGateway {
    /// Loads one owner-private grant file listing admitted repositories.
    ///
    /// # Errors
    ///
    /// Returns for unsafe files, malformed/expired authority, or invalid namespaces.
    pub fn new(bridge: GitBridge, principal_file: impl AsRef<Path>) -> Result<Self, GitError> {
        let principal_file = principal_file.as_ref();
        if !principal_file.is_absolute()
            || principal_file
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(GitError::InvalidConfiguration);
        }
        let bytes =
            read_bounded(principal_file, 16 * 1024).map_err(|_| GitError::InvalidConfiguration)?;
        let grant: SshGrantFile =
            serde_json::from_slice(&bytes).map_err(|_| GitError::InvalidConfiguration)?;
        if grant.repositories.is_empty()
            || grant.expires_at <= OffsetDateTime::now_utc()
            || grant
                .repositories
                .iter()
                .any(|repository| validate_repository(repository).is_err())
        {
            return Err(GitError::InvalidConfiguration);
        }
        Ok(Self {
            bridge,
            repositories: grant.repositories,
            expires_at: grant.expires_at,
        })
    }

    /// Re-evaluates expiry and repository membership for one strict original command.
    ///
    /// # Errors
    ///
    /// Returns when the grant is expired or the repository is not admitted.
    pub fn authorize(&self, command: &SshOriginalCommand) -> Result<NamespaceGrant, GitError> {
        if self.expires_at <= OffsetDateTime::now_utc()
            || !self.repositories.contains(&command.repository)
        {
            return Err(GitError::RefDenied);
        }
        Ok(NamespaceGrant::new(BTreeSet::from([command
            .repository
            .clone()])))
    }

    /// Authorizes then runs the exact SSH Git service over inherited standard streams.
    ///
    /// # Errors
    ///
    /// Returns for denial or backend failure.
    pub fn run(&self, command: &SshOriginalCommand) -> Result<(), GitError> {
        let grant = self.authorize(command)?;
        self.bridge.run_ssh(&grant, command)
    }
}

#[derive(Debug)]
struct GitHttpRequest {
    repository: String,
    #[allow(dead_code)]
    operation: GitOperation,
    method: Method,
    path_info: String,
    query: String,
    content_type: Option<String>,
}

#[derive(Debug)]
struct GitHttpOutput {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl GitBridge {
    /// Opens the compatibility adapter using admitted absolute executables.
    ///
    /// # Errors
    ///
    /// Returns when either executable or a derived private path is unsafe.
    pub fn new(
        store: PersistentLoomStore,
        git_program: impl AsRef<Path>,
        hook_program: impl AsRef<Path>,
    ) -> Result<Self, GitError> {
        let git_program = validate_executable(git_program.as_ref())?;
        let hook_program = validate_executable(hook_program.as_ref())?;
        let repositories = store.root.join("git");
        let mappings = store.root.join("git-mappings");
        ensure_private_directory(&repositories)?;
        ensure_private_directory(&mappings)?;
        Ok(Self {
            store,
            git_program,
            hook_program,
            repositories,
            mappings,
        })
    }

    /// Creates or reconciles one private bare repository and its fail-closed pre-receive hook.
    ///
    /// # Errors
    ///
    /// Returns for invalid namespaces, unsafe state, or failed Git initialization/configuration.
    pub fn ensure_repository(&self, repository: &str) -> Result<PathBuf, GitError> {
        validate_repository(repository).map_err(|_| GitError::InvalidRequest)?;
        let lock = self.store.exclusive_lock()?;
        let bare = self.repositories.join(format!("{repository}.git"));
        if !bare.exists() {
            run_git_status(
                &self.git_program,
                &self.repositories,
                [OsStr::new("init"), OsStr::new("--bare"), bare.as_os_str()],
            )?;
        }
        let metadata = fs::symlink_metadata(&bare).map_err(|_| GitError::BackendUnavailable)?;
        if !metadata.is_dir() {
            return Err(GitError::InvalidConfiguration);
        }
        fs::set_permissions(&bare, fs::Permissions::from_mode(0o700))
            .map_err(|_| GitError::BackendUnavailable)?;
        run_git_status(
            &self.git_program,
            &bare,
            [
                OsStr::new("config"),
                OsStr::new("http.receivepack"),
                OsStr::new("true"),
            ],
        )?;
        run_git_status(
            &self.git_program,
            &bare,
            [
                OsStr::new("config"),
                OsStr::new("uploadpack.allowFilter"),
                OsStr::new("true"),
            ],
        )?;
        let hooks = bare.join("hooks");
        fs::set_permissions(&hooks, fs::Permissions::from_mode(0o700))
            .map_err(|_| GitError::BackendUnavailable)?;
        let hook = hooks.join("pre-receive");
        let temporary = hooks.join(".pre-receive.next");
        if temporary.exists() {
            fs::remove_file(&temporary).map_err(|_| GitError::BackendUnavailable)?;
        }
        symlink(&self.hook_program, &temporary).map_err(|_| GitError::BackendUnavailable)?;
        fs::rename(&temporary, &hook).map_err(|_| GitError::BackendUnavailable)?;
        std::fs::File::unlock(&lock).map_err(|_| GitError::BackendUnavailable)?;
        Ok(bare)
    }

    /// Imports every new commit from a pre-receive batch before Git can mutate its refs.
    ///
    /// # Errors
    ///
    /// Rejects protected/unsupported refs, malformed batches, unknown commits, unsafe trees,
    /// resource-limit violations, or any native Loom admission failure.
    pub fn import_pre_receive(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        input: &[u8],
    ) -> Result<Vec<RepositoryRevision>, GitError> {
        authorize(grant, repository)?;
        if input.len() > MAX_GIT_UPDATE_BYTES {
            return Err(GitError::InvalidRequest);
        }
        let updates = parse_updates(input)?;
        if updates.is_empty() || updates.len() > MAX_GIT_UPDATES {
            return Err(GitError::InvalidRequest);
        }
        let bare = self.ensure_repository(repository)?;
        for update in &updates {
            validate_writable_ref(&update.ref_name)?;
            validate_oid(&update.old_oid)?;
            validate_oid(&update.new_oid)?;
        }
        let mut admitted = Vec::new();
        for update in updates {
            if is_zero_oid(&update.new_oid) {
                continue;
            }
            let revision = self.import_git_commit(grant, repository, &bare, &update.new_oid)?;
            admitted.push(revision);
        }
        Ok(admitted)
    }

    /// Resolves the native immutable revision previously admitted for one exact Git commit.
    ///
    /// # Errors
    ///
    /// Returns for denial, invalid identifiers, a missing mapping, or corrupt durable state.
    pub fn revision_for_git_oid(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        git_oid: &str,
    ) -> Result<RepositoryRevision, GitError> {
        authorize(grant, repository)?;
        validate_repository(repository).map_err(|_| GitError::InvalidRequest)?;
        validate_oid(git_oid)?;
        if is_zero_oid(git_oid) {
            return Err(GitError::InvalidRequest);
        }
        let path = self.mapping_path(repository, git_oid);
        let bytes = read_bounded(&path, 4096).map_err(|error| match error {
            LoomError::StorageUnavailable => GitError::InvalidRequest,
            other => GitError::Loom(other),
        })?;
        let mapping: GitRevisionMapping =
            serde_json::from_slice(&bytes).map_err(|_| GitError::InvalidRequest)?;
        if mapping.schema_version != "v1"
            || mapping.repository != repository
            || mapping.git_oid != git_oid
            || mapping.revision.repository != repository
        {
            return Err(GitError::InvalidRequest);
        }
        self.store.has_revision(grant, &mapping.revision)?;
        Ok(mapping.revision)
    }

    /// Runs an SSH Git service after an external forced-command boundary supplied the grant.
    ///
    /// The child inherits stdin/stdout exactly as required by the Git SSH protocol.
    ///
    /// # Errors
    ///
    /// Returns for namespace denial, unsafe commands, repository setup, or backend failure.
    pub fn run_ssh(
        &self,
        grant: &NamespaceGrant,
        command: &SshOriginalCommand,
    ) -> Result<(), GitError> {
        authorize(grant, &command.repository)?;
        let bare = self.ensure_repository(&command.repository)?;
        self.sync_protected_refs(grant, &command.repository, &bare)?;
        let status = Command::new(&self.git_program)
            .arg(command.operation.program_name().trim_start_matches("git-"))
            .arg(&bare)
            .env("LOOM_ROOT", &self.store.root)
            .env("LOOM_REPOSITORY", &command.repository)
            .env("LOOM_GIT_PROGRAM", &self.git_program)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|_| GitError::BackendUnavailable)?;
        if status.success() {
            Ok(())
        } else {
            Err(GitError::BackendUnavailable)
        }
    }

    fn run_http_backend(
        &self,
        request: &GitHttpRequest,
        principal: &str,
        body: Vec<u8>,
    ) -> Result<GitHttpOutput, GitError> {
        let bare = self.ensure_repository(&request.repository)?;
        let grant = NamespaceGrant::new(BTreeSet::from([request.repository.clone()]));
        self.sync_protected_refs(&grant, &request.repository, &bare)?;
        let mut command = Command::new(&self.git_program);
        command
            .arg("http-backend")
            .env("GIT_PROJECT_ROOT", &self.repositories)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("PATH_INFO", &request.path_info)
            .env("QUERY_STRING", &request.query)
            .env("REQUEST_METHOD", request.method.as_str())
            .env("CONTENT_LENGTH", body.len().to_string())
            .env("REMOTE_USER", principal)
            .env("LOOM_ROOT", &self.store.root)
            .env("LOOM_REPOSITORY", &request.repository)
            .env("LOOM_GIT_PROGRAM", &self.git_program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(content_type) = &request.content_type {
            command.env("CONTENT_TYPE", content_type);
        }
        let mut child = command.spawn().map_err(|_| GitError::BackendUnavailable)?;
        let mut stdin = child.stdin.take().ok_or(GitError::BackendUnavailable)?;
        let writer = std::thread::spawn(move || stdin.write_all(&body));
        let mut stdout = Vec::new();
        child
            .stdout
            .take()
            .ok_or(GitError::BackendUnavailable)?
            .take(MAX_GIT_HTTP_RESPONSE_BYTES.saturating_add(1))
            .read_to_end(&mut stdout)
            .map_err(|_| GitError::BackendUnavailable)?;
        let write_result = writer.join().map_err(|_| GitError::BackendUnavailable)?;
        write_result.map_err(|_| GitError::BackendUnavailable)?;
        if stdout.len() as u64 > MAX_GIT_HTTP_RESPONSE_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err(GitError::BackendUnavailable);
        }
        let status = child.wait().map_err(|_| GitError::BackendUnavailable)?;
        if !status.success() {
            return Err(GitError::BackendUnavailable);
        }
        parse_cgi_output(&stdout)
    }

    fn sync_protected_refs(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        bare: &Path,
    ) -> Result<(), GitError> {
        let protected = self
            .store
            .protected_refs_for_repository(grant, repository)?;
        if protected.is_empty() {
            return Ok(());
        }
        let mut transaction = String::from("start\n");
        for (native_ref, revision) in protected {
            let git_ref = native_ref
                .strip_prefix("refs/")
                .filter(|suffix| !suffix.is_empty())
                .map(|suffix| format!("refs/heads/{suffix}"))
                .ok_or(GitError::InvalidRequest)?;
            validate_writable_projection_ref(&git_ref)?;
            let oid = self.git_oid_for_revision(repository, &revision)?;
            run_git_status(
                &self.git_program,
                bare,
                [
                    OsStr::new("cat-file"),
                    OsStr::new("-e"),
                    OsStr::new(&format!("{oid}^{{commit}}")),
                ],
            )?;
            writeln!(transaction, "update {git_ref} {oid}")
                .map_err(|_| GitError::BackendUnavailable)?;
        }
        transaction.push_str("prepare\ncommit\n");
        run_git_input_status(
            &self.git_program,
            bare,
            [OsStr::new("update-ref"), OsStr::new("--stdin")],
            transaction.as_bytes(),
        )
    }

    fn git_oid_for_revision(
        &self,
        repository: &str,
        revision: &RepositoryRevision,
    ) -> Result<String, GitError> {
        let directory = self.mappings.join(repository);
        let mut paths = fs::read_dir(&directory)
            .map_err(|_| GitError::BackendUnavailable)?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|_| GitError::BackendUnavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if paths.len() > MAX_FILES_PER_COMMIT {
            return Err(GitError::BackendUnavailable);
        }
        paths.sort();
        let mut selected = None;
        for path in paths {
            let bytes = read_bounded(&path, 4096)?;
            let mapping: GitRevisionMapping =
                serde_json::from_slice(&bytes).map_err(|_| GitError::InvalidRequest)?;
            let expected_name = format!("{}.json", mapping.git_oid);
            if mapping.schema_version != "v1"
                || mapping.repository != repository
                || mapping.revision.repository != repository
                || path.file_name().and_then(OsStr::to_str) != Some(expected_name.as_str())
                || validate_oid(&mapping.git_oid).is_err()
            {
                return Err(GitError::InvalidRequest);
            }
            if mapping.revision == *revision {
                selected = Some(mapping.git_oid);
            }
        }
        selected.ok_or(GitError::BackendUnavailable)
    }

    fn import_git_commit(
        &self,
        grant: &NamespaceGrant,
        repository: &str,
        bare: &Path,
        git_oid: &str,
    ) -> Result<RepositoryRevision, GitError> {
        if let Ok(revision) = self.revision_for_git_oid(grant, repository, git_oid) {
            return Ok(revision);
        }
        run_git_status(
            &self.git_program,
            bare,
            [
                OsStr::new("cat-file"),
                OsStr::new("-e"),
                OsStr::new(&format!("{git_oid}^{{commit}}")),
            ],
        )?;
        let tree = run_git_output(
            &self.git_program,
            bare,
            [
                OsStr::new("ls-tree"),
                OsStr::new("-r"),
                OsStr::new("-z"),
                OsStr::new("--full-tree"),
                OsStr::new(git_oid),
            ],
            MAX_GIT_TREE_BYTES,
        )?;
        let mut files = BTreeMap::new();
        for entry in tree
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let entry = std::str::from_utf8(entry).map_err(|_| GitError::InvalidRequest)?;
            let (metadata, path) = entry.split_once('\t').ok_or(GitError::InvalidRequest)?;
            let mut metadata = metadata.split(' ');
            let mode = metadata.next().ok_or(GitError::InvalidRequest)?;
            let kind = metadata.next().ok_or(GitError::InvalidRequest)?;
            let oid = metadata.next().ok_or(GitError::InvalidRequest)?;
            if metadata.next().is_some()
                || kind != "blob"
                || !matches!(mode, "100644" | "100755" | "120000")
            {
                return Err(GitError::InvalidRequest);
            }
            validate_oid(oid)?;
            let contents = run_git_output(
                &self.git_program,
                bare,
                [OsStr::new("cat-file"), OsStr::new("blob"), OsStr::new(oid)],
                MAX_GIT_COMMAND_OUTPUT,
            )?;
            let mode = match mode {
                "100644" => SourceFileMode::Regular,
                "100755" => SourceFileMode::Executable,
                "120000" => SourceFileMode::Symlink,
                _ => return Err(GitError::InvalidRequest),
            };
            if files
                .insert(path.to_owned(), PendingSourceFile { contents, mode })
                .is_some()
            {
                return Err(GitError::InvalidRequest);
            }
        }
        let revision = self.store.commit_git_source(grant, repository, files)?;
        self.write_mapping(repository, git_oid, &revision)?;
        Ok(revision)
    }

    fn write_mapping(
        &self,
        repository: &str,
        git_oid: &str,
        revision: &RepositoryRevision,
    ) -> Result<(), GitError> {
        let directory = self.mappings.join(repository);
        ensure_private_directory(&directory)?;
        let mapping = GitRevisionMapping {
            schema_version: "v1".to_owned(),
            repository: repository.to_owned(),
            git_oid: git_oid.to_owned(),
            revision: revision.clone(),
        };
        let bytes = serde_json::to_vec(&mapping).map_err(|_| GitError::InvalidRequest)?;
        let path = self.mapping_path(repository, git_oid);
        if path.exists() {
            let existing = read_bounded(&path, 4096)?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(GitError::InvalidRequest)
            };
        }
        write_atomic(&directory, &path, &bytes, 0o600)?;
        Ok(())
    }

    fn mapping_path(&self, repository: &str, git_oid: &str) -> PathBuf {
        self.mappings
            .join(repository)
            .join(format!("{git_oid}.json"))
    }
}

async fn git_http_request(State(state): State<Arc<GitHttpState>>, request: Request) -> Response {
    let Ok(parsed) = parse_http_request(&request) else {
        return git_http_error(StatusCode::BAD_REQUEST);
    };
    if authenticate_git(&state, request.headers()).is_err() {
        return git_http_error(StatusCode::UNAUTHORIZED);
    }
    let body = match to_bytes(request.into_body(), MAX_GIT_HTTP_BODY_BYTES).await {
        Ok(body) => body.to_vec(),
        Err(_) => return git_http_error(StatusCode::PAYLOAD_TOO_LARGE),
    };
    let bridge = state.bridge.clone();
    let output =
        tokio::task::spawn_blocking(move || bridge.run_http_backend(&parsed, "loom", body)).await;
    match output {
        Ok(Ok(output)) => git_http_output(output),
        Ok(Err(GitError::RefDenied)) => git_http_error(StatusCode::FORBIDDEN),
        Ok(Err(GitError::InvalidRequest)) => git_http_error(StatusCode::BAD_REQUEST),
        Ok(Err(_)) | Err(_) => git_http_error(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn parse_http_request(request: &Request) -> Result<GitHttpRequest, GitError> {
    let path = request.uri().path();
    let relative = path
        .strip_prefix("/git/")
        .or_else(|| path.strip_prefix('/'))
        .ok_or(GitError::InvalidRequest)?;
    let (repository, suffix) = relative
        .split_once(".git/")
        .or_else(|| relative.split_once('/'))
        .ok_or(GitError::InvalidRequest)?;
    validate_repository(repository).map_err(|_| GitError::InvalidRequest)?;
    if repository.contains('/') || repository.contains('\\') {
        return Err(GitError::InvalidRequest);
    }
    let query = request.uri().query().unwrap_or_default();
    let (operation, content_type) = if request.method() == Method::GET && suffix == "info/refs" {
        let service = query
            .strip_prefix("service=")
            .ok_or(GitError::InvalidRequest)?;
        if service.contains('&') || service.contains('=') {
            return Err(GitError::InvalidRequest);
        }
        (parse_git_service(service)?, None)
    } else if request.method() == Method::POST && query.is_empty() {
        let operation = parse_git_service(suffix)?;
        let expected = format!("application/x-{}-request", operation.program_name());
        let actual = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .ok_or(GitError::InvalidRequest)?;
        if actual != expected {
            return Err(GitError::InvalidRequest);
        }
        (operation, Some(actual.to_owned()))
    } else {
        return Err(GitError::InvalidRequest);
    };
    Ok(GitHttpRequest {
        repository: repository.to_owned(),
        operation,
        method: request.method().clone(),
        path_info: format!("/{repository}.git/{suffix}"),
        query: query.to_owned(),
        content_type,
    })
}

fn parse_git_service(service: &str) -> Result<GitOperation, GitError> {
    match service {
        "git-upload-pack" => Ok(GitOperation::UploadPack),
        "git-receive-pack" => Ok(GitOperation::ReceivePack),
        _ => Err(GitError::InvalidRequest),
    }
}

fn authenticate_git(state: &GitHttpState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::auth::bearer_token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if state.token.matches(token) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn parse_cgi_output(bytes: &[u8]) -> Result<GitHttpOutput, GitError> {
    let boundary = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| (position, 4))
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| (position, 2))
        })
        .ok_or(GitError::BackendUnavailable)?;
    if boundary.0 > MAX_GIT_HTTP_HEADER_BYTES {
        return Err(GitError::BackendUnavailable);
    }
    let headers =
        std::str::from_utf8(&bytes[..boundary.0]).map_err(|_| GitError::BackendUnavailable)?;
    let mut status = StatusCode::OK;
    let mut forwarded = Vec::new();
    for line in headers.lines() {
        let (name, value) = line.split_once(':').ok_or(GitError::BackendUnavailable)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("Status") {
            let code = value
                .split_once(' ')
                .map_or(value, |(code, _)| code)
                .parse::<u16>()
                .map_err(|_| GitError::BackendUnavailable)?;
            status = StatusCode::from_u16(code).map_err(|_| GitError::BackendUnavailable)?;
        } else if matches!(
            name.to_ascii_lowercase().as_str(),
            "content-type" | "cache-control" | "expires" | "pragma"
        ) {
            forwarded.push((name.to_owned(), value.to_owned()));
        }
    }
    if !forwarded
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
    {
        return Err(GitError::BackendUnavailable);
    }
    Ok(GitHttpOutput {
        status,
        headers: forwarded,
        body: bytes[boundary.0 + boundary.1..].to_vec(),
    })
}

fn git_http_output(output: GitHttpOutput) -> Response {
    let mut builder = Response::builder().status(output.status);
    for (name, value) in output.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(output.body))
        .unwrap_or_else(|_| git_http_error(StatusCode::SERVICE_UNAVAILABLE))
}

fn git_http_error(status: StatusCode) -> Response {
    let mut response = (status, "Git request denied\n").into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            header::HeaderValue::from_static("Bearer realm=\"loom\""),
        );
    }
    response
}

fn validate_executable(path: &Path) -> Result<PathBuf, GitError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(GitError::InvalidConfiguration);
    }
    let metadata = fs::metadata(path).map_err(|_| GitError::InvalidConfiguration)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(GitError::InvalidConfiguration);
    }
    Ok(path.to_path_buf())
}

fn validate_writable_ref(ref_name: &str) -> Result<(), GitError> {
    let suffix = ref_name
        .strip_prefix("refs/heads/workspaces/")
        .or_else(|| ref_name.strip_prefix("refs/heads/candidates/"))
        .ok_or(GitError::RefDenied)?;
    if suffix.is_empty()
        || suffix.len() > 256
        || suffix.starts_with('.')
        || suffix.ends_with('.')
        || suffix.ends_with('/')
        || suffix.contains("..")
        || suffix.contains("@{")
        || suffix.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        })
    {
        return Err(GitError::RefDenied);
    }
    Ok(())
}

fn validate_writable_projection_ref(ref_name: &str) -> Result<(), GitError> {
    let suffix = ref_name
        .strip_prefix("refs/heads/")
        .ok_or(GitError::InvalidRequest)?;
    if suffix.is_empty()
        || suffix.len() > 256
        || suffix.starts_with('.')
        || suffix.ends_with('.')
        || suffix.ends_with('/')
        || suffix.contains("..")
        || suffix.contains("@{")
        || suffix.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
        })
    {
        return Err(GitError::InvalidRequest);
    }
    Ok(())
}

fn parse_updates(input: &[u8]) -> Result<Vec<GitRefUpdate>, GitError> {
    std::str::from_utf8(input)
        .map_err(|_| GitError::InvalidRequest)?
        .lines()
        .map(|line| {
            let mut fields = line.split(' ');
            let old_oid = fields.next().ok_or(GitError::InvalidRequest)?;
            let new_oid = fields.next().ok_or(GitError::InvalidRequest)?;
            let ref_name = fields.next().ok_or(GitError::InvalidRequest)?;
            if fields.next().is_some() {
                return Err(GitError::InvalidRequest);
            }
            Ok(GitRefUpdate {
                old_oid: old_oid.to_owned(),
                new_oid: new_oid.to_owned(),
                ref_name: ref_name.to_owned(),
            })
        })
        .collect()
}

fn validate_oid(oid: &str) -> Result<(), GitError> {
    if matches!(oid.len(), 40 | MAX_GIT_OID_BYTES)
        && oid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(GitError::InvalidRequest)
    }
}

fn is_zero_oid(oid: &str) -> bool {
    oid.bytes().all(|byte| byte == b'0')
}

fn run_git_status<I, S>(git_program: &Path, directory: &Path, arguments: I) -> Result<(), GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new(git_program)
        .current_dir(directory)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| GitError::BackendUnavailable)?;
    if status.success() {
        Ok(())
    } else {
        Err(GitError::BackendUnavailable)
    }
}

fn run_git_input_status<I, S>(
    git_program: &Path,
    directory: &Path,
    arguments: I,
    input: &[u8],
) -> Result<(), GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    if input.len() > MAX_GIT_UPDATE_BYTES {
        return Err(GitError::InvalidRequest);
    }
    let mut child = Command::new(git_program)
        .current_dir(directory)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| GitError::BackendUnavailable)?;
    child
        .stdin
        .take()
        .ok_or(GitError::BackendUnavailable)?
        .write_all(input)
        .map_err(|_| GitError::BackendUnavailable)?;
    let status = child.wait().map_err(|_| GitError::BackendUnavailable)?;
    if status.success() {
        Ok(())
    } else {
        Err(GitError::BackendUnavailable)
    }
}

fn run_git_output<I, S>(
    git_program: &Path,
    directory: &Path,
    arguments: I,
    maximum: u64,
) -> Result<Vec<u8>, GitError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = Command::new(git_program)
        .current_dir(directory)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| GitError::BackendUnavailable)?;
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .ok_or(GitError::BackendUnavailable)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut stdout)
        .map_err(|_| GitError::BackendUnavailable)?;
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .ok_or(GitError::BackendUnavailable)?
        .take(MAX_GIT_ERROR_BYTES.saturating_add(1))
        .read_to_end(&mut stderr)
        .map_err(|_| GitError::BackendUnavailable)?;
    let status = child.wait().map_err(|_| GitError::BackendUnavailable)?;
    if !status.success()
        || stdout.len() as u64 > maximum
        || stderr.len() as u64 > MAX_GIT_ERROR_BYTES
    {
        return Err(GitError::BackendUnavailable);
    }
    Ok(stdout)
}

/// Executes the pre-receive hook from bounded standard input and environment configuration.
///
/// # Errors
///
/// Returns for missing/unsafe environment, oversized input, denied refs, or failed Loom import.
pub fn run_pre_receive_hook() -> Result<(), GitError> {
    let root = required_path_environment("LOOM_ROOT")?;
    let repository =
        std::env::var("LOOM_REPOSITORY").map_err(|_| GitError::InvalidConfiguration)?;
    let git_program = required_path_environment("LOOM_GIT_PROGRAM")?;
    validate_repository(&repository).map_err(|_| GitError::InvalidConfiguration)?;
    let current_exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| GitError::InvalidConfiguration)?;
    let store = PersistentLoomStore::open(root)?;
    let bridge = GitBridge::new(store, git_program, current_exe)?;
    let mut input = Vec::new();
    std::io::stdin()
        .take((MAX_GIT_UPDATE_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| GitError::InvalidRequest)?;
    if input.len() > MAX_GIT_UPDATE_BYTES {
        return Err(GitError::InvalidRequest);
    }
    let grant = NamespaceGrant::new(BTreeSet::from([repository.clone()]));
    bridge.import_pre_receive(&grant, &repository, &input)?;
    std::io::stdout()
        .flush()
        .map_err(|_| GitError::BackendUnavailable)
}

fn required_path_environment(name: &str) -> Result<PathBuf, GitError> {
    let value = std::env::var_os(name).ok_or(GitError::InvalidConfiguration)?;
    let path = PathBuf::from(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(GitError::InvalidConfiguration);
    }
    Ok(path)
}
