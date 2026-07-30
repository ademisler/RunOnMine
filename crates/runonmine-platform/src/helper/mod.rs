//! Authenticated local IPC for the optional privileged helper.
//!
//! The helper is deliberately not a shell. It accepts an absolute executable
//! only when that exact, root-controlled file was allowlisted at installation
//! time, its SHA-256 digest still matches, and execution remains tied to a
//! retained verified file handle through process creation. The transport additionally
//! authenticates the operating-system identity of every peer.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use crate::output::{SharedOutputBudget, read_with_shared_budget};
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use command_group::AsyncCommandGroup as _;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use uuid::Uuid;

mod arguments;
mod executable;
mod install_transaction;
mod service;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use arguments::{
    AdminArgumentSchema, AdminCommandSchema, AdminFlagSchema, AdminPathMode, AdminProgramRule,
};
pub use service::{
    HelperInstallOptions, HelperManager, HelperServiceStatus, installed_policy_path,
    resolve_install_owner,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const POLICY_VERSION: u16 = 2;
pub const PROGRAM_PROFILE_VERSION: u16 = 1;
pub const MAX_PROGRAM_PROFILES: usize = 128;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 3 * 1024 * 1024;
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_mins(1);
pub const MAX_TIMEOUT: Duration = Duration::from_mins(5);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnerIdentity {
    UnixUid { uid: u32 },
    WindowsSid { sid: String },
}

impl OwnerIdentity {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::UnixUid { uid } => {
                if *uid == 0 {
                    bail!("the privileged helper may not be assigned to the root account");
                }
            }
            Self::WindowsSid { sid } => validate_windows_sid(sid)?,
        }
        Ok(())
    }
}

/// Resolve the exact executable identity accepted by the privileged helper.
///
/// Policy evaluation and helper allowlist installation use this same function so
/// alternate path spellings cannot bypass an executable resource rule.
pub fn canonical_program_identity(path: &Path) -> Result<PathBuf> {
    executable::inspect_path(path).map(|(canonical_path, _sha256)| canonical_path)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramProfileDocument {
    pub version: u16,
    pub programs: Vec<AdminProgramRule>,
}

impl ProgramProfileDocument {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            bail!("admin program profile file must use an absolute path");
        }
        reject_symlink(path, "admin program profile")?;
        let metadata = fs::metadata(path).context("failed to inspect admin program profile")?;
        if metadata.len() > MAX_REQUEST_BYTES as u64 {
            bail!("admin program profile exceeds the size limit");
        }
        let bytes = fs::read(path).context("failed to read admin program profile")?;
        let document: Self =
            serde_json::from_slice(&bytes).context("admin program profile is not valid JSON")?;
        if document.version != PROGRAM_PROFILE_VERSION {
            bail!("unsupported admin program profile version");
        }
        if document.programs.is_empty() || document.programs.len() > MAX_PROGRAM_PROFILES {
            bail!("admin program profile contains an invalid program count");
        }
        for program in &document.programs {
            program.validate()?;
        }
        Ok(document)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedProgram {
    pub canonical_path: PathBuf,
    pub sha256: String,
    #[serde(default = "default_no_argument_commands")]
    pub commands: Vec<AdminCommandSchema>,
}

impl AllowedProgram {
    pub fn inspect(path: &Path) -> Result<Self> {
        Self::inspect_rule(AdminProgramRule::no_arguments(path.to_path_buf()))
    }

    pub fn inspect_rule(rule: AdminProgramRule) -> Result<Self> {
        let rule = rule.normalize()?;
        let (canonical_path, sha256) = executable::inspect_path(&rule.program)?;
        Ok(Self {
            canonical_path,
            sha256,
            commands: rule.commands,
        })
    }

    fn prepare(
        &self,
        execution: &AdminExecution,
    ) -> Result<Option<executable::PreparedExecutable>> {
        let mut arguments_allowed = false;
        for command in &self.commands {
            if command.permits(&execution.args)? {
                arguments_allowed = true;
                break;
            }
        }
        if !arguments_allowed {
            return Ok(None);
        }
        executable::PreparedExecutable::open(self, &execution.program)
    }

    fn validate(&self) -> Result<()> {
        if !self.canonical_path.is_absolute()
            || self.sha256.len() != 64
            || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.commands.is_empty()
            || self.commands.len() > 64
        {
            bail!("installed admin program policy is invalid");
        }
        let canonical = canonical_program_identity(&self.canonical_path)?;
        if canonical != self.canonical_path {
            bail!("installed admin program path is not canonical");
        }
        for command in &self.commands {
            command.validates_loaded_roots()?;
        }
        Ok(())
    }
}

fn default_no_argument_commands() -> Vec<AdminCommandSchema> {
    vec![AdminCommandSchema::no_arguments()]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminPolicy {
    pub version: u16,
    pub owner: OwnerIdentity,
    #[serde(default)]
    pub allowed_programs: Vec<AllowedProgram>,
}

impl AdminPolicy {
    pub fn build(owner: OwnerIdentity, programs: &[AdminProgramRule]) -> Result<Self> {
        owner.validate()?;
        if programs.is_empty() {
            bail!("the privileged helper requires at least one program profile");
        }
        if programs.len() > MAX_PROGRAM_PROFILES {
            bail!("too many admin program profiles");
        }
        let mut allowed_programs = Vec::<AllowedProgram>::new();
        for rule in programs.iter().cloned() {
            let inspected = AllowedProgram::inspect_rule(rule)?;
            if let Some(existing) = allowed_programs
                .iter_mut()
                .find(|program| program.canonical_path == inspected.canonical_path)
            {
                if existing.sha256 != inspected.sha256 {
                    bail!("duplicate admin program profile has a different executable digest");
                }
                for command in inspected.commands {
                    if !existing.commands.contains(&command) {
                        existing.commands.push(command);
                    }
                }
            } else {
                allowed_programs.push(inspected);
            }
        }
        allowed_programs.sort_by(|left, right| left.canonical_path.cmp(&right.canonical_path));
        Ok(Self {
            version: POLICY_VERSION,
            owner,
            allowed_programs,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        reject_symlink(path, "helper policy")?;
        let bytes = fs::read(path).context("failed to read the helper policy")?;
        if bytes.len() > MAX_REQUEST_BYTES {
            bail!("helper policy is larger than the supported limit");
        }
        let policy: Self =
            serde_json::from_slice(&bytes).context("helper policy is not valid JSON")?;
        if policy.version != POLICY_VERSION {
            bail!("unsupported helper policy version; reinstall the privileged helper");
        }
        policy.owner.validate()?;
        if policy.allowed_programs.len() > MAX_PROGRAM_PROFILES {
            bail!("installed helper policy has too many programs");
        }
        for program in &policy.allowed_programs {
            program.validate()?;
        }
        Ok(policy)
    }

    fn prepare_execution(
        &self,
        execution: &AdminExecution,
    ) -> Result<Option<executable::PreparedExecutable>> {
        execution.validate()?;
        for allowed in &self.allowed_programs {
            if let Some(prepared) = allowed.prepare(execution)? {
                return Ok(Some(prepared));
            }
        }
        Ok(None)
    }

    pub fn permits(&self, execution: &AdminExecution) -> Result<bool> {
        Ok(self.prepare_execution(execution)?.is_some())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperRequest {
    pub version: u16,
    pub request_id: Uuid,
    pub operation: AdminOperation,
}

impl HelperRequest {
    #[must_use]
    pub fn health() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation: AdminOperation::Health,
        }
    }

    pub fn execute(program: PathBuf, args: Vec<String>, timeout: Duration) -> Result<Self> {
        let request = Self {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation: AdminOperation::Execute(AdminExecution {
                program,
                args,
                timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            }),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            bail!("unsupported helper protocol version");
        }
        match &self.operation {
            AdminOperation::Health => {}
            AdminOperation::Execute(execution) => execution.validate()?,
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminOperation {
    Health,
    Execute(AdminExecution),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminExecution {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_ms: u64,
}

impl AdminExecution {
    pub fn validate(&self) -> Result<()> {
        if !self.program.is_absolute() {
            bail!("admin executable must be an absolute path");
        }
        if self.args.len() > 128 {
            bail!("admin execution has too many arguments");
        }
        if self.args.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > 8 * 1024
                || argument.chars().any(char::is_control)
        }) {
            bail!("admin execution contains an invalid argument");
        }
        if self.timeout_ms == 0 || Duration::from_millis(self.timeout_ms) > MAX_TIMEOUT {
            bail!("admin execution timeout is outside the supported range");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperResponse {
    pub version: u16,
    pub request_id: Uuid,
    pub result: HelperResult,
}

impl HelperResponse {
    #[must_use]
    pub fn healthy(request_id: Uuid, allowlisted_programs: usize) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            result: HelperResult::Healthy {
                allowlisted_programs,
                protocol_version: PROTOCOL_VERSION,
                package_version: HELPER_VERSION.to_owned(),
            },
        }
    }

    #[must_use]
    pub fn rejected(request_id: Uuid, message: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            result: HelperResult::Rejected {
                message: sanitize_message(&message.into()),
            },
        }
    }

    #[must_use]
    pub fn failed(request_id: Uuid, message: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            result: HelperResult::Failed {
                message: sanitize_message(&message.into()),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HelperResult {
    Healthy {
        allowlisted_programs: usize,
        protocol_version: u16,
        package_version: String,
    },
    Completed {
        exit_code: Option<i32>,
        stdout_base64: String,
        stderr_base64: String,
        output_truncated: bool,
        timed_out: bool,
    },
    Rejected {
        message: String,
    },
    Failed {
        message: String,
    },
}

impl HelperResult {
    #[must_use]
    pub fn completed(
        exit_code: Option<i32>,
        stdout: &[u8],
        stderr: &[u8],
        output_truncated: bool,
        timed_out: bool,
    ) -> Self {
        Self::Completed {
            exit_code,
            stdout_base64: BASE64_STANDARD.encode(stdout),
            stderr_base64: BASE64_STANDARD.encode(stderr),
            output_truncated,
            timed_out,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HelperAvailability {
    Available { allowlisted_programs: usize },
    Missing,
    Disabled,
    Corrupt,
    Unavailable,
    PermissionDenied,
}

impl HelperAvailability {
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    #[must_use]
    pub const fn allowlisted_programs(&self) -> Option<usize> {
        match self {
            Self::Available {
                allowlisted_programs,
            } => Some(*allowlisted_programs),
            _ => None,
        }
    }

    #[must_use]
    pub fn from_error(error: &anyhow::Error) -> Self {
        for cause in error.chain() {
            if let Some(io) = cause.downcast_ref::<std::io::Error>() {
                return match io.kind() {
                    std::io::ErrorKind::NotFound => Self::Missing,
                    std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
                    std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::BrokenPipe => Self::Disabled,
                    std::io::ErrorKind::InvalidData => Self::Corrupt,
                    _ => Self::Unavailable,
                };
            }
            if cause.downcast_ref::<serde_json::Error>().is_some() {
                return Self::Corrupt;
            }
        }
        Self::Unavailable
    }

    fn from_health_result(result: HelperResult) -> Self {
        match result {
            HelperResult::Healthy {
                allowlisted_programs,
                protocol_version,
                package_version,
            } if protocol_version == PROTOCOL_VERSION && package_version == HELPER_VERSION => {
                Self::Available {
                    allowlisted_programs,
                }
            }
            HelperResult::Healthy { .. }
            | HelperResult::Completed { .. }
            | HelperResult::Rejected { .. } => Self::Corrupt,
            HelperResult::Failed { .. } => Self::Unavailable,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HelperClient {
    owner: OwnerIdentity,
}

impl HelperClient {
    pub fn new(owner: OwnerIdentity) -> Result<Self> {
        owner.validate()?;
        Ok(Self { owner })
    }

    /// Creates a client bound to the operating-system identity of this process.
    /// The helper transport still performs its own peer credential check.
    pub fn for_current_user() -> Result<Self> {
        Self::new(current_user_identity()?)
    }

    pub async fn request(&self, request: &HelperRequest) -> Result<HelperResponse> {
        request.validate()?;
        #[cfg(unix)]
        {
            unix::client_request(&self.owner, request).await
        }
        #[cfg(windows)]
        {
            windows::client_request(&self.owner, request).await
        }
        #[cfg(not(any(unix, windows)))]
        {
            bail!("the privileged helper is unsupported on this operating system")
        }
    }

    pub async fn availability(&self) -> HelperAvailability {
        match self.request(&HelperRequest::health()).await {
            Ok(response) => HelperAvailability::from_health_result(response.result),
            Err(error) => HelperAvailability::from_error(&error),
        }
    }
}

pub async fn serve_installed() -> Result<()> {
    let path = installed_policy_path()?;
    let policy = AdminPolicy::load(&path)?;
    require_privileged_identity()?;
    #[cfg(unix)]
    {
        unix::serve(policy).await
    }
    #[cfg(windows)]
    {
        windows::serve(policy).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("the privileged helper is unsupported on this operating system")
    }
}

async fn read_frame<R>(reader: &mut R, limit: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let length = reader
        .read_u32()
        .await
        .context("failed to read helper frame length")?;
    let length = usize::try_from(length).context("invalid helper frame length")?;
    if length == 0 || length > limit {
        bail!("helper frame is outside the supported size limit");
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .await
        .context("failed to read helper frame")?;
    Ok(bytes)
}

async fn write_frame<W, T>(writer: &mut W, value: &T, limit: usize) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value).context("failed to encode helper frame")?;
    if bytes.is_empty() || bytes.len() > limit {
        bail!("encoded helper frame is outside the supported size limit");
    }
    let length = u32::try_from(bytes.len()).context("helper frame is too large")?;
    writer
        .write_u32(length)
        .await
        .context("failed to write helper frame length")?;
    writer
        .write_all(&bytes)
        .await
        .context("failed to write helper frame")?;
    writer
        .flush()
        .await
        .context("failed to flush helper frame")?;
    Ok(())
}

fn decode_request(bytes: &[u8]) -> Result<HelperRequest> {
    let request: HelperRequest =
        serde_json::from_slice(bytes).context("helper request is not valid JSON")?;
    request.validate()?;
    Ok(request)
}

fn decode_response(bytes: &[u8], request_id: Uuid) -> Result<HelperResponse> {
    let response: HelperResponse =
        serde_json::from_slice(bytes).context("helper response is not valid JSON")?;
    if response.version != PROTOCOL_VERSION || response.request_id != request_id {
        bail!("helper response did not match the request");
    }
    Ok(response)
}

async fn handle_authenticated_request(
    policy: &AdminPolicy,
    request: HelperRequest,
) -> HelperResponse {
    let request_id = request.request_id;
    if let Err(error) = request.validate() {
        return HelperResponse::rejected(request_id, error.to_string());
    }
    match request.operation {
        AdminOperation::Health => {
            HelperResponse::healthy(request_id, policy.allowed_programs.len())
        }
        AdminOperation::Execute(execution) => {
            let prepared = match policy.prepare_execution(&execution) {
                Ok(Some(prepared)) => prepared,
                Ok(None) => {
                    return HelperResponse::rejected(
                        request_id,
                        "the privileged invocation is not permitted by the installed admin policy",
                    );
                }
                Err(_) => {
                    return HelperResponse::failed(
                        request_id,
                        "the installed admin allowlist could not be verified",
                    );
                }
            };
            match execute_program(&execution, prepared).await {
                Ok(output) => HelperResponse {
                    version: PROTOCOL_VERSION,
                    request_id,
                    result: HelperResult::completed(
                        output.exit_code,
                        &output.stdout,
                        &output.stderr,
                        output.truncated,
                        output.timed_out,
                    ),
                },
                Err(_) => HelperResponse::failed(request_id, "admin execution failed"),
            }
        }
    }
}

#[derive(Debug)]
struct ExecutionOutput {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
    timed_out: bool,
}

static ADMIN_SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

async fn execute_program(
    execution: &AdminExecution,
    prepared: executable::PreparedExecutable,
) -> Result<ExecutionOutput> {
    execution.validate()?;
    let mut command = Command::new(prepared.command_path());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.as_std_mut().arg0(prepared.canonical_path());
    }
    command
        .args(&execution.args)
        .current_dir(platform_root_directory())
        .env_clear()
        .env("PATH", safe_admin_path())
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.env("SystemRoot", windows::system_root());

    let mut child = {
        let _spawn_guard = ADMIN_SPAWN_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("privileged process spawn lock was poisoned"))?;
        prepared.revalidate_before_spawn()?;
        #[cfg(target_os = "linux")]
        prepared.make_inheritable_for_spawn()?;
        let child = command
            .group_spawn()
            .context("failed to start an admin process")?;
        drop(prepared);
        child
    };
    let stdout = child
        .inner()
        .stdout
        .take()
        .context("failed to capture admin stdout")?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .context("failed to capture admin stderr")?;
    let output_budget = Arc::new(SharedOutputBudget::new(MAX_CAPTURE_BYTES));
    let stdout_task = tokio::spawn(read_with_shared_budget(stdout, Arc::clone(&output_budget)));
    let stderr_task = tokio::spawn(read_with_shared_budget(stderr, Arc::clone(&output_budget)));

    let (status, timed_out) = if let Ok(result) =
        tokio::time::timeout(Duration::from_millis(execution.timeout_ms), child.wait()).await
    {
        (Some(result?), false)
    } else {
        let _ignored = child.kill().await;
        (child.wait().await.ok(), true)
    };
    let stdout = stdout_task.await.context("admin stdout task failed")??;
    let stderr = stderr_task.await.context("admin stderr task failed")??;
    let truncated = output_budget.truncated();
    Ok(ExecutionOutput {
        exit_code: status.and_then(|status| status.code()),
        stdout,
        stderr,
        truncated,
        timed_out,
    })
}

#[cfg(unix)]
fn platform_root_directory() -> &'static str {
    "/"
}

#[cfg(windows)]
fn platform_root_directory() -> PathBuf {
    windows::system_root()
}

#[cfg(unix)]
fn safe_admin_path() -> &'static str {
    "/usr/sbin:/usr/bin:/sbin:/bin"
}

#[cfg(windows)]
fn safe_admin_path() -> String {
    windows::system_root()
        .join("System32")
        .to_string_lossy()
        .into_owned()
}

fn reject_symlink(path: &Path, description: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to inspect {description}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{description} must be a regular, non-symlink file");
    }
    Ok(())
}

fn sanitize_message(message: &str) -> String {
    message
        .chars()
        .filter(|character| !character.is_control() || *character == ' ')
        .take(512)
        .collect()
}

fn validate_windows_sid(sid: &str) -> Result<()> {
    let mut segments = sid.split('-');
    if segments.next() != Some("S") || segments.next() != Some("1") {
        bail!("invalid Windows owner SID");
    }
    let remaining = segments.collect::<Vec<_>>();
    if remaining.len() < 2
        || remaining.len() > 16
        || remaining
            .iter()
            .any(|segment| segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()))
    {
        bail!("invalid Windows owner SID");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_privileged_program_ownership(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!(
            "admin executable must be owned by root and not group- or world-writable: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn validate_privileged_program_ownership(path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    windows::validate_privileged_program_path(path)
}

#[cfg(not(any(unix, windows)))]
fn validate_privileged_program_ownership(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    bail!("privileged programs are unsupported on this operating system")
}

fn require_privileged_identity() -> Result<()> {
    #[cfg(unix)]
    {
        if !nix::unistd::geteuid().is_root() {
            bail!("the privileged helper must run as root");
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        windows::require_local_system()
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("the privileged helper is unsupported on this operating system")
    }
}

fn require_installer_identity() -> Result<()> {
    #[cfg(unix)]
    {
        require_privileged_identity()
    }
    #[cfg(windows)]
    {
        windows::require_elevated_administrator()
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("the privileged helper is unsupported on this operating system")
    }
}

#[cfg(unix)]
fn current_user_identity() -> Result<OwnerIdentity> {
    let owner = OwnerIdentity::UnixUid {
        uid: nix::unistd::geteuid().as_raw(),
    };
    owner.validate()?;
    Ok(owner)
}

#[cfg(windows)]
fn current_user_identity() -> Result<OwnerIdentity> {
    let owner = OwnerIdentity::WindowsSid {
        sid: windows::current_user_sid()?,
    };
    owner.validate()?;
    Ok(owner)
}

#[cfg(not(any(unix, windows)))]
fn current_user_identity() -> Result<OwnerIdentity> {
    bail!("the privileged helper is unsupported on this operating system")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn canonical_program_identity_matches_allowlist_identity() -> Result<()> {
        let canonical = canonical_program_identity(Path::new("/usr/bin/id"))?;
        let alternate = canonical_program_identity(Path::new("/usr/bin/../bin/id"))?;
        let allowed = AllowedProgram::inspect(Path::new("/usr/bin/id"))?;
        assert_eq!(canonical, alternate);
        assert_eq!(allowed.canonical_path, canonical);
        assert!(canonical_program_identity(Path::new("relative/id")).is_err());
        Ok(())
    }

    #[test]
    fn empty_admin_policy_is_rejected() {
        let owner = if cfg!(windows) {
            OwnerIdentity::WindowsSid {
                sid: "S-1-5-21-1-2-3-1001".to_owned(),
            }
        } else {
            OwnerIdentity::UnixUid { uid: 1000 }
        };
        assert!(AdminPolicy::build(owner, &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn compatibility_allow_program_is_strictly_argument_free() -> Result<()> {
        let program = PathBuf::from("/usr/bin/id");
        let policy = AdminPolicy::build(
            OwnerIdentity::UnixUid { uid: 1000 },
            &[AdminProgramRule::no_arguments(program.clone())],
        )?;
        let without_arguments = AdminExecution {
            program: program.clone(),
            args: Vec::new(),
            timeout_ms: 1_000,
        };
        let with_arguments = AdminExecution {
            program,
            args: vec!["-u".to_owned()],
            timeout_ms: 1_000,
        };
        assert!(policy.permits(&without_arguments)?);
        assert!(!policy.permits(&with_arguments)?);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn authenticated_helper_rejects_arguments_outside_the_installed_schema() -> Result<()> {
        let program = PathBuf::from("/usr/bin/id");
        let policy = AdminPolicy::build(
            OwnerIdentity::UnixUid { uid: 1000 },
            &[AdminProgramRule::no_arguments(program.clone())],
        )?;
        let request =
            HelperRequest::execute(program, vec!["-u".to_owned()], Duration::from_secs(1))?;
        let response = handle_authenticated_request(&policy, request).await;
        assert!(matches!(response.result, HelperResult::Rejected { .. }));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn prepared_linux_execution_spawns_the_verified_descriptor() -> Result<()> {
        let program = PathBuf::from("/usr/bin/id");
        let policy = AdminPolicy::build(
            OwnerIdentity::UnixUid { uid: 1000 },
            &[AdminProgramRule::no_arguments(program.clone())],
        )?;
        let execution = AdminExecution {
            program,
            args: Vec::new(),
            timeout_ms: 5_000,
        };
        let prepared = policy
            .prepare_execution(&execution)?
            .context("test execution was not prepared")?;
        let output = execute_program(&execution, prepared).await?;
        assert_eq!(output.exit_code, Some(0));
        assert!(!output.stdout.is_empty());
        assert!(!output.timed_out);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn installed_policy_enforces_subcommands_flags_values_and_path_roots() -> Result<()> {
        let root = tempfile::tempdir()?;
        let config = root.path().join("agent.conf");
        fs::write(&config, b"test")?;
        let program = PathBuf::from("/usr/bin/id");
        let rule = AdminProgramRule {
            program: program.clone(),
            commands: vec![AdminCommandSchema {
                subcommand: Some("inspect".to_owned()),
                flags: vec![AdminFlagSchema {
                    name: "--config".to_owned(),
                    value: Some(AdminArgumentSchema::Path {
                        roots: vec![root.path().to_path_buf()],
                        mode: AdminPathMode::ExistingFile,
                    }),
                    repeatable: false,
                }],
                forbidden_flags: vec!["--root".to_owned()],
                positionals: vec![AdminArgumentSchema::Choice {
                    values: vec!["safe-target".to_owned()],
                }],
            }],
        };
        let policy = AdminPolicy::build(OwnerIdentity::UnixUid { uid: 1000 }, &[rule])?;
        let allowed = AdminExecution {
            program: program.clone(),
            args: vec![
                "inspect".to_owned(),
                "--config".to_owned(),
                config.to_string_lossy().into_owned(),
                "safe-target".to_owned(),
            ],
            timeout_ms: 1_000,
        };
        assert!(policy.permits(&allowed)?);
        for args in [
            vec!["delete".to_owned(), "safe-target".to_owned()],
            vec![
                "inspect".to_owned(),
                "--root=/".to_owned(),
                "safe-target".to_owned(),
            ],
            vec![
                "inspect".to_owned(),
                "--config".to_owned(),
                "/etc/passwd".to_owned(),
                "safe-target".to_owned(),
            ],
            vec![
                "inspect".to_owned(),
                "--config".to_owned(),
                config.to_string_lossy().into_owned(),
                "unsafe-target".to_owned(),
            ],
        ] {
            assert!(!policy.permits(&AdminExecution {
                program: program.clone(),
                args,
                timeout_ms: 1_000,
            })?);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn current_policy_without_command_schemas_fails_closed_to_no_arguments() -> Result<()> {
        let allowed = AllowedProgram::inspect(Path::new("/usr/bin/id"))?;
        let mut encoded = serde_json::to_value(AdminPolicy {
            version: POLICY_VERSION,
            owner: OwnerIdentity::UnixUid { uid: 1000 },
            allowed_programs: vec![allowed],
        })?;
        let commands = encoded
            .get_mut("allowed_programs")
            .and_then(serde_json::Value::as_array_mut)
            .and_then(|programs| programs.first_mut())
            .and_then(serde_json::Value::as_object_mut)
            .context("test policy has no allowed program")?;
        commands.remove("commands");
        let directory = tempfile::tempdir()?;
        let policy_path = directory.path().join("policy.json");
        fs::write(&policy_path, serde_json::to_vec(&encoded)?)?;
        let policy = AdminPolicy::load(&policy_path)?;
        assert!(policy.permits(&AdminExecution {
            program: PathBuf::from("/usr/bin/id"),
            args: Vec::new(),
            timeout_ms: 1_000,
        })?);
        assert!(!policy.permits(&AdminExecution {
            program: PathBuf::from("/usr/bin/id"),
            args: vec!["-u".to_owned()],
            timeout_ms: 1_000,
        })?);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn legacy_v1_policy_requires_an_explicit_helper_reinstall() -> Result<()> {
        let allowed = AllowedProgram::inspect(Path::new("/usr/bin/id"))?;
        let directory = tempfile::tempdir()?;
        let policy_path = directory.path().join("legacy-policy.json");
        fs::write(
            &policy_path,
            serde_json::to_vec(&AdminPolicy {
                version: 1,
                owner: OwnerIdentity::UnixUid { uid: 1000 },
                allowed_programs: vec![allowed],
            })?,
        )?;
        assert!(AdminPolicy::load(&policy_path).is_err());
        Ok(())
    }

    #[test]
    fn profile_document_rejects_unknown_fields_and_relative_paths() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let unknown = directory.path().join("unknown.json");
        fs::write(
            &unknown,
            br#"{"version":1,"programs":[],"unexpected":true}"#,
        )?;
        assert!(ProgramProfileDocument::load(&unknown).is_err());

        let relative = directory.path().join("relative.json");
        fs::write(
            &relative,
            br#"{"version":1,"programs":[{"program":"relative","commands":[{"subcommand":null,"flags":[],"forbidden_flags":[],"positionals":[]}]}]}"#,
        )?;
        assert!(ProgramProfileDocument::load(&relative).is_err());
        Ok(())
    }

    #[test]
    fn helper_availability_distinguishes_transport_and_protocol_failures() {
        let missing = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound));
        let denied = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let disabled =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        assert_eq!(
            HelperAvailability::from_error(&missing),
            HelperAvailability::Missing
        );
        assert_eq!(
            HelperAvailability::from_error(&denied),
            HelperAvailability::PermissionDenied
        );
        assert_eq!(
            HelperAvailability::from_error(&disabled),
            HelperAvailability::Disabled
        );
        assert_eq!(
            HelperAvailability::from_health_result(HelperResult::Healthy {
                allowlisted_programs: 2,
                protocol_version: PROTOCOL_VERSION,
                package_version: HELPER_VERSION.to_owned(),
            }),
            HelperAvailability::Available {
                allowlisted_programs: 2
            }
        );
        assert_eq!(
            HelperAvailability::from_health_result(HelperResult::Healthy {
                allowlisted_programs: 2,
                protocol_version: PROTOCOL_VERSION.saturating_add(1),
                package_version: HELPER_VERSION.to_owned(),
            }),
            HelperAvailability::Corrupt
        );
    }

    #[test]
    fn protocol_rejects_relative_programs_and_unbounded_timeouts() {
        assert!(
            HelperRequest::execute(
                PathBuf::from("relative-command"),
                Vec::new(),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            HelperRequest::execute(
                PathBuf::from(if cfg!(windows) {
                    r"C:\Windows\System32\whoami.exe"
                } else {
                    "/usr/bin/id"
                }),
                Vec::new(),
                MAX_TIMEOUT + Duration::from_millis(1)
            )
            .is_err()
        );
        let absolute = PathBuf::from(if cfg!(windows) {
            r"C:\Windows\System32\whoami.exe"
        } else {
            "/usr/bin/id"
        });
        assert!(
            HelperRequest::execute(
                absolute.clone(),
                vec![String::new()],
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(
            HelperRequest::execute(
                absolute,
                vec![
                    "line
break"
                        .to_owned()
                ],
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    #[test]
    fn response_request_id_must_match() -> Result<()> {
        let response = HelperResponse::healthy(Uuid::new_v4(), 0);
        let encoded = serde_json::to_vec(&response)?;
        assert!(decode_response(&encoded, Uuid::new_v4()).is_err());
        Ok(())
    }

    #[test]
    fn windows_sid_validation_is_strict() {
        assert!(validate_windows_sid("S-1-5-21-123-456-789-1001").is_ok());
        assert!(validate_windows_sid("S-2-5-21").is_err());
        assert!(validate_windows_sid("S-1-5-owner").is_err());
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut reader = std::io::Cursor::new(bytes);
        assert!(read_frame(&mut reader, MAX_REQUEST_BYTES).await.is_err());
    }
}
