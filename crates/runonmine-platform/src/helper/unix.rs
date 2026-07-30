//! Unix-domain socket transport for macOS and Linux.

use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use super::{
    AdminPolicy, HelperRequest, HelperResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    OwnerIdentity, decode_request, decode_response, handle_authenticated_request, read_frame,
    write_frame,
};

const MAX_CONCURRENT_CLIENTS: usize = 16;

pub(super) async fn client_request(
    owner: &OwnerIdentity,
    request: &HelperRequest,
) -> Result<HelperResponse> {
    let OwnerIdentity::UnixUid { .. } = owner else {
        bail!("a Unix helper requires a Unix owner identity");
    };
    let mut stream = UnixStream::connect(socket_path())
        .await
        .context("failed to connect to the privileged helper")?;
    let peer = stream
        .peer_cred()
        .context("failed to authenticate the privileged helper")?;
    if peer.uid() != 0 {
        bail!("refusing a privileged helper endpoint not owned by root");
    }
    write_frame(&mut stream, request, MAX_REQUEST_BYTES).await?;
    let response = read_frame(&mut stream, MAX_RESPONSE_BYTES).await?;
    decode_response(&response, request.request_id)
}

pub(super) async fn serve(policy: AdminPolicy) -> Result<()> {
    let OwnerIdentity::UnixUid { uid } = policy.owner else {
        bail!("a Unix helper policy requires a Unix owner identity");
    };
    prepare_socket_path(uid)?;
    let listener =
        UnixListener::bind(socket_path()).context("failed to bind the privileged helper socket")?;
    fs::set_permissions(socket_path(), fs::Permissions::from_mode(0o600))
        .context("failed to restrict the privileged helper socket")?;
    assign_socket_owner(uid)?;

    let policy = Arc::new(policy);
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENTS));
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("failed to accept a privileged helper client")?;
        let credential = match stream.peer_cred() {
            Ok(credential) if matches!(credential.uid(), peer_uid if peer_uid == uid || peer_uid == 0) => {
                credential
            }
            _ => continue,
        };
        let owner_peer = credential.uid() == uid;
        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
            continue;
        };
        let policy = Arc::clone(&policy);
        tokio::spawn(async move {
            let _permit = permit;
            let _ignored = handle_client(stream, &policy, owner_peer).await;
        });
    }
}

async fn handle_client(
    mut stream: UnixStream,
    policy: &AdminPolicy,
    owner_peer: bool,
) -> Result<()> {
    let bytes = read_frame(&mut stream, MAX_REQUEST_BYTES).await?;
    let request = decode_request(&bytes)?;
    let response = if owner_peer || matches!(&request.operation, super::AdminOperation::Health) {
        handle_authenticated_request(policy, request).await
    } else {
        HelperResponse::rejected(
            request.request_id,
            "the privileged service account may only perform a health check",
        )
    };
    write_frame(&mut stream, &response, MAX_RESPONSE_BYTES).await
}

#[cfg(test)]
static TEST_SOCKET_PATH: std::sync::OnceLock<std::sync::Mutex<Option<PathBuf>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn set_test_socket_path(path: Option<PathBuf>) {
    let mutex = TEST_SOCKET_PATH.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(mut value) = mutex.lock() {
        *value = path;
    }
}

fn socket_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_SOCKET_PATH
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|value| value.clone())
    {
        return path;
    }
    if cfg!(target_os = "linux") {
        PathBuf::from("/run/runonmine-helper/helper.sock")
    } else {
        PathBuf::from("/var/run/runonmine-helper/helper.sock")
    }
}

fn prepare_socket_path(owner_uid: u32) -> Result<()> {
    let path = socket_path();
    let parent = path
        .parent()
        .context("helper socket path has no parent directory")?;
    fs::create_dir_all(parent).context("failed to create helper runtime directory")?;
    let parent_metadata =
        fs::symlink_metadata(parent).context("failed to inspect helper runtime directory")?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
    {
        bail!("helper runtime directory must be a root-owned, non-symlink directory");
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;

    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == owner_uid => {
            fs::remove_file(&path).context("failed to remove stale helper socket")?;
        }
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == 0 => {
            fs::remove_file(&path).context("failed to remove stale root helper socket")?;
        }
        Ok(_) => bail!("refusing to replace a non-socket helper runtime path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect helper socket path"),
    }
    Ok(())
}

fn assign_socket_owner(owner_uid: u32) -> Result<()> {
    nix::unistd::chown(
        &socket_path(),
        Some(nix::unistd::Uid::from_raw(owner_uid)),
        None,
    )
    .context("failed to set helper socket owner")?;
    let metadata =
        fs::symlink_metadata(socket_path()).context("failed to verify helper socket ownership")?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("helper socket ownership verification failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ResetSocketPath;

    impl Drop for ResetSocketPath {
        fn drop(&mut self) {
            set_test_socket_path(None);
        }
    }

    struct RemoveAcceptanceDirectory(PathBuf);

    impl Drop for RemoveAcceptanceDirectory {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.0);
        }
    }

    fn encode_hex(bytes: &[u8]) -> Result<String> {
        use std::fmt::Write as _;
        let mut output = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            write!(&mut output, "{byte:02x}")?;
        }
        Ok(output)
    }

    fn peer_client(
        socket: &std::path::Path,
        encoded_hex: &str,
        user: &nix::unistd::User,
    ) -> Result<std::process::Output> {
        #[cfg(not(target_os = "macos"))]
        use std::os::unix::process::CommandExt as _;
        use std::process::Command;
        let script = r"
import socket, struct, sys
path=sys.argv[1]
payload=bytes.fromhex(sys.argv[2])
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(path)
s.sendall(struct.pack('>I', len(payload)) + payload)
head=s.recv(4)
if len(head) != 4: raise SystemExit('short response header')
length=struct.unpack('>I', head)[0]
data=b''
while len(data) < length:
    chunk=s.recv(length-len(data))
    if not chunk: raise SystemExit('short response body')
    data += chunk
print(data.decode())
";
        #[cfg(target_os = "macos")]
        {
            Ok(Command::new("/usr/bin/sudo")
                .arg("-n")
                .arg("-u")
                .arg(&user.name)
                .arg("/usr/bin/python3")
                .arg("-c")
                .arg(script)
                .arg(socket)
                .arg(encoded_hex)
                .output()?)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(Command::new("/usr/bin/python3")
                .arg("-c")
                .arg(script)
                .arg(socket)
                .arg(encoded_hex)
                .uid(user.uid.as_raw())
                .gid(user.gid.as_raw())
                .output()?)
        }
    }

    #[test]
    fn socket_never_uses_legacy_macmcp_port_or_name() {
        let path = socket_path().to_string_lossy().to_lowercase();
        assert!(!path.contains("macmcp"));
        assert!(!path.contains("45799"));
    }

    #[test]
    fn runtime_parent_is_not_user_writable_by_design() {
        let parent = socket_path().parent().map(std::path::Path::to_path_buf);
        assert!(parent.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires root and two real Unix user identities"]
    async fn real_peer_uid_and_socket_acl_reject_a_second_user() -> Result<()> {
        use std::time::Duration;

        if !nix::unistd::Uid::effective().is_root() {
            bail!("real helper identity acceptance must run as root");
        }
        let owner_name = std::env::var("RUNONMINE_ACCEPTANCE_OWNER_USER")
            .context("RUNONMINE_ACCEPTANCE_OWNER_USER must name the non-root helper owner")?;
        let attacker_name = std::env::var("RUNONMINE_ACCEPTANCE_ATTACKER_USER")
            .context("RUNONMINE_ACCEPTANCE_ATTACKER_USER must name a distinct second user")?;
        let owner = nix::unistd::User::from_name(&owner_name)?
            .with_context(|| format!("acceptance owner {owner_name} is missing"))?;
        let attacker = nix::unistd::User::from_name(&attacker_name)?
            .with_context(|| format!("acceptance attacker {attacker_name} is missing"))?;
        if owner.uid == attacker.uid {
            bail!("helper acceptance identities must be distinct");
        }

        let token = uuid::Uuid::new_v4().simple().to_string();
        let temporary_root = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::env::temp_dir()
        };
        let directory = temporary_root.join(format!("romh-{}", &token[..12]));
        fs::create_dir(&directory).context("failed to create acceptance runtime directory")?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
            .context("failed to make the root-owned acceptance directory traversable")?;
        let _remove_directory = RemoveAcceptanceDirectory(directory.clone());
        let socket = directory.join("helper.sock");
        set_test_socket_path(Some(socket.clone()));
        let _reset = ResetSocketPath;
        let policy = AdminPolicy {
            version: super::super::POLICY_VERSION,
            owner: OwnerIdentity::UnixUid {
                uid: owner.uid.as_raw(),
            },
            allowed_programs: Vec::new(),
        };
        let server = tokio::spawn(serve(policy));
        for _ in 0..100 {
            if fs::symlink_metadata(&socket).is_ok_and(|metadata| metadata.file_type().is_socket())
            {
                break;
            }
            if server.is_finished() {
                return server.await.context("helper server task failed")?;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let metadata = fs::symlink_metadata(&socket)?;
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), owner.uid.as_raw());
        assert_eq!(metadata.mode() & 0o777, 0o600);

        let request = HelperRequest::health();
        let request_id = request.request_id;
        let encoded = serde_json::to_vec(&request)?;
        let encoded_hex = encode_hex(&encoded)?;
        let owner_output = peer_client(&socket, &encoded_hex, &owner)?;
        assert!(
            owner_output.status.success(),
            "owner client failed: {}",
            String::from_utf8_lossy(&owner_output.stderr)
        );
        let response: HelperResponse = serde_json::from_slice(&owner_output.stdout)?;
        assert_eq!(response.request_id, request_id);
        assert!(matches!(
            response.result,
            super::super::HelperResult::Healthy { .. }
        ));

        let attacker_output = peer_client(&socket, &encoded_hex, &attacker)?;
        assert!(!attacker_output.status.success());
        let attacker_error = String::from_utf8_lossy(&attacker_output.stderr);
        assert!(
            attacker_error.contains("PermissionError")
                || attacker_error.contains("Permission denied"),
            "unexpected second-user failure: {attacker_error}"
        );

        server.abort();
        let _ignored = server.await;
        Ok(())
    }
}
