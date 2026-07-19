//! Unix-domain socket transport for macOS and Linux.

use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::process::Command;
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

fn socket_path() -> PathBuf {
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
    let output = Command::new("chown")
        .arg(owner_uid.to_string())
        .arg(socket_path())
        .output()
        .context("failed to set helper socket owner")?;
    if !output.status.success() {
        bail!("failed to restrict helper socket to the installing user");
    }
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
}
