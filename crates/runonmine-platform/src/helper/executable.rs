#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::{AllowedProgram, validate_privileged_program_ownership};

#[derive(Debug)]
pub(super) struct PreparedExecutable {
    file: File,
    canonical_path: PathBuf,
    identity: PlatformFileIdentity,
    expected_sha256: String,
    #[cfg(target_os = "linux")]
    descriptor_path: PathBuf,
}

pub(super) fn inspect_path(path: &Path) -> Result<(PathBuf, String)> {
    if !path.is_absolute() {
        bail!("an admin executable must be an absolute path");
    }
    let file = open_program_file(path)?;
    let metadata_before = file
        .metadata()
        .context("failed to inspect the opened admin executable")?;
    if !metadata_before.is_file() {
        bail!("admin executable must be a regular file");
    }
    validate_privileged_program_ownership(path, &metadata_before)?;
    let identity = platform_file_identity(&file)?;
    let canonical_path = canonical_open_file_path(path, &file)?;
    let digest = sha256_file_handle(&file)?;
    if platform_file_identity(&file)? != identity {
        bail!("admin executable changed while it was being inspected");
    }
    if !bool::from(
        sha256_file_handle(&file)?
            .as_bytes()
            .ct_eq(digest.as_bytes()),
    ) {
        bail!("admin executable content changed while it was being inspected");
    }
    Ok((canonical_path, digest))
}

impl PreparedExecutable {
    pub(super) fn open(allowed: &AllowedProgram, requested: &Path) -> Result<Option<Self>> {
        Self::open_with_validator(allowed, requested, validate_privileged_program_ownership)
    }

    fn open_with_validator<F>(
        allowed: &AllowedProgram,
        requested: &Path,
        validator: F,
    ) -> Result<Option<Self>>
    where
        F: Fn(&Path, &fs::Metadata) -> Result<()>,
    {
        if !requested.is_absolute() {
            return Ok(None);
        }
        let path_metadata = match fs::symlink_metadata(requested) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("failed to inspect an admin executable"),
        };
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Ok(None);
        }
        validator(requested, &path_metadata)?;
        let file = open_program_file(requested)?;
        let metadata_before = file
            .metadata()
            .context("failed to inspect the opened admin executable")?;
        if !metadata_before.is_file() {
            return Ok(None);
        }
        validator(requested, &metadata_before)?;
        let identity = platform_file_identity(&file)?;
        let canonical_path = canonical_open_file_path(requested, &file)?;
        if canonical_path != allowed.canonical_path {
            return Ok(None);
        }
        let digest = sha256_file_handle(&file)?;
        if !bool::from(digest.as_bytes().ct_eq(allowed.sha256.as_bytes())) {
            return Ok(None);
        }
        if platform_file_identity(&file)? != identity {
            bail!("admin executable changed while it was being verified");
        }

        #[cfg(target_os = "linux")]
        let descriptor_path = {
            use std::os::fd::AsRawFd as _;

            PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
        };

        Ok(Some(Self {
            file,
            canonical_path,
            identity,
            expected_sha256: allowed.sha256.clone(),
            #[cfg(target_os = "linux")]
            descriptor_path,
        }))
    }

    #[cfg(unix)]
    pub(super) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    #[cfg(target_os = "linux")]
    pub(super) fn make_inheritable_for_spawn(&self) -> Result<()> {
        nix::fcntl::fcntl(
            &self.file,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
        )
        .context("failed to retain the verified admin executable descriptor for spawn")?;
        Ok(())
    }

    pub(super) fn command_path(&self) -> &Path {
        #[cfg(target_os = "linux")]
        {
            &self.descriptor_path
        }
        #[cfg(not(target_os = "linux"))]
        {
            &self.canonical_path
        }
    }

    pub(super) fn revalidate_before_spawn(&self) -> Result<()> {
        if platform_file_identity(&self.file)? != self.identity {
            bail!("prepared admin executable identity changed before spawn");
        }
        let digest = sha256_file_handle(&self.file)?;
        if !bool::from(digest.as_bytes().ct_eq(self.expected_sha256.as_bytes())) {
            bail!("prepared admin executable content changed before spawn");
        }

        #[cfg(not(target_os = "linux"))]
        {
            let current = open_program_file(&self.canonical_path)?;
            let current_metadata = current
                .metadata()
                .context("failed to inspect the current admin executable path")?;
            validate_privileged_program_ownership(&self.canonical_path, &current_metadata)?;
            if platform_file_identity(&current)? != self.identity
                || !bool::from(
                    sha256_file_handle(&current)?
                        .as_bytes()
                        .ct_eq(self.expected_sha256.as_bytes()),
                )
            {
                bail!("admin executable path changed after authorization");
            }
        }
        Ok(())
    }
}

fn sha256_file_handle(file: &File) -> Result<String> {
    let mut file = file
        .try_clone()
        .context("failed to clone an admin executable handle")?;
    file.seek(SeekFrom::Start(0))
        .context("failed to rewind an admin executable handle")?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .context("failed to hash an admin executable")?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(windows)]
fn open_program_file(path: &Path) -> Result<File> {
    super::windows::open_privileged_program(path)
}

#[cfg(unix)]
fn open_program_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits() | nix::fcntl::OFlag::O_CLOEXEC.bits())
        .open(path)
        .context("failed to open an admin executable without following symlinks")
}

#[cfg(not(any(unix, windows)))]
fn open_program_file(path: &Path) -> Result<File> {
    File::open(path).context("failed to open an admin executable")
}

#[cfg(target_os = "linux")]
fn canonical_open_file_path(_requested: &Path, file: &File) -> Result<PathBuf> {
    use std::os::fd::AsRawFd as _;

    fs::canonicalize(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .context("failed to resolve the opened admin executable")
}

#[cfg(not(target_os = "linux"))]
fn canonical_open_file_path(requested: &Path, file: &File) -> Result<PathBuf> {
    let canonical = requested
        .canonicalize()
        .context("failed to resolve the opened admin executable path")?;
    let current = open_program_file(&canonical)?;
    if platform_file_identity(&current)? != platform_file_identity(file)? {
        bail!("admin executable path changed while it was being opened");
    }
    Ok(canonical)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlatformFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn platform_file_identity(file: &File) -> Result<PlatformFileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .context("failed to inspect an admin executable identity")?;
    Ok(PlatformFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
type PlatformFileIdentity = super::windows::FileIdentity;

#[cfg(windows)]
fn platform_file_identity(file: &File) -> Result<PlatformFileIdentity> {
    super::windows::file_identity(file)
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlatformFileIdentity {
    length: u64,
}

#[cfg(not(any(unix, windows)))]
fn platform_file_identity(file: &File) -> Result<PlatformFileIdentity> {
    let metadata = file
        .metadata()
        .context("failed to inspect an admin executable identity")?;
    Ok(PlatformFileIdentity {
        length: metadata.len(),
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    use tempfile::tempdir;

    use super::*;
    use crate::helper::AdminCommandSchema;

    #[test]
    fn verified_descriptor_executes_original_inode_after_path_replacement() -> Result<()> {
        let directory = tempdir()?;
        let program = directory.path().join("verified-original-command.sh");
        let replacement = directory.path().join("verified-replacement-command.sh");
        fs::write(&program, b"#!/bin/sh\nprintf original")?;
        fs::write(&replacement, b"#!/bin/sh\nprintf replacement")?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755))?;
        let allowed = AllowedProgram {
            canonical_path: program.canonicalize()?,
            sha256: sha256_file_handle(&File::open(&program)?)?,
            commands: vec![AdminCommandSchema::no_arguments()],
        };
        let prepared =
            PreparedExecutable::open_with_validator(&allowed, &program, |_path, _metadata| Ok(()))?
                .context("verified command handle was not prepared")?;

        fs::rename(&replacement, &program)?;
        prepared.revalidate_before_spawn()?;
        prepared.make_inheritable_for_spawn()?;
        let output = Command::new(prepared.command_path()).output()?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"original");
        assert_eq!(fs::read(&program)?, b"#!/bin/sh\nprintf replacement");
        Ok(())
    }

    #[test]
    fn descriptor_stays_close_on_exec_until_immediate_spawn() -> Result<()> {
        use std::os::fd::AsRawFd as _;

        let directory = tempdir()?;
        let program = directory.path().join("verified-original-command.sh");
        fs::write(&program, b"#!/bin/sh\nprintf original")?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755))?;
        let allowed = AllowedProgram {
            canonical_path: program.canonicalize()?,
            sha256: sha256_file_handle(&File::open(&program)?)?,
            commands: vec![AdminCommandSchema::no_arguments()],
        };
        let prepared =
            PreparedExecutable::open_with_validator(&allowed, &program, |_path, _metadata| Ok(()))?
                .context("verified command handle was not prepared")?;
        let before = nix::fcntl::fcntl(&prepared.file, nix::fcntl::FcntlArg::F_GETFD)?;
        assert_ne!(before & nix::libc::FD_CLOEXEC, 0);
        prepared.make_inheritable_for_spawn()?;
        let after = nix::fcntl::fcntl(&prepared.file, nix::fcntl::FcntlArg::F_GETFD)?;
        assert_eq!(after & nix::libc::FD_CLOEXEC, 0);
        assert!(prepared.file.as_raw_fd() >= 0);
        Ok(())
    }

    #[test]
    fn in_place_content_change_is_detected_before_spawn() -> Result<()> {
        let directory = tempdir()?;
        let program = directory.path().join("verified-original-command.sh");
        fs::write(&program, b"#!/bin/sh\nprintf original")?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755))?;
        let allowed = AllowedProgram {
            canonical_path: program.canonicalize()?,
            sha256: sha256_file_handle(&File::open(&program)?)?,
            commands: vec![AdminCommandSchema::no_arguments()],
        };
        let prepared =
            PreparedExecutable::open_with_validator(&allowed, &program, |_path, _metadata| Ok(()))?
                .context("verified command handle was not prepared")?;
        fs::write(&program, b"#!/bin/sh\nprintf changed!")?;
        assert!(prepared.revalidate_before_spawn().is_err());
        Ok(())
    }
}
