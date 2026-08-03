use crate::desktop_shell::DesktopCommand;

#[derive(Debug)]
pub(crate) enum DesktopInstanceOutcome {
    Primary(DesktopInstance),
    Secondary,
}

#[cfg(target_os = "linux")]
mod native {
    use std::fs;
    use std::io::{ErrorKind, Read as _, Write as _};
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use runonmine_core::AppPaths;

    use super::{DesktopCommand, DesktopInstanceOutcome};

    const SOCKET_FILE: &str = "desktop-instance.sock";
    const SHOW_MESSAGE: &[u8] = b"show\n";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SocketIdentity {
        device: u64,
        inode: u64,
        owner: u32,
    }

    #[derive(Debug)]
    pub(crate) struct DesktopInstance {
        receiver: Receiver<DesktopCommand>,
        socket_path: PathBuf,
        socket_identity: SocketIdentity,
        stopping: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl DesktopInstance {
        pub(crate) fn acquire() -> Result<DesktopInstanceOutcome> {
            let paths = AppPaths::discover()?;
            paths.ensure()?;
            Self::acquire_at(&paths.state_dir.join(SOCKET_FILE))
        }

        fn acquire_at(socket_path: &Path) -> Result<DesktopInstanceOutcome> {
            let parent = socket_path
                .parent()
                .context("desktop instance socket has no parent directory")?;
            ensure_private_parent(parent)?;

            match UnixListener::bind(socket_path) {
                Ok(listener) => Self::primary(listener, socket_path.to_path_buf()),
                Err(error) if error.kind() == ErrorKind::AddrInUse => {
                    if notify_primary(socket_path).is_ok() {
                        return Ok(DesktopInstanceOutcome::Secondary);
                    }
                    remove_stale_socket(socket_path)?;
                    let listener = UnixListener::bind(socket_path).with_context(|| {
                        format!(
                            "failed to bind recovered desktop instance socket at {}",
                            socket_path.display()
                        )
                    })?;
                    Self::primary(listener, socket_path.to_path_buf())
                }
                Err(error) => Err(error).with_context(|| {
                    format!(
                        "failed to bind desktop instance socket at {}",
                        socket_path.display()
                    )
                }),
            }
        }

        fn primary(listener: UnixListener, socket_path: PathBuf) -> Result<DesktopInstanceOutcome> {
            fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
            let socket_identity = owned_socket_identity(&socket_path)?;
            listener.set_nonblocking(true)?;
            let (sender, receiver) = mpsc::channel();
            let stopping = Arc::new(AtomicBool::new(false));
            let worker_stopping = Arc::clone(&stopping);
            let worker = thread::Builder::new()
                .name("runonmine-desktop-instance".to_owned())
                .spawn(move || {
                    while !worker_stopping.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((mut stream, _address)) => {
                                let _ignored =
                                    stream.set_read_timeout(Some(Duration::from_millis(250)));
                                let mut message = [0_u8; SHOW_MESSAGE.len()];
                                if stream.read_exact(&mut message).is_ok()
                                    && message == SHOW_MESSAGE
                                {
                                    let _sent = sender.send(DesktopCommand::Show);
                                }
                            }
                            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(50));
                            }
                            Err(_) => break,
                        }
                    }
                })?;
            Ok(DesktopInstanceOutcome::Primary(Self {
                receiver,
                socket_path,
                socket_identity,
                stopping,
                worker: Some(worker),
            }))
        }

        pub(crate) fn try_command(&self) -> Option<DesktopCommand> {
            self.receiver.try_recv().ok()
        }
    }

    impl Drop for DesktopInstance {
        fn drop(&mut self) {
            self.stopping.store(true, Ordering::Release);
            let _ignored = UnixStream::connect(&self.socket_path);
            if let Some(worker) = self.worker.take() {
                let _ignored = worker.join();
            }
            if owned_socket_identity(&self.socket_path).ok() == Some(self.socket_identity) {
                let _ignored = fs::remove_file(&self.socket_path);
            }
        }
    }

    fn notify_primary(socket_path: &Path) -> Result<()> {
        let _identity = owned_socket_identity(socket_path)?;
        let mut stream = UnixStream::connect(socket_path)?;
        stream.write_all(SHOW_MESSAGE)?;
        Ok(())
    }

    fn ensure_private_parent(parent: &Path) -> Result<()> {
        if parent
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("desktop instance directory must not be a symbolic link");
        }
        fs::create_dir_all(parent)?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            bail!("desktop instance directory must be owned by the current user");
        }
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn owned_socket_identity(socket_path: &Path) -> Result<SocketIdentity> {
        let metadata = fs::symlink_metadata(socket_path).with_context(|| {
            format!(
                "failed to inspect desktop instance socket at {}",
                socket_path.display()
            )
        })?;
        if !metadata.file_type().is_socket() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            bail!("desktop instance socket must be owned by the current user");
        }
        Ok(SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        })
    }

    fn remove_stale_socket(socket_path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(socket_path).with_context(|| {
            format!(
                "desktop instance socket could not be contacted or inspected at {}",
                socket_path.display()
            )
        })?;
        if !metadata.file_type().is_socket() || metadata.uid() != nix::unistd::geteuid().as_raw() {
            bail!(
                "refusing to replace an unsafe desktop instance entry at {}",
                socket_path.display()
            );
        }
        fs::remove_file(socket_path)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::net::UnixListener;

        #[test]
        fn second_instance_notifies_the_primary() -> Result<()> {
            let temporary = tempfile::tempdir()?;
            let socket = temporary.path().join("instance.sock");
            let DesktopInstanceOutcome::Primary(primary) = DesktopInstance::acquire_at(&socket)?
            else {
                bail!("first instance unexpectedly became secondary");
            };
            assert!(matches!(
                DesktopInstance::acquire_at(&socket)?,
                DesktopInstanceOutcome::Secondary
            ));
            for _ in 0..40 {
                if primary.try_command() == Some(DesktopCommand::Show) {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(25));
            }
            bail!("primary instance did not receive the show command")
        }

        #[test]
        fn stale_owned_socket_is_recovered() -> Result<()> {
            let temporary = tempfile::tempdir()?;
            let socket = temporary.path().join("instance.sock");
            let listener = UnixListener::bind(&socket)?;
            drop(listener);
            let outcome = DesktopInstance::acquire_at(&socket)?;
            assert!(matches!(outcome, DesktopInstanceOutcome::Primary(_)));
            Ok(())
        }

        #[test]
        fn dropping_primary_does_not_remove_replacement_socket() -> Result<()> {
            let temporary = tempfile::tempdir()?;
            let socket = temporary.path().join("instance.sock");
            let DesktopInstanceOutcome::Primary(primary) = DesktopInstance::acquire_at(&socket)?
            else {
                bail!("first instance unexpectedly became secondary");
            };
            fs::remove_file(&socket)?;
            let replacement = UnixListener::bind(&socket)?;
            let replacement_identity = owned_socket_identity(&socket)?;
            drop(primary);
            assert_eq!(owned_socket_identity(&socket)?, replacement_identity);
            drop(replacement);
            Ok(())
        }

        #[test]
        fn regular_file_is_not_replaced() -> Result<()> {
            let temporary = tempfile::tempdir()?;
            let socket = temporary.path().join("instance.sock");
            fs::write(&socket, b"do not replace")?;
            assert!(DesktopInstance::acquire_at(&socket).is_err());
            assert_eq!(fs::read(&socket)?, b"do not replace");
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod native {
    use anyhow::Result;

    use super::{DesktopCommand, DesktopInstanceOutcome};

    #[derive(Debug)]
    pub(crate) struct DesktopInstance;

    impl DesktopInstance {
        pub(crate) fn acquire() -> Result<DesktopInstanceOutcome> {
            Ok(DesktopInstanceOutcome::Primary(Self))
        }

        pub(crate) fn try_command(&self) -> Option<DesktopCommand> {
            None
        }
    }
}

pub(crate) use native::DesktopInstance;
