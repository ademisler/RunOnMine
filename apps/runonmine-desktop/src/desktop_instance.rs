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

#[cfg(target_os = "windows")]
mod native {
    #![allow(unsafe_code)] // Audited Win32 lifecycle calls are confined to this module.

    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::thread;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND, LPARAM,
    };
    use windows_sys::Win32::System::Threading::{
        CreateMutexW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, SW_RESTORE,
        SetForegroundWindow, ShowWindow,
    };

    use super::{DesktopCommand, DesktopInstanceOutcome};

    const MUTEX_NAME: &str = r"Local\RunOnMine.Desktop";
    const WINDOW_TITLE: &str = "RunOnMine";

    #[derive(Debug)]
    pub(crate) struct DesktopInstance {
        _mutex: OwnedHandle,
    }

    impl DesktopInstance {
        pub(crate) fn acquire() -> Result<DesktopInstanceOutcome> {
            let executable = std::env::current_exe()
                .context("failed to identify the RunOnMine desktop executable")?;
            Self::acquire_named(MUTEX_NAME, || activate_existing_window(&executable))
        }

        fn acquire_named(name: &str, activate: impl FnOnce()) -> Result<DesktopInstanceOutcome> {
            let wide_name = wide(name);
            // SAFETY: wide_name is NUL-terminated for the complete synchronous call.
            let handle = unsafe { CreateMutexW(ptr::null(), 0, wide_name.as_ptr()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error())
                    .context("failed to create the Windows desktop instance mutex");
            }
            // GetLastError must be read immediately after CreateMutexW because a valid
            // handle is returned for both the first and subsequent callers.
            let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
            if already_exists {
                // SAFETY: handle is the valid reference returned by CreateMutexW.
                unsafe {
                    CloseHandle(handle);
                }
                activate();
                return Ok(DesktopInstanceOutcome::Secondary);
            }
            Ok(DesktopInstanceOutcome::Primary(Self {
                _mutex: OwnedHandle(handle),
            }))
        }

        pub(crate) fn try_command(&self) -> Option<DesktopCommand> {
            assert!(
                !self._mutex.0.is_null(),
                "Windows desktop mutex handle invariant was violated"
            );
            None
        }
    }

    fn activate_existing_window(executable: &Path) {
        for _ in 0..40 {
            if let Some(window) = matching_window(executable) {
                // SAFETY: window was returned by EnumWindows and remains valid for
                // these best-effort, synchronous visibility/focus calls.
                unsafe {
                    ShowWindow(window, SW_RESTORE);
                    SetForegroundWindow(window);
                }
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn matching_window(executable: &Path) -> Option<HWND> {
        let expected = executable.canonicalize().ok()?;
        let mut search = WindowSearch {
            expected: &expected,
            found: ptr::null_mut::<core::ffi::c_void>(),
        };
        // SAFETY: search remains alive and exclusively borrowed for the synchronous
        // enumeration; the callback interprets lparam as the same WindowSearch.
        unsafe {
            EnumWindows(
                Some(enum_window),
                (&raw mut search).cast::<core::ffi::c_void>() as isize,
            );
        }
        (!search.found.is_null()).then_some(search.found)
    }

    struct WindowSearch<'a> {
        expected: &'a Path,
        found: HWND,
    }

    unsafe extern "system" fn enum_window(window: HWND, parameter: LPARAM) -> i32 {
        // SAFETY: matching_window passes a valid WindowSearch pointer and EnumWindows
        // invokes this callback only before that stack value is released.
        let search = unsafe { &mut *(parameter as *mut WindowSearch<'_>) };
        if window_title(window).as_deref() != Some(WINDOW_TITLE) {
            return 1;
        }
        let mut process_id = 0_u32;
        // SAFETY: window is supplied by EnumWindows and process_id is writable.
        unsafe {
            GetWindowThreadProcessId(window, &raw mut process_id);
        }
        if process_id == 0 {
            return 1;
        }
        let Some(candidate) = process_executable(process_id) else {
            return 1;
        };
        let Ok(candidate) = candidate.canonicalize() else {
            return 1;
        };
        if windows_paths_equal(search.expected, &candidate) {
            search.found = window;
            return 0;
        }
        1
    }

    fn window_title(window: HWND) -> Option<String> {
        // SAFETY: window comes from EnumWindows.
        let length = unsafe { GetWindowTextLengthW(window) };
        if length <= 0 || length > 1024 {
            return None;
        }
        let mut buffer = vec![0_u16; usize::try_from(length).ok()?.saturating_add(1)];
        // SAFETY: buffer has room for the reported title plus its NUL terminator.
        let copied = unsafe {
            GetWindowTextW(
                window,
                buffer.as_mut_ptr(),
                i32::try_from(buffer.len()).ok()?,
            )
        };
        if copied <= 0 {
            return None;
        }
        Some(String::from_utf16_lossy(
            &buffer[..usize::try_from(copied).ok()?],
        ))
    }

    fn process_executable(process_id: u32) -> Option<PathBuf> {
        // SAFETY: process_id was obtained from a current top-level window.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        if process.is_null() {
            return None;
        }
        let process = OwnedHandle(process);
        let mut buffer = vec![0_u16; 32_768];
        let mut length = u32::try_from(buffer.len()).ok()?;
        // SAFETY: process is retained and buffer/length satisfy the API contract.
        if unsafe { QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &raw mut length) }
            == 0
        {
            return None;
        }
        let value = OsString::from_wide(&buffer[..usize::try_from(length).ok()?]);
        Some(PathBuf::from(value))
    }

    fn windows_paths_equal(left: &Path, right: &Path) -> bool {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }

    fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
        value.as_ref().encode_wide().chain(Some(0)).collect()
    }

    #[derive(Debug)]
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this wrapper uniquely owns the Windows handle.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        #[test]
        fn named_mutex_keeps_one_primary_and_notifies_the_secondary() -> Result<()> {
            let name = format!(
                r"Local\RunOnMine.Desktop.Test.{}.{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            );
            let DesktopInstanceOutcome::Primary(primary) =
                DesktopInstance::acquire_named(&name, || {})?
            else {
                anyhow::bail!("first Windows desktop instance was not primary");
            };
            let activated = Arc::new(AtomicBool::new(false));
            let secondary_activated = Arc::clone(&activated);
            assert!(matches!(
                DesktopInstance::acquire_named(&name, move || {
                    secondary_activated.store(true, Ordering::Release);
                })?,
                DesktopInstanceOutcome::Secondary
            ));
            assert!(activated.load(Ordering::Acquire));
            drop(primary);
            assert!(matches!(
                DesktopInstance::acquire_named(&name, || {})?,
                DesktopInstanceOutcome::Primary(_)
            ));
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
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
