//! Cross-process approval-change notifications with database polling as recovery.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher as _};
use tokio::sync::watch;
use uuid::Uuid;

const APPROVAL_PULSE_FILE: &str = "approval-events";

#[derive(Clone)]
pub struct ApprovalNotifications {
    inner: Arc<ApprovalNotificationsInner>,
}

struct ApprovalNotificationsInner {
    sender: watch::Sender<u64>,
    pulse_path: Option<PathBuf>,
    watcher: Mutex<Option<RecommendedWatcher>>,
    delivered: AtomicU64,
    signal_failures: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ApprovalNotificationMetrics {
    pub native_watcher_active: bool,
    pub delivered: u64,
    pub signal_failures: u64,
}

pub struct ApprovalNotificationSubscription {
    receiver: watch::Receiver<u64>,
}

impl Default for ApprovalNotifications {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl std::fmt::Debug for ApprovalNotifications {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalNotifications")
            .field("metrics", &self.metrics())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ApprovalNotificationSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalNotificationSubscription")
            .finish_non_exhaustive()
    }
}

impl ApprovalNotifications {
    pub(crate) fn for_state_db(state_db: &Path) -> Result<Self> {
        let parent = state_db
            .parent()
            .context("state database path has no parent")?;
        let parent = parent
            .canonicalize()
            .with_context(|| format!("failed to resolve {}", parent.display()))?;
        let pulse_path = parent.join(APPROVAL_PULSE_FILE);
        ensure_safe_pulse_file(&pulse_path)?;
        Ok(Self::new(Some(pulse_path)))
    }

    #[must_use]
    pub fn in_memory() -> Self {
        Self::new(None)
    }

    fn new(pulse_path: Option<PathBuf>) -> Self {
        let (sender, _receiver) = watch::channel(0_u64);
        let inner = Arc::new(ApprovalNotificationsInner {
            sender,
            pulse_path: pulse_path.clone(),
            watcher: Mutex::new(None),
            delivered: AtomicU64::new(0),
            signal_failures: AtomicU64::new(0),
        });
        if let Some(path) = pulse_path {
            install_watcher(&inner, &path);
        }
        Self { inner }
    }

    #[must_use]
    pub fn subscribe(&self) -> ApprovalNotificationSubscription {
        ApprovalNotificationSubscription {
            receiver: self.inner.sender.subscribe(),
        }
    }

    pub fn notify(&self) {
        deliver(&self.inner);
        let Some(path) = self.inner.pulse_path.as_deref() else {
            return;
        };
        let payload = Uuid::new_v4().as_hyphenated().to_string();
        if crate::atomic::write(path, payload.as_bytes(), 0o600).is_err() {
            self.inner.signal_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn metrics(&self) -> ApprovalNotificationMetrics {
        let native_watcher_active = self
            .inner
            .watcher
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some();
        ApprovalNotificationMetrics {
            native_watcher_active,
            delivered: self.inner.delivered.load(Ordering::Relaxed),
            signal_failures: self.inner.signal_failures.load(Ordering::Relaxed),
        }
    }
}

impl ApprovalNotificationSubscription {
    pub async fn changed(&mut self) -> Result<()> {
        self.receiver
            .changed()
            .await
            .context("approval notification channel closed")
    }
}

fn ensure_safe_pulse_file(path: &Path) -> Result<()> {
    match path.symlink_metadata() {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("approval notification pulse must be a regular file");
            }
            restrict_pulse_file(path)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::atomic::write(path, b"initial", 0o600)
        }
        Err(error) => Err(error).context("failed to inspect approval notification pulse"),
    }
}

#[cfg(unix)]
fn restrict_pulse_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .context("failed to restrict approval notification pulse")
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_pulse_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn install_watcher(inner: &Arc<ApprovalNotificationsInner>, pulse_path: &Path) {
    let Some(parent) = pulse_path.parent() else {
        return;
    };
    let pulse_name = pulse_path.file_name().map(ToOwned::to_owned);
    let callback_inner = Arc::downgrade(inner);
    let watcher = notify::recommended_watcher(move |event: notify::Result<Event>| {
        let Ok(event) = event else {
            return;
        };
        if event
            .paths
            .iter()
            .any(|path| path.file_name() == pulse_name.as_deref())
            && let Some(inner) = callback_inner.upgrade()
        {
            deliver(&inner);
        }
    });
    let Ok(mut watcher) = watcher else {
        return;
    };
    if watcher.watch(parent, RecursiveMode::NonRecursive).is_err() {
        return;
    }
    *inner
        .watcher
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(watcher);
}

fn deliver(inner: &ApprovalNotificationsInner) {
    inner.delivered.fetch_add(1, Ordering::Relaxed);
    inner.sender.send_modify(|generation| {
        *generation = generation.wrapping_add(1);
    });
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn in_memory_signal_wakes_subscriber() -> Result<()> {
        let notifications = ApprovalNotifications::in_memory();
        let mut subscription = notifications.subscribe();
        notifications.notify();
        tokio::time::timeout(Duration::from_secs(1), subscription.changed())
            .await
            .context("in-memory approval notification timed out")??;
        assert!(notifications.metrics().delivered >= 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pulse_file_is_owner_only() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir()?;
        let state_db = directory.path().join("state.db");
        fs::write(&state_db, [])?;
        let notifications = ApprovalNotifications::for_state_db(&state_db)?;
        let pulse = directory.path().join(APPROVAL_PULSE_FILE);
        assert_eq!(fs::metadata(pulse)?.permissions().mode() & 0o777, 0o600);
        assert!(notifications.metrics().native_watcher_active);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_pulse_is_rejected() -> Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempdir()?;
        let state_db = directory.path().join("state.db");
        fs::write(&state_db, [])?;
        let target = directory.path().join("target");
        fs::write(&target, b"untouched")?;
        symlink(&target, directory.path().join(APPROVAL_PULSE_FILE))?;
        assert!(ApprovalNotifications::for_state_db(&state_db).is_err());
        assert_eq!(fs::read(target)?, b"untouched");
        Ok(())
    }
}
