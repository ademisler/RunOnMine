use std::fmt;
use std::fs;
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use anyhow::{Context, Result, anyhow, bail};
use tempfile::NamedTempFile;

use super::service::{
    SystemPaths, apply_artifact_permissions, reject_existing_symlink,
    remove_regular_file_if_present,
};
use super::{AdminPolicy, OwnerIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ServiceState {
    pub(super) installed: bool,
    pub(super) enabled: bool,
    pub(super) running: bool,
}

pub(super) trait ServiceLifecycle: fmt::Debug + Send + Sync {
    fn state(&self, paths: &SystemPaths) -> Result<ServiceState>;
    fn stop(&self, paths: &SystemPaths) -> Result<()>;
    fn activate(&self, paths: &SystemPaths) -> Result<()>;
    fn restore(&self, paths: &SystemPaths, previous: ServiceState) -> Result<()>;
    fn health(
        &self,
        owner: OwnerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactKind {
    Binary,
    Policy,
    ServiceDefinition,
}

impl ArtifactKind {
    const fn mode(self) -> u32 {
        match self {
            Self::Binary => 0o755,
            Self::Policy => 0o600,
            Self::ServiceDefinition => 0o644,
        }
    }

    const fn executable(self) -> bool {
        matches!(self, Self::Binary)
    }
}

#[derive(Debug)]
struct StagedArtifact {
    destination: PathBuf,
    kind: ArtifactKind,
    temporary: Option<NamedTempFile>,
}

impl StagedArtifact {
    fn from_file(source: &Path, destination: PathBuf, kind: ArtifactKind) -> Result<Self> {
        let parent = destination
            .parent()
            .context("staged helper artifact has no parent directory")?;
        let mut temporary =
            NamedTempFile::new_in(parent).context("failed to create a staged helper artifact")?;
        let mut source = fs::File::open(source).context("failed to open helper source artifact")?;
        std::io::copy(&mut source, temporary.as_file_mut())
            .context("failed to stage helper source artifact")?;
        finish_staging(&temporary, kind.mode())?;
        Ok(Self {
            destination,
            kind,
            temporary: Some(temporary),
        })
    }

    fn from_bytes(destination: PathBuf, bytes: &[u8], kind: ArtifactKind) -> Result<Self> {
        let parent = destination
            .parent()
            .context("staged helper artifact has no parent directory")?;
        let mut temporary =
            NamedTempFile::new_in(parent).context("failed to create a staged helper artifact")?;
        temporary
            .write_all(bytes)
            .context("failed to write a staged helper artifact")?;
        finish_staging(&temporary, kind.mode())?;
        Ok(Self {
            destination,
            kind,
            temporary: Some(temporary),
        })
    }

    fn activate(&mut self) -> Result<()> {
        reject_existing_symlink(&self.destination)?;
        remove_regular_file_if_present(&self.destination)?;
        let temporary = self
            .temporary
            .take()
            .context("staged helper artifact was already activated")?;
        temporary
            .persist(&self.destination)
            .map_err(|error| error.error)
            .with_context(|| {
                format!(
                    "failed to activate staged helper artifact {}",
                    self.destination.display()
                )
            })?;
        apply_artifact_permissions(&self.destination, self.kind.executable(), self.kind.mode())?;
        sync_parent(&self.destination)
    }
}

fn finish_staging(temporary: &NamedTempFile, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    temporary.as_file().sync_all()?;
    Ok(())
}

#[derive(Debug)]
enum ArtifactSnapshot {
    Missing {
        destination: PathBuf,
    },
    File {
        destination: PathBuf,
        kind: ArtifactKind,
        bytes: Vec<u8>,
        #[cfg(unix)]
        mode: u32,
    },
}

impl ArtifactSnapshot {
    fn capture(destination: PathBuf, kind: ArtifactKind) -> Result<Self> {
        let metadata = match fs::symlink_metadata(&destination) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::Missing { destination });
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect helper artifact {}",
                        destination.display()
                    )
                });
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "refusing to snapshot a non-regular helper artifact: {}",
                destination.display()
            );
        }
        let mut file = fs::File::open(&destination)
            .with_context(|| format!("failed to open helper artifact {}", destination.display()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt as _;
            metadata.permissions().mode() & 0o777
        };
        Ok(Self::File {
            destination,
            kind,
            bytes,
            #[cfg(unix)]
            mode,
        })
    }

    fn previous_owner(&self) -> Option<OwnerIdentity> {
        let Self::File {
            kind: ArtifactKind::Policy,
            bytes,
            ..
        } = self
        else {
            return None;
        };
        serde_json::from_slice::<AdminPolicy>(bytes)
            .ok()
            .map(|policy| policy.owner)
    }

    fn restore(&self) -> Result<()> {
        match self {
            Self::Missing { destination } => {
                remove_regular_file_if_present(destination)?;
                sync_parent(destination)
            }
            Self::File {
                destination,
                kind,
                bytes,
                #[cfg(unix)]
                mode,
            } => {
                reject_existing_symlink(destination)?;
                remove_regular_file_if_present(destination)?;
                let parent = destination
                    .parent()
                    .context("helper rollback artifact has no parent directory")?;
                let mut temporary = NamedTempFile::new_in(parent)
                    .context("failed to stage a helper rollback artifact")?;
                temporary.write_all(bytes)?;
                #[cfg(unix)]
                temporary
                    .as_file()
                    .set_permissions(std::os::unix::fs::PermissionsExt::from_mode(*mode))?;
                temporary.as_file().sync_all()?;
                temporary
                    .persist(destination)
                    .map_err(|error| error.error)
                    .context("failed to restore a helper artifact")?;
                #[cfg(unix)]
                let restore_mode = *mode;
                #[cfg(not(unix))]
                let restore_mode = kind.mode();
                apply_artifact_permissions(destination, kind.executable(), restore_mode)?;
                sync_parent(destination)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum InstallFault {
    #[default]
    None,
    AfterBinary,
    AfterPolicy,
    AfterServiceDefinition,
}

impl InstallFault {
    fn check(self, expected: Self) -> Result<()> {
        if self == expected {
            bail!("injected helper installation failure at {expected:?}");
        }
        Ok(())
    }
}

pub(super) struct InstallRequest<'a> {
    pub(super) paths: &'a SystemPaths,
    pub(super) source_executable: &'a Path,
    pub(super) policy_bytes: &'a [u8],
    pub(super) service_definition: Option<&'a [u8]>,
    pub(super) owner: OwnerIdentity,
    pub(super) fault: InstallFault,
}

impl fmt::Debug for InstallRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallRequest")
            .field("paths", self.paths)
            .field("source_executable", &self.source_executable)
            .field("has_service_definition", &self.service_definition.is_some())
            .field("owner", &self.owner)
            .field("fault", &self.fault)
            .finish_non_exhaustive()
    }
}

pub(super) async fn install_transaction(
    request: InstallRequest<'_>,
    lifecycle: &dyn ServiceLifecycle,
) -> Result<()> {
    let mut binary = StagedArtifact::from_file(
        request.source_executable,
        request.paths.binary.clone(),
        ArtifactKind::Binary,
    )?;
    let mut policy = StagedArtifact::from_bytes(
        request.paths.policy.clone(),
        request.policy_bytes,
        ArtifactKind::Policy,
    )?;
    let mut service = match (
        request.paths.service_definition.as_ref(),
        request.service_definition,
    ) {
        (Some(destination), Some(bytes)) => Some(StagedArtifact::from_bytes(
            destination.clone(),
            bytes,
            ArtifactKind::ServiceDefinition,
        )?),
        (None, None) => None,
        _ => bail!("helper service definition path and staged contents must agree"),
    };

    let snapshots = capture_snapshots(request.paths)?;
    let previous_owner = snapshots.iter().find_map(ArtifactSnapshot::previous_owner);
    let previous_state = lifecycle.state(request.paths)?;

    let result = async {
        lifecycle.stop(request.paths)?;
        binary.activate()?;
        request.fault.check(InstallFault::AfterBinary)?;
        policy.activate()?;
        request.fault.check(InstallFault::AfterPolicy)?;
        if let Some(service) = service.as_mut() {
            service.activate()?;
        }
        request.fault.check(InstallFault::AfterServiceDefinition)?;
        lifecycle.activate(request.paths)?;
        lifecycle.health(request.owner).await
    }
    .await;

    if let Err(error) = result {
        let rollback = rollback_installation(
            request.paths,
            &snapshots,
            previous_state,
            previous_owner,
            lifecycle,
        )
        .await;
        return match rollback {
            Ok(()) => Err(error.context("helper installation rolled back to the previous state")),
            Err(rollback_error) => Err(anyhow!(
                "helper installation failed: {error:#}; rollback also failed: {rollback_error:#}"
            )),
        };
    }
    Ok(())
}

fn capture_snapshots(paths: &SystemPaths) -> Result<Vec<ArtifactSnapshot>> {
    let mut snapshots = vec![
        ArtifactSnapshot::capture(paths.binary.clone(), ArtifactKind::Binary)?,
        ArtifactSnapshot::capture(paths.policy.clone(), ArtifactKind::Policy)?,
    ];
    if let Some(service) = &paths.service_definition {
        snapshots.push(ArtifactSnapshot::capture(
            service.clone(),
            ArtifactKind::ServiceDefinition,
        )?);
    }
    Ok(snapshots)
}

async fn rollback_installation(
    paths: &SystemPaths,
    snapshots: &[ArtifactSnapshot],
    previous_state: ServiceState,
    previous_owner: Option<OwnerIdentity>,
    lifecycle: &dyn ServiceLifecycle,
) -> Result<()> {
    let mut failures = Vec::new();
    if let Err(error) = lifecycle.stop(paths) {
        failures.push(format!("stop failed: {error:#}"));
    }
    for snapshot in snapshots.iter().rev() {
        if let Err(error) = snapshot.restore() {
            failures.push(format!("artifact restore failed: {error:#}"));
        }
    }
    if let Err(error) = lifecycle.restore(paths, previous_state) {
        failures.push(format!("service restore failed: {error:#}"));
    } else if previous_state.running {
        match previous_owner {
            Some(owner) => {
                if let Err(error) = lifecycle.health(owner).await {
                    failures.push(format!("restored helper health check failed: {error:#}"));
                }
            }
            None => failures.push(
                "restored helper health could not be verified because its policy owner is unavailable"
                    .to_owned(),
            ),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}

fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .context("helper artifact has no parent directory")?;
        fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Debug)]
    struct FakeLifecycle {
        state: ServiceState,
        fail_activate: bool,
        fail_health_once: Arc<Mutex<bool>>,
        fail_restore: bool,
        expected_at_stop: Vec<(PathBuf, Vec<u8>)>,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl FakeLifecycle {
        fn new(state: ServiceState) -> Self {
            Self {
                state,
                fail_activate: false,
                fail_health_once: Arc::new(Mutex::new(false)),
                fail_restore: false,
                expected_at_stop: Vec::new(),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn events(&self) -> Result<Vec<String>> {
            self.events
                .lock()
                .map(|events| events.clone())
                .map_err(|_| anyhow!("fake lifecycle event mutex was poisoned"))
        }

        fn record(&self, event: &str) -> Result<()> {
            self.events
                .lock()
                .map_err(|_| anyhow!("fake lifecycle event mutex was poisoned"))?
                .push(event.to_owned());
            Ok(())
        }
    }

    impl ServiceLifecycle for FakeLifecycle {
        fn state(&self, _paths: &SystemPaths) -> Result<ServiceState> {
            self.record("state")?;
            Ok(self.state)
        }

        fn stop(&self, _paths: &SystemPaths) -> Result<()> {
            for (path, expected) in &self.expected_at_stop {
                let actual = fs::read(path).with_context(|| {
                    format!("failed to inspect {} at service stop", path.display())
                })?;
                if actual != *expected {
                    bail!("helper artifact changed before every replacement was staged");
                }
            }
            self.record("stop")
        }

        fn activate(&self, _paths: &SystemPaths) -> Result<()> {
            self.record("activate")?;
            if self.fail_activate {
                bail!("injected service activation failure");
            }
            Ok(())
        }

        fn restore(&self, _paths: &SystemPaths, previous: ServiceState) -> Result<()> {
            self.record(&format!(
                "restore:{}:{}:{}",
                previous.installed, previous.enabled, previous.running
            ))?;
            if self.fail_restore {
                bail!("injected service rollback failure");
            }
            Ok(())
        }

        fn health(
            &self,
            _owner: OwnerIdentity,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>> {
            let events = Arc::clone(&self.events);
            let fail_once = Arc::clone(&self.fail_health_once);
            Box::pin(async move {
                events
                    .lock()
                    .map_err(|_| anyhow!("fake lifecycle event mutex was poisoned"))?
                    .push("health".to_owned());
                let should_fail = {
                    let mut failure = fail_once
                        .lock()
                        .map_err(|_| anyhow!("fake health mutex was poisoned"))?;
                    let value = *failure;
                    *failure = false;
                    value
                };
                if should_fail {
                    bail!("injected helper health failure");
                }
                Ok(())
            })
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        paths: SystemPaths,
        source: PathBuf,
        old_binary: Vec<u8>,
        old_policy: Vec<u8>,
        old_service: Vec<u8>,
        new_policy: Vec<u8>,
    }

    impl Fixture {
        fn installed() -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let root = directory.path();
            let paths = SystemPaths {
                binary: root.join("bin/helper"),
                policy: root.join("etc/policy.json"),
                service_definition: Some(root.join("service/helper.service")),
                socket: root.join("run/helper.sock"),
            };
            for path in [
                &paths.binary,
                &paths.policy,
                paths
                    .service_definition
                    .as_ref()
                    .context("test service path is missing")?,
            ] {
                fs::create_dir_all(path.parent().context("test path has no parent")?)?;
            }
            let source = root.join("source-helper");
            fs::write(&source, b"new-binary")?;
            let old_binary = b"old-binary".to_vec();
            let old_policy = serde_json::to_vec(&AdminPolicy {
                version: super::super::POLICY_VERSION,
                owner: OwnerIdentity::UnixUid { uid: 1000 },
                allowed_programs: Vec::new(),
            })?;
            let old_service = b"old-service".to_vec();
            let new_policy = b"new-policy".to_vec();
            fs::write(&paths.binary, &old_binary)?;
            fs::write(&paths.policy, &old_policy)?;
            fs::write(
                paths
                    .service_definition
                    .as_ref()
                    .context("test service path is missing")?,
                &old_service,
            )?;
            Ok(Self {
                _directory: directory,
                paths,
                source,
                old_binary,
                old_policy,
                old_service,
                new_policy,
            })
        }

        fn request(&self, fault: InstallFault) -> InstallRequest<'_> {
            InstallRequest {
                paths: &self.paths,
                source_executable: &self.source,
                policy_bytes: &self.new_policy,
                service_definition: Some(b"new-service"),
                owner: OwnerIdentity::UnixUid { uid: 1000 },
                fault,
            }
        }

        fn assert_old_artifacts(&self) -> Result<()> {
            assert_eq!(fs::read(&self.paths.binary)?, self.old_binary);
            assert_eq!(fs::read(&self.paths.policy)?, self.old_policy);
            assert_eq!(
                fs::read(
                    self.paths
                        .service_definition
                        .as_ref()
                        .context("test service path is missing")?
                )?,
                self.old_service
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn partial_artifact_activation_restores_every_previous_file() -> Result<()> {
        let fixture = Fixture::installed()?;
        let lifecycle = FakeLifecycle::new(ServiceState {
            installed: true,
            enabled: true,
            running: true,
        });
        assert!(
            install_transaction(fixture.request(InstallFault::AfterBinary), &lifecycle)
                .await
                .is_err()
        );
        fixture.assert_old_artifacts()?;
        assert!(
            lifecycle
                .events()?
                .contains(&"restore:true:true:true".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn service_activation_failure_restores_previous_installation() -> Result<()> {
        let fixture = Fixture::installed()?;
        let mut lifecycle = FakeLifecycle::new(ServiceState {
            installed: true,
            enabled: true,
            running: true,
        });
        lifecycle.fail_activate = true;
        assert!(
            install_transaction(fixture.request(InstallFault::None), &lifecycle)
                .await
                .is_err()
        );
        fixture.assert_old_artifacts()?;
        assert_eq!(
            lifecycle.events()?,
            vec![
                "state",
                "stop",
                "activate",
                "stop",
                "restore:true:true:true",
                "health"
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn health_failure_restores_previous_installation() -> Result<()> {
        let fixture = Fixture::installed()?;
        let lifecycle = FakeLifecycle::new(ServiceState {
            installed: true,
            enabled: true,
            running: true,
        });
        *lifecycle
            .fail_health_once
            .lock()
            .map_err(|_| anyhow!("fake health mutex was poisoned"))? = true;
        assert!(
            install_transaction(fixture.request(InstallFault::None), &lifecycle)
                .await
                .is_err()
        );
        fixture.assert_old_artifacts()?;
        let events = lifecycle.events()?;
        assert_eq!(events.iter().filter(|event| *event == "health").count(), 2);
        assert!(events.contains(&"restore:true:true:true".to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn failed_first_install_leaves_no_artifacts_or_service() -> Result<()> {
        let fixture = Fixture::installed()?;
        for path in [
            &fixture.paths.binary,
            &fixture.paths.policy,
            fixture
                .paths
                .service_definition
                .as_ref()
                .context("test service path is missing")?,
        ] {
            fs::remove_file(path)?;
        }
        let mut lifecycle = FakeLifecycle::new(ServiceState {
            installed: false,
            enabled: false,
            running: false,
        });
        lifecycle.fail_activate = true;
        assert!(
            install_transaction(fixture.request(InstallFault::None), &lifecycle)
                .await
                .is_err()
        );
        assert!(!fixture.paths.binary.exists());
        assert!(!fixture.paths.policy.exists());
        assert!(
            fixture
                .paths
                .service_definition
                .as_ref()
                .is_some_and(|path| !path.exists())
        );
        assert!(
            lifecycle
                .events()?
                .contains(&"restore:false:false:false".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn rollback_failure_is_reported_with_the_original_error() -> Result<()> {
        let fixture = Fixture::installed()?;
        let mut lifecycle = FakeLifecycle::new(ServiceState {
            installed: true,
            enabled: true,
            running: true,
        });
        lifecycle.fail_activate = true;
        lifecycle.fail_restore = true;
        let error = match install_transaction(fixture.request(InstallFault::None), &lifecycle).await
        {
            Ok(()) => bail!("injected activation and rollback failures unexpectedly succeeded"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(message.contains("service activation failure"));
        assert!(message.contains("rollback also failed"));
        assert!(message.contains("service rollback failure"));
        fixture.assert_old_artifacts()?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_destination_is_rejected_before_service_stop() -> Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::installed()?;
        let outside = fixture.paths.policy.with_extension("outside");
        fs::write(&outside, b"outside-policy")?;
        fs::remove_file(&fixture.paths.policy)?;
        symlink(&outside, &fixture.paths.policy)?;
        let lifecycle = FakeLifecycle::new(ServiceState {
            installed: true,
            enabled: true,
            running: true,
        });
        assert!(
            install_transaction(fixture.request(InstallFault::None), &lifecycle)
                .await
                .is_err()
        );
        assert!(lifecycle.events()?.is_empty());
        assert_eq!(fs::read(outside)?, b"outside-policy");
        Ok(())
    }

    #[tokio::test]
    async fn rollback_of_running_service_requires_a_restored_policy_owner() -> Result<()> {
        let fixture = Fixture::installed()?;
        fs::write(&fixture.paths.policy, b"invalid-old-policy")?;
        let mut lifecycle = FakeLifecycle::new(ServiceState {
            installed: true,
            enabled: true,
            running: true,
        });
        lifecycle.fail_activate = true;
        let error = match install_transaction(fixture.request(InstallFault::None), &lifecycle).await
        {
            Ok(()) => bail!("rollback without a verifiable previous owner unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("policy owner is unavailable"));
        assert_eq!(fs::read(&fixture.paths.policy)?, b"invalid-old-policy");
        Ok(())
    }

    #[tokio::test]
    async fn successful_install_keeps_new_artifacts() -> Result<()> {
        let fixture = Fixture::installed()?;
        let mut lifecycle = FakeLifecycle::new(ServiceState {
            installed: true,
            enabled: true,
            running: true,
        });
        lifecycle.expected_at_stop = vec![
            (fixture.paths.binary.clone(), fixture.old_binary.clone()),
            (fixture.paths.policy.clone(), fixture.old_policy.clone()),
            (
                fixture
                    .paths
                    .service_definition
                    .clone()
                    .context("test service path is missing")?,
                fixture.old_service.clone(),
            ),
        ];
        install_transaction(fixture.request(InstallFault::None), &lifecycle).await?;
        assert_eq!(fs::read(&fixture.paths.binary)?, b"new-binary");
        assert_eq!(fs::read(&fixture.paths.policy)?, b"new-policy");
        assert_eq!(
            fs::read(
                fixture
                    .paths
                    .service_definition
                    .as_ref()
                    .context("test service path is missing")?
            )?,
            b"new-service"
        );
        assert_eq!(
            lifecycle.events()?,
            vec!["state", "stop", "activate", "health"]
        );
        Ok(())
    }
}
