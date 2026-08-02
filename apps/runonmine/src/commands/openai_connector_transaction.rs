//! Transactional preparation and activation for `OpenAI` tunnel connectors.

#[allow(clippy::wildcard_imports)]
use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::connectors::{
    managed_receipt_path, prepare_latest_managed_binary, verify_managed_binary,
};

const ACTIVATION_MARKER: &str = ".runonmine-openai-activation";

#[derive(Debug)]
pub(super) struct OpenAiConnectorStaging {
    transaction_id: String,
    staging_data_root: PathBuf,
    staging_state_root: PathBuf,
    final_data_root: PathBuf,
    final_state_root: PathBuf,
    activated_data: bool,
    activated_state: bool,
    committed: bool,
}

impl OpenAiConnectorStaging {
    pub(super) fn prepare(paths: &AppPaths, connector_id: &str) -> Result<Self> {
        validate_connector_id(connector_id)?;
        paths.ensure()?;
        ensure_real_private_directory(&paths.data_dir)?;
        ensure_real_private_directory(&paths.state_dir)?;

        let final_data_root = paths.data_dir.join("connectors").join(connector_id);
        let final_state_root = paths.state_dir.join("connectors").join(connector_id);
        ensure_path_absent(&final_data_root, "OpenAI connector data")?;
        ensure_path_absent(&final_state_root, "OpenAI connector state")?;

        let transaction_id = Uuid::new_v4().to_string();
        let staging_data_root = paths.data_dir.join(format!(
            ".openai-stage-{connector_id}-{transaction_id}-data"
        ));
        let staging_state_root = paths.state_dir.join(format!(
            ".openai-stage-{connector_id}-{transaction_id}-state"
        ));
        create_transaction_root(&staging_data_root, &transaction_id)?;
        if let Err(error) = create_transaction_root(&staging_state_root, &transaction_id) {
            let cleanup = remove_owned_transaction_root(&staging_data_root, &transaction_id);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(error.context(format!(
                    "OpenAI data staging cleanup also failed: {cleanup_error:#}"
                ))),
            };
        }
        let profile_directory = staging_data_root.join("openai-profiles");
        if let Err(error) = ensure_real_private_directory(&profile_directory) {
            let data_cleanup = remove_owned_transaction_root(&staging_data_root, &transaction_id);
            let state_cleanup = remove_owned_transaction_root(&staging_state_root, &transaction_id);
            return Err(combine_staging_cleanup_errors(
                error,
                data_cleanup,
                state_cleanup,
            ));
        }

        Ok(Self {
            transaction_id,
            staging_data_root,
            staging_state_root,
            final_data_root,
            final_state_root,
            activated_data: false,
            activated_state: false,
            committed: false,
        })
    }

    pub(super) fn profile_directory(&self) -> PathBuf {
        self.staging_data_root.join("openai-profiles")
    }

    pub(super) fn health_directory(&self) -> &Path {
        &self.staging_state_root
    }

    fn activate(&mut self) -> Result<()> {
        self.verify_owned(&self.staging_data_root)?;
        self.verify_owned(&self.staging_state_root)?;
        ensure_path_absent(&self.final_data_root, "OpenAI connector data")?;
        ensure_path_absent(&self.final_state_root, "OpenAI connector state")?;
        ensure_real_private_directory(
            self.final_data_root
                .parent()
                .context("OpenAI connector data path has no parent")?,
        )?;
        ensure_real_private_directory(
            self.final_state_root
                .parent()
                .context("OpenAI connector state path has no parent")?,
        )?;

        fs::rename(&self.staging_data_root, &self.final_data_root)
            .context("failed to activate OpenAI connector data")?;
        self.activated_data = true;
        sync_parent(&self.final_data_root)?;
        if let Err(error) = fs::rename(&self.staging_state_root, &self.final_state_root) {
            let cleanup = self.remove_owned(&self.final_data_root);
            self.activated_data = false;
            return match cleanup {
                Ok(()) => Err(error).context("failed to activate OpenAI connector state"),
                Err(cleanup_error) => Err(error).context(format!(
                    "failed to activate OpenAI connector state; partial activation cleanup also failed: {cleanup_error:#}"
                )),
            };
        }
        self.activated_state = true;
        sync_parent(&self.final_state_root)?;
        Ok(())
    }

    fn finish(&mut self) {
        self.committed = true;
    }

    fn rollback(&mut self) -> Result<()> {
        if self.committed {
            return Ok(());
        }
        let mut failures = Vec::new();
        for path in [
            self.activated_state.then_some(&self.final_state_root),
            self.activated_data.then_some(&self.final_data_root),
            Some(&self.staging_state_root),
            Some(&self.staging_data_root),
        ]
        .into_iter()
        .flatten()
        {
            if let Err(error) = self.remove_owned(path) {
                failures.push(format!("{}: {error:#}", path.display()));
            }
        }
        self.activated_data = false;
        self.activated_state = false;
        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "OpenAI connector staging rollback was incomplete: {}",
                failures.join("; ")
            )
        }
    }

    fn verify_owned(&self, root: &Path) -> Result<()> {
        let marker = root.join(ACTIVATION_MARKER);
        let metadata = fs::symlink_metadata(&marker).with_context(|| {
            format!("OpenAI activation marker is missing in {}", root.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("OpenAI activation marker is not a safe regular file");
        }
        let value = fs::read_to_string(&marker)?;
        if value != self.transaction_id {
            bail!("OpenAI activation marker does not belong to this transaction");
        }
        Ok(())
    }

    fn remove_owned(&self, root: &Path) -> Result<()> {
        match fs::symlink_metadata(root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                bail!("refusing to remove an unsafe OpenAI connector transaction path")
            }
            Ok(_) => {}
        }
        self.verify_owned(root)?;
        fs::remove_dir_all(root).with_context(|| {
            format!(
                "failed to remove OpenAI transaction path {}",
                root.display()
            )
        })?;
        sync_parent(root)
    }
}

impl Drop for OpenAiConnectorStaging {
    fn drop(&mut self) {
        let _ignored = self.rollback();
    }
}

#[derive(Debug)]
pub(super) enum OpenAiBinaryStaging {
    Existing(InstalledBinary),
    Versioned(Box<VersionedOpenAiBinary>),
}

#[derive(Debug)]
pub(super) struct VersionedOpenAiBinary {
    binary: InstalledBinary,
    store: VersionedBinaryStore,
    version: ManagedBinaryVersion,
    activation: Option<ManagedBinaryActivation>,
    committed: bool,
}

impl OpenAiBinaryStaging {
    pub(super) fn configured_path(
        paths: &AppPaths,
        explicit_path: Option<&Path>,
    ) -> Result<PathBuf> {
        if let Some(path) = explicit_path {
            return Ok(
                InstalledBinary::from_verified_path(BinaryKind::OpenAiTunnelClient, path)?.path,
            );
        }
        let store = managed_binary_store(&paths.data_dir, BinaryKind::OpenAiTunnelClient);
        let active_manifest = store.root().join("active.json");
        match fs::symlink_metadata(&active_manifest) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("managed OpenAI active manifest is unsafe")
            }
            Ok(_) => store
                .resolve_active()?
                .map(|version| version.binary_path)
                .context("managed OpenAI active manifest has no valid version"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(store.version(&"0".repeat(64))?.binary_path)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(super) async fn prepare(paths: &AppPaths, explicit_path: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit_path {
            let binary = InstalledBinary::from_verified_path(BinaryKind::OpenAiTunnelClient, path)?;
            BinaryProbe::run_compatible(&binary, Duration::from_secs(10)).await?;
            return Ok(Self::Existing(binary));
        }

        let store = managed_binary_store(&paths.data_dir, BinaryKind::OpenAiTunnelClient);
        if let Some(active) = store.resolve_active()? {
            let binary = InstalledBinary::from_verified_path(
                BinaryKind::OpenAiTunnelClient,
                &active.binary_path,
            )?;
            verify_managed_binary(
                &binary,
                ReleaseProvider::OpenAiTunnelClient,
                &active.receipt_path,
            )?;
            BinaryProbe::run_compatible(&binary, Duration::from_secs(10)).await?;
            return Ok(Self::Existing(binary));
        }

        let legacy_directory = paths.data_dir.join("bin");
        let legacy_binary = legacy_directory.join(BinaryKind::OpenAiTunnelClient.executable_name());
        let legacy_receipt =
            managed_receipt_path(&legacy_directory, BinaryKind::OpenAiTunnelClient);
        let binary_present = safe_regular_file_presence(&legacy_binary, "managed OpenAI binary")?;
        let receipt_present =
            safe_regular_file_presence(&legacy_receipt, "managed OpenAI receipt")?;
        if binary_present != receipt_present {
            bail!(
                "managed OpenAI tunnel-client installation is incomplete; repair or remove the existing binary/receipt pair before connector setup"
            );
        }
        if binary_present {
            let legacy = InstalledBinary::from_verified_path(
                BinaryKind::OpenAiTunnelClient,
                &legacy_binary,
            )?;
            verify_managed_binary(
                &legacy,
                ReleaseProvider::OpenAiTunnelClient,
                &legacy_receipt,
            )
            .context(
                "existing managed OpenAI tunnel-client failed integrity verification; repair or remove it before connector setup",
            )?;
            BinaryProbe::run_compatible(&legacy, Duration::from_secs(10))
                .await
                .context(
                    "existing managed OpenAI tunnel-client is outside the supported compatibility range",
                )?;
            let mut receipt: InstallReceipt =
                serde_json::from_slice(&fs::read(&legacy_receipt)?)
                    .context("existing managed OpenAI receipt is invalid")?;
            let version_id = store.version_id_for_file(&legacy_binary)?;
            let target = store.version(&version_id)?;
            receipt.installed_path.clone_from(&target.binary_path);
            let version = store.prepare(&legacy_binary, &serde_json::to_vec_pretty(&receipt)?)?;
            let binary = InstalledBinary::from_verified_path(
                BinaryKind::OpenAiTunnelClient,
                &version.binary_path,
            )?;
            verify_managed_binary(
                &binary,
                ReleaseProvider::OpenAiTunnelClient,
                &version.receipt_path,
            )?;
            return Ok(Self::Versioned(Box::new(VersionedOpenAiBinary {
                binary,
                store,
                version,
                activation: None,
                committed: false,
            })));
        }

        let prepared = prepare_latest_managed_binary(
            paths,
            BinaryKind::OpenAiTunnelClient,
            ReleaseProvider::OpenAiTunnelClient,
        )
        .await?;
        Ok(Self::Versioned(Box::new(VersionedOpenAiBinary {
            binary: prepared.binary,
            store: prepared.store,
            version: prepared.version,
            activation: None,
            committed: false,
        })))
    }

    pub(super) fn binary(&self) -> &InstalledBinary {
        match self {
            Self::Existing(binary) => binary,
            Self::Versioned(versioned) => &versioned.binary,
        }
    }

    pub(super) fn configured_binary_path(&self) -> PathBuf {
        match self {
            Self::Existing(binary) => binary.path.clone(),
            Self::Versioned(versioned) => versioned.binary.path.clone(),
        }
    }

    fn activate(&mut self) -> Result<()> {
        if let Self::Versioned(versioned) = self {
            versioned.activation = Some(versioned.store.activate(&versioned.version)?);
        }
        Ok(())
    }

    fn finish(&mut self) {
        if let Self::Versioned(versioned) = self {
            versioned.committed = true;
        }
    }

    fn rollback(&mut self) -> Result<()> {
        if let Self::Versioned(versioned) = self {
            if versioned.committed {
                return Ok(());
            }
            if let Some(activation) = versioned.activation.take() {
                versioned.store.rollback(activation)?;
            }
        }
        Ok(())
    }
}

impl Drop for OpenAiBinaryStaging {
    fn drop(&mut self) {
        let _ignored = self.rollback();
    }
}

fn safe_regular_file_presence(path: &Path, description: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{description} must be a regular non-symlink file")
        }
        Ok(_) => Ok(true),
    }
}

fn create_transaction_root(root: &Path, transaction_id: &str) -> Result<()> {
    ensure_path_absent(root, "OpenAI transaction staging")?;
    ensure_real_private_directory(root)?;
    if let Err(error) = write_marker(root, transaction_id) {
        let cleanup = remove_new_transaction_root(root);
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(error.context(format!(
                "OpenAI transaction-root cleanup also failed: {cleanup_error:#}"
            ))),
        };
    }
    Ok(())
}

fn remove_new_transaction_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("refusing to remove an unsafe new OpenAI transaction root")
        }
        Ok(_) => {}
    }
    fs::remove_dir_all(root)?;
    sync_parent(root)
}

fn combine_staging_cleanup_errors(
    error: anyhow::Error,
    data_cleanup: Result<()>,
    state_cleanup: Result<()>,
) -> anyhow::Error {
    let mut details = Vec::new();
    if let Err(cleanup) = data_cleanup {
        details.push(format!("data cleanup failed: {cleanup:#}"));
    }
    if let Err(cleanup) = state_cleanup {
        details.push(format!("state cleanup failed: {cleanup:#}"));
    }
    if details.is_empty() {
        error
    } else {
        error.context(details.join("; "))
    }
}

fn verify_transaction_root(root: &Path, transaction_id: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("OpenAI transaction root must be a real directory");
    }
    let marker = root.join(ACTIVATION_MARKER);
    let marker_metadata = fs::symlink_metadata(&marker)?;
    if marker_metadata.file_type().is_symlink() || !marker_metadata.is_file() {
        bail!("OpenAI transaction marker must be a regular non-symlink file");
    }
    if fs::read_to_string(marker)? != transaction_id {
        bail!("OpenAI transaction marker does not belong to this transaction");
    }
    Ok(())
}

fn remove_owned_transaction_root(root: &Path, transaction_id: &str) -> Result<()> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("refusing to remove an unsafe OpenAI transaction root")
        }
        Ok(_) => {}
    }
    verify_transaction_root(root, transaction_id)?;
    fs::remove_dir_all(root)?;
    sync_parent(root)
}

pub(super) fn validate_new_openai_connector(
    paths: &AppPaths,
    config_path: &Path,
    mut connector: ConnectorConfig,
) -> Result<ConnectorConfig> {
    let _removal_lock = ConnectorRemovalLock::acquire(paths)?;
    ConnectorRemovalJournal::new(paths).ensure_id_available(&connector.id)?;
    let mut config = if config_path.exists() {
        AppConfig::load(config_path)?
    } else {
        AppConfig::default()
    };
    if config.connector(&connector.id).is_some() {
        bail!("connector id already exists");
    }
    connector.policy_preset = config.default_preset;
    config.connectors.push(connector.clone());
    config.validate()?;
    Ok(connector)
}

pub(super) fn commit_prepared_openai_connector(
    connector: ConnectorConfig,
    paths: &AppPaths,
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    values: &[(String, SecretString)],
    binary: OpenAiBinaryStaging,
    staging: OpenAiConnectorStaging,
) -> Result<()> {
    let connector_id = connector.id.clone();
    let configured_binary = connector
        .openai_tunnel
        .as_ref()
        .and_then(|settings| settings.tunnel_client_path.as_ref())
        .context("OpenAI connector has no tunnel-client path")?;
    if configured_binary != &binary.configured_binary_path() {
        bail!("OpenAI connector path does not match the prepared tunnel-client");
    }
    let _removal_lock = ConnectorRemovalLock::acquire(paths)?;
    ConnectorRemovalJournal::new(paths).ensure_id_available(&connector_id)?;
    let mut state = OpenAiCommitState {
        secrets: SecretTransaction::new(secrets),
        binary,
        staging,
    };
    AppConfig::update_with_activation(
        config_path,
        &mut state,
        move |config, state| {
            if config.connector(&connector_id).is_some() {
                bail!("connector id already exists");
            }
            for (name, value) in values {
                state.secrets.set(name, value)?;
            }
            let mut connector = connector;
            connector.policy_preset = config.default_preset;
            config.connectors.push(connector);
            Ok(())
        },
        |(), state| {
            state.binary.activate()?;
            state.staging.activate()?;
            state.binary.finish();
            state.staging.finish();
            Ok(())
        },
        rollback_openai_commit,
    )
}

#[derive(Debug)]
struct OpenAiCommitState<'a> {
    secrets: SecretTransaction<'a>,
    binary: OpenAiBinaryStaging,
    staging: OpenAiConnectorStaging,
}

fn rollback_openai_commit(state: &mut OpenAiCommitState<'_>) -> Result<()> {
    let mut failures = Vec::new();
    if let Err(error) = state.staging.rollback() {
        failures.push(format!("profile/state rollback failed: {error:#}"));
    }
    if let Err(error) = state.binary.rollback() {
        failures.push(format!("binary rollback failed: {error:#}"));
    }
    if let Err(error) = state.secrets.rollback() {
        failures.push(format!("secret rollback failed: {error:#}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}

fn validate_connector_id(connector_id: &str) -> Result<()> {
    runonmine_core::validate_connector_id(connector_id).context("OpenAI connector ID is invalid")
}

fn ensure_real_private_directory(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked OpenAI connector directory");
    }
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("OpenAI connector path must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn ensure_path_absent(path: &Path, description: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => bail!("{description} path already exists: {}", path.display()),
    }
}

fn write_marker(root: &Path, transaction_id: &str) -> Result<()> {
    use std::io::Write as _;

    let path = root.join(ACTIVATION_MARKER);
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path)?;
    file.write_all(transaction_id.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "parent directory fsync is Unix-only while connector activation keeps one fallible interface"
)]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;
    use std::sync::Mutex;

    use runonmine_connectors::Sha256Digest;
    use runonmine_core::secrets::SecretStore as _;
    use secrecy::ExposeSecret as _;
    use sha2::{Digest as _, Sha256};

    use super::*;

    #[derive(Default)]
    struct TestSecretStore {
        values: Mutex<BTreeMap<String, String>>,
        fail_name: Mutex<Option<String>>,
    }

    impl TestSecretStore {
        fn fail_next_set(&self, name: &str) -> Result<()> {
            *self
                .fail_name
                .lock()
                .map_err(|_| anyhow::anyhow!("test failure lock failed"))? = Some(name.to_owned());
            Ok(())
        }
    }

    impl runonmine_core::secrets::SecretStore for TestSecretStore {
        fn get(&self, name: &str) -> Result<Option<SecretString>> {
            Ok(self
                .values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret lock failed"))?
                .get(name)
                .cloned()
                .map(SecretString::from))
        }

        fn set(&self, name: &str, value: &SecretString) -> Result<()> {
            let mut failure = self
                .fail_name
                .lock()
                .map_err(|_| anyhow::anyhow!("test failure lock failed"))?;
            if failure.as_deref() == Some(name) {
                *failure = None;
                bail!("injected secret-store failure");
            }
            drop(failure);
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret lock failed"))?
                .insert(name.to_owned(), value.expose_secret().to_owned());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret lock failed"))?
                .remove(name);
            Ok(())
        }
    }

    fn existing_binary() -> Result<OpenAiBinaryStaging> {
        Ok(OpenAiBinaryStaging::Existing(InstalledBinary {
            kind: BinaryKind::OpenAiTunnelClient,
            path: std::env::current_exe()?.canonicalize()?,
        }))
    }

    fn versioned_binary(paths: &AppPaths, contents: &[u8]) -> Result<OpenAiBinaryStaging> {
        let store = managed_binary_store(&paths.data_dir, BinaryKind::OpenAiTunnelClient);
        let source = paths
            .data_dir
            .join(format!("test-openai-{}", Uuid::new_v4()));
        fs::write(&source, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o700))?;
        }
        let version_id = store.version_id_for_file(&source)?;
        let target = store.version(&version_id)?;
        let digest = Sha256::digest(contents);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            write!(&mut encoded, "{byte:02x}")?;
        }
        let receipt = InstallReceipt {
            provider: ReleaseProvider::OpenAiTunnelClient,
            release_tag: "test-v0.0.10".to_owned(),
            sha256: Sha256Digest::parse(&format!("sha256:{encoded}"))?,
            installed_path: target.binary_path.clone(),
            provenance: None,
        };
        let version = store.prepare(&source, &serde_json::to_vec_pretty(&receipt)?)?;
        fs::remove_file(source)?;
        let binary = InstalledBinary::from_verified_path(
            BinaryKind::OpenAiTunnelClient,
            &version.binary_path,
        )?;
        Ok(OpenAiBinaryStaging::Versioned(Box::new(
            VersionedOpenAiBinary {
                binary,
                store,
                version,
                activation: None,
                committed: false,
            },
        )))
    }

    fn connector(id: &str) -> ConnectorConfig {
        connector_with_binary(
            id,
            std::env::current_exe()
                .and_then(|path| path.canonicalize())
                .unwrap_or_else(|_| PathBuf::from("/usr/bin/true")),
        )
    }

    fn connector_with_binary(id: &str, binary_path: PathBuf) -> ConnectorConfig {
        ConnectorConfig {
            id: id.to_owned(),
            name: "OpenAI test connector".to_owned(),
            kind: ConnectorKind::OpenAiTunnel,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: BTreeMap::new(),
            tool_overrides: BTreeMap::new(),
            policy_rules: Vec::new(),
            public_base_url: None,
            cloudflare_quick: None,
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: Some(OpenAiTunnelSettings {
                tunnel_id: "tunnel_0123456789abcdef0123456789abcdef".to_owned(),
                profile: "test-profile".to_owned(),
                tunnel_client_path: Some(binary_path),
                health_port: 47_823,
            }),
        }
    }

    fn prepared_staging(paths: &AppPaths, id: &str) -> Result<OpenAiConnectorStaging> {
        let staging = OpenAiConnectorStaging::prepare(paths, id)?;
        fs::write(
            staging.profile_directory().join("test-profile.yaml"),
            b"profile",
        )?;
        Ok(staging)
    }

    #[test]
    fn transaction_root_creation_and_owned_cleanup_are_symmetric() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("transaction-root");
        create_transaction_root(&root, "transaction-id")?;
        assert!(root.is_dir());
        remove_owned_transaction_root(&root, "transaction-id")?;
        assert!(!root.exists());
        Ok(())
    }

    #[test]
    fn second_configured_openai_connector_is_rejected_before_staging() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        let binary = std::env::current_exe()?.canonicalize()?;
        let mut config = AppConfig::default();
        let mut existing = connector_with_binary("existing-openai", binary.clone());
        existing.enabled = false;
        config.connectors.push(existing);
        config.save(&config_path)?;
        let mut candidate = connector_with_binary("second-openai", binary);
        candidate
            .openai_tunnel
            .as_mut()
            .context("test OpenAI settings are missing")?
            .health_port = 47_825;

        assert!(validate_new_openai_connector(&paths, &config_path, candidate).is_err());
        assert!(
            fs::read_dir(&paths.data_dir)?
                .filter_map(std::result::Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().starts_with(".openai-"))
        );
        assert!(!paths.data_dir.join("connectors/second-openai").exists());
        assert!(!paths.state_dir.join("connectors/second-openai").exists());
        Ok(())
    }

    #[test]
    fn validation_failure_creates_no_connector_artifacts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        let mut config = AppConfig::default();
        config.connectors.push(connector("existing"));
        config.save(&config_path)?;
        let result = validate_new_openai_connector(&paths, &config_path, connector("new"));
        assert!(result.is_err());
        assert!(!paths.data_dir.join("connectors/new").exists());
        assert!(!paths.state_dir.join("connectors/new").exists());
        Ok(())
    }

    #[test]
    fn secret_failure_rolls_back_config_and_staging() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        AppConfig::default().save(&config_path)?;
        let staging = prepared_staging(&paths, "secret-fail")?;
        let stage_data = staging.staging_data_root.clone();
        let stage_state = staging.staging_state_root.clone();
        let store = TestSecretStore::default();
        let name = "connector.secret-fail.runtime_api_key".to_owned();
        store.fail_next_set(&name)?;
        let result = commit_prepared_openai_connector(
            connector("secret-fail"),
            &paths,
            &config_path,
            &store,
            &[(name.clone(), SecretString::from("secret".to_owned()))],
            existing_binary()?,
            staging,
        );
        assert!(result.is_err());
        assert!(
            AppConfig::load(&config_path)?
                .connector("secret-fail")
                .is_none()
        );
        assert!(store.get(&name)?.is_none());
        assert!(!stage_data.exists());
        assert!(!stage_state.exists());
        assert!(!paths.data_dir.join("connectors/secret-fail").exists());
        assert!(!paths.state_dir.join("connectors/secret-fail").exists());
        Ok(())
    }

    #[test]
    fn activation_failure_restores_config_secret_and_partial_artifacts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        AppConfig::default().save(&config_path)?;
        let staging = prepared_staging(&paths, "activate-fail")?;
        fs::remove_dir_all(&staging.staging_state_root)?;
        let store = TestSecretStore::default();
        let name = "connector.activate-fail.runtime_api_key".to_owned();
        store.set(&name, &SecretString::from("previous".to_owned()))?;
        let result = commit_prepared_openai_connector(
            connector("activate-fail"),
            &paths,
            &config_path,
            &store,
            &[(name.clone(), SecretString::from("secret".to_owned()))],
            existing_binary()?,
            staging,
        );
        assert!(result.is_err());
        assert!(
            AppConfig::load(&config_path)?
                .connector("activate-fail")
                .is_none()
        );
        assert_eq!(
            store
                .get(&name)?
                .map(|value| value.expose_secret().to_owned()),
            Some("previous".to_owned())
        );
        assert!(!paths.data_dir.join("connectors/activate-fail").exists());
        assert!(!paths.state_dir.join("connectors/activate-fail").exists());
        Ok(())
    }

    #[test]
    fn profile_activation_failure_removes_new_managed_binary_and_receipt() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        AppConfig::default().save(&config_path)?;
        let staging = prepared_staging(&paths, "binary-rollback")?;
        fs::remove_dir_all(&staging.staging_state_root)?;
        let binary = versioned_binary(&paths, b"new tunnel client")?;
        let final_binary = binary.configured_binary_path();
        let store = TestSecretStore::default();
        let name = "connector.binary-rollback.runtime_api_key".to_owned();
        store.set(&name, &SecretString::from("previous".to_owned()))?;

        let result = commit_prepared_openai_connector(
            connector_with_binary("binary-rollback", final_binary.clone()),
            &paths,
            &config_path,
            &store,
            &[(name.clone(), SecretString::from("secret".to_owned()))],
            binary,
            staging,
        );
        assert!(result.is_err());
        assert!(final_binary.exists());
        assert!(
            managed_binary_store(&paths.data_dir, BinaryKind::OpenAiTunnelClient)
                .resolve_active()?
                .is_none()
        );
        assert!(
            AppConfig::load(&config_path)?
                .connector("binary-rollback")
                .is_none()
        );
        assert_eq!(
            store
                .get(&name)?
                .map(|value| value.expose_secret().to_owned()),
            Some("previous".to_owned())
        );
        assert!(!paths.data_dir.join("connectors/binary-rollback").exists());
        assert!(!paths.state_dir.join("connectors/binary-rollback").exists());
        Ok(())
    }

    #[test]
    fn dropping_versioned_binary_does_not_activate_it() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let binary = versioned_binary(&paths, b"temporary tunnel client")?;
        let immutable_path = binary.configured_binary_path();
        drop(binary);
        assert!(immutable_path.exists());
        assert!(
            managed_binary_store(&paths.data_dir, BinaryKind::OpenAiTunnelClient)
                .resolve_active()?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn dropping_prepared_staging_removes_precommit_artifacts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let staging = prepared_staging(&paths, "drop-before-commit")?;
        let data_stage = staging.staging_data_root.clone();
        let state_stage = staging.staging_state_root.clone();
        drop(staging);
        assert!(!data_stage.exists());
        assert!(!state_stage.exists());
        assert!(
            !paths
                .data_dir
                .join("connectors/drop-before-commit")
                .exists()
        );
        assert!(
            !paths
                .state_dir
                .join("connectors/drop-before-commit")
                .exists()
        );
        Ok(())
    }

    #[test]
    fn successful_activation_commits_config_secret_and_artifacts() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        AppConfig::default().save(&config_path)?;
        let staging = prepared_staging(&paths, "success-connector")?;
        let binary = versioned_binary(&paths, b"successful tunnel client")?;
        let final_binary = binary.configured_binary_path();
        let store = TestSecretStore::default();
        let name = "connector.success-connector.runtime_api_key".to_owned();
        commit_prepared_openai_connector(
            connector_with_binary("success-connector", final_binary.clone()),
            &paths,
            &config_path,
            &store,
            &[(name.clone(), SecretString::from("secret".to_owned()))],
            binary,
            staging,
        )?;
        assert!(
            AppConfig::load(&config_path)?
                .connector("success-connector")
                .is_some()
        );
        assert_eq!(
            store
                .get(&name)?
                .map(|value| value.expose_secret().to_owned()),
            Some("secret".to_owned())
        );
        assert!(final_binary.is_file());
        let active_binary = managed_binary_store(&paths.data_dir, BinaryKind::OpenAiTunnelClient)
            .resolve_active()?
            .context("OpenAI version was not activated")?
            .binary_path;
        assert_eq!(active_binary.canonicalize()?, final_binary.canonicalize()?);
        assert!(
            paths
                .data_dir
                .join("connectors/success-connector/openai-profiles/test-profile.yaml")
                .is_file()
        );
        assert!(
            paths
                .state_dir
                .join(format!("connectors/success-connector/{ACTIVATION_MARKER}"))
                .is_file()
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_managed_binary_migrates_and_activation_rolls_back() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let legacy_dir = paths.data_dir.join("bin");
        ensure_real_private_directory(&legacy_dir)?;
        let legacy = legacy_dir.join(BinaryKind::OpenAiTunnelClient.executable_name());
        let bytes = br#"#!/bin/sh
if [ "${1:-}" = "--version" ]; then printf '%s
' 'tunnel-client version 0.0.10'; exit 0; fi
exit 0
"#;
        fs::write(&legacy, bytes)?;
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700))?;
        let digest = Sha256::digest(bytes);
        let mut hex = String::with_capacity(64);
        for byte in digest {
            write!(&mut hex, "{byte:02x}")?;
        }
        let receipt_path = managed_receipt_path(&legacy_dir, BinaryKind::OpenAiTunnelClient);
        fs::write(
            &receipt_path,
            serde_json::to_vec_pretty(&InstallReceipt {
                provider: ReleaseProvider::OpenAiTunnelClient,
                release_tag: "v0.0.10".to_owned(),
                sha256: Sha256Digest::parse(&format!("sha256:{hex}"))?,
                installed_path: legacy.clone(),
                provenance: None,
            })?,
        )?;
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600))?;
        let mut prepared = OpenAiBinaryStaging::prepare(&paths, None).await?;
        let immutable = prepared.configured_binary_path();
        assert_ne!(immutable, legacy);
        assert!(immutable.is_file());
        prepared.activate()?;
        let store = managed_binary_store(&paths.data_dir, BinaryKind::OpenAiTunnelClient);
        let active_binary = store
            .resolve_active()?
            .context("missing active version")?
            .binary_path;
        assert_eq!(active_binary.canonicalize()?, immutable.canonicalize()?);
        prepared.rollback()?;
        assert!(store.resolve_active()?.is_none());
        assert!(legacy.is_file());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn incompatible_candidate_preserves_known_good_active_version() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let mut known_good = versioned_binary(&paths, b"known-good")?;
        known_good.activate()?;
        let store = managed_binary_store(&paths.data_dir, BinaryKind::OpenAiTunnelClient);
        let active = store
            .resolve_active()?
            .context("missing known-good version")?;
        let candidate = paths.data_dir.join("future-tunnel-client");
        fs::write(
            &candidate,
            br#"#!/bin/sh
if [ "${1:-}" = "--version" ]; then printf '%s
' 'tunnel-client version 0.0.11-dev'; exit 0; fi
exit 0
"#,
        )?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
        let binary =
            InstalledBinary::from_verified_path(BinaryKind::OpenAiTunnelClient, &candidate)?;
        assert!(
            BinaryProbe::run_compatible(&binary, Duration::from_secs(5))
                .await
                .is_err()
        );
        assert_eq!(
            store
                .resolve_active()?
                .context("known-good disappeared")?
                .version_id,
            active.version_id
        );
        Ok(())
    }

    #[tokio::test]
    async fn incomplete_or_invalid_existing_managed_binary_is_preserved() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let final_binary = paths
            .data_dir
            .join("bin")
            .join(BinaryKind::OpenAiTunnelClient.executable_name());
        ensure_real_private_directory(
            final_binary
                .parent()
                .context("test managed binary has no parent")?,
        )?;
        fs::write(&final_binary, b"do not replace")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&final_binary, fs::Permissions::from_mode(0o700))?;
        }
        assert!(OpenAiBinaryStaging::prepare(&paths, None).await.is_err());
        assert_eq!(fs::read(&final_binary)?, b"do not replace");

        let final_receipt = managed_receipt_path(
            final_binary
                .parent()
                .context("test managed binary has no parent")?,
            BinaryKind::OpenAiTunnelClient,
        );
        fs::write(&final_receipt, b"invalid receipt")?;
        assert!(OpenAiBinaryStaging::prepare(&paths, None).await.is_err());
        assert_eq!(fs::read(&final_binary)?, b"do not replace");
        assert_eq!(fs::read(&final_receipt)?, b"invalid receipt");
        Ok(())
    }

    #[test]
    fn staging_rejects_connector_id_path_injection() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        assert!(OpenAiConnectorStaging::prepare(&paths, "../escape").is_err());
        assert!(!directory.path().join("escape").exists());
        Ok(())
    }

    #[test]
    fn preexisting_final_path_is_preserved() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let final_path = paths.data_dir.join("connectors/existing");
        fs::create_dir_all(&final_path)?;
        fs::write(final_path.join("keep"), b"keep")?;
        assert!(OpenAiConnectorStaging::prepare(&paths, "existing").is_err());
        assert_eq!(fs::read(final_path.join("keep"))?, b"keep");
        Ok(())
    }
}
