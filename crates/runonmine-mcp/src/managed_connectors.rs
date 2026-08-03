//! External connector process lifecycle and managed connector artifacts.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::FutureExt as _;
use runonmine_connectors::cloudflare::{
    NamedTunnelConfig, QuickTunnelConfig, parse_quick_tunnel_url,
};
use runonmine_connectors::openai::{OpenAiMcpTarget, OpenAiTunnelProfile};
use runonmine_connectors::{
    BinaryKind, BinaryProbe, ExternalBinaryTrust, ProcessEvent, ProcessState, ProcessSupervisor,
    ReleaseProvider, RestartPolicy, SecretValue, SupervisorHandle, resolve_connector_binary,
    run_once,
};
use runonmine_core::{
    AppConfig, AppPaths, ConnectorConfig, ConnectorKind, QuickTunnelGeneration,
    QuickTunnelRuntimeStore,
};
use secrecy::ExposeSecret;
use serde::Serialize;
use tokio::sync::oneshot;
use url::Url;

use super::required_secret;

const OPENAI_PREPARATION_DEADLINE: Duration = Duration::from_secs(75);
const OPENAI_READINESS_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
struct OpenAiActivationDeadlines {
    preparation: Duration,
    readiness: Duration,
}

impl Default for OpenAiActivationDeadlines {
    fn default() -> Self {
        Self {
            preparation: OPENAI_PREPARATION_DEADLINE,
            readiness: OPENAI_READINESS_DEADLINE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConnectorStartupStage {
    Authentication,
    Preparation,
    Process,
    Readiness,
}

impl ConnectorStartupStage {
    const fn message(self) -> &'static str {
        match self {
            Self::Authentication => "connector authentication could not be prepared",
            Self::Preparation => "connector preparation did not complete",
            Self::Process => "connector process could not be prepared",
            Self::Readiness => "connector did not become ready before its deadline",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct ConnectorStartupFailure {
    pub(super) connector_id: String,
    pub(super) kind: ConnectorKind,
    pub(super) stage: ConnectorStartupStage,
    pub(super) message: String,
}

impl ConnectorStartupFailure {
    pub(super) fn new(
        connector_id: impl Into<String>,
        kind: ConnectorKind,
        stage: ConnectorStartupStage,
    ) -> Self {
        Self {
            connector_id: connector_id.into(),
            kind,
            stage,
            message: stage.message().to_owned(),
        }
    }

    fn log(&self) {
        tracing::error!(
            connector_id = %self.connector_id,
            kind = ?self.kind,
            stage = ?self.stage,
            "connector is degraded; continuing with healthy connectors"
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConnectorRuntimePhase {
    Starting,
    Backoff,
    Ready,
    Degraded,
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct ConnectorRuntimeStatus {
    pub(super) connector_id: String,
    pub(super) kind: ConnectorKind,
    pub(super) phase: ConnectorRuntimePhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) stage: Option<ConnectorStartupStage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) message: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ConnectorRuntimeRegistry {
    inner: Arc<Mutex<BTreeMap<String, ConnectorRuntimeStatus>>>,
}

impl ConnectorRuntimeRegistry {
    pub(super) fn from_failures(failures: &[ConnectorStartupFailure]) -> Self {
        let registry = Self::default();
        for failure in failures {
            registry.set_degraded(failure.clone());
        }
        registry
    }

    pub(super) fn set_starting(
        &self,
        connector_id: &str,
        kind: ConnectorKind,
        stage: ConnectorStartupStage,
    ) {
        self.replace(ConnectorRuntimeStatus {
            connector_id: connector_id.to_owned(),
            kind,
            phase: ConnectorRuntimePhase::Starting,
            stage: Some(stage),
            message: None,
        });
    }

    pub(super) fn set_backoff(
        &self,
        connector_id: &str,
        kind: ConnectorKind,
        stage: ConnectorStartupStage,
    ) {
        self.replace(ConnectorRuntimeStatus {
            connector_id: connector_id.to_owned(),
            kind,
            phase: ConnectorRuntimePhase::Backoff,
            stage: Some(stage),
            message: Some("connector restart is waiting for backoff".to_owned()),
        });
    }

    pub(super) fn set_ready(&self, connector_id: &str, kind: ConnectorKind) {
        self.replace(ConnectorRuntimeStatus {
            connector_id: connector_id.to_owned(),
            kind,
            phase: ConnectorRuntimePhase::Ready,
            stage: None,
            message: None,
        });
    }

    pub(super) fn set_degraded(&self, failure: ConnectorStartupFailure) {
        self.replace(ConnectorRuntimeStatus {
            connector_id: failure.connector_id,
            kind: failure.kind,
            phase: ConnectorRuntimePhase::Degraded,
            stage: Some(failure.stage),
            message: Some(failure.message),
        });
    }

    pub(super) fn set_stopped(&self, connector_id: &str, kind: ConnectorKind) {
        self.replace(ConnectorRuntimeStatus {
            connector_id: connector_id.to_owned(),
            kind,
            phase: ConnectorRuntimePhase::Stopped,
            stage: None,
            message: None,
        });
    }

    pub(super) fn snapshot(&self) -> Vec<ConnectorRuntimeStatus> {
        let guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.values().cloned().collect()
    }

    fn replace(&self, status: ConnectorRuntimeStatus) {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(status.connector_id.clone(), status);
    }
}

#[derive(Debug)]
struct AsyncConnectorTask {
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Debug, Default)]
pub(super) struct ManagedConnectors {
    handles: Vec<SupervisorHandle>,
    observers: Vec<QuickObserverHandle>,
    async_tasks: Vec<AsyncConnectorTask>,
    degraded: Vec<ConnectorStartupFailure>,
    runtime: ConnectorRuntimeRegistry,
}

#[derive(Debug)]
struct PendingQuickObserver {
    events: tokio::sync::broadcast::Receiver<ProcessEvent>,
    store: QuickTunnelRuntimeStore,
    generation: QuickTunnelGeneration,
}

impl ManagedConnectors {
    fn with_degraded(
        degraded: Vec<ConnectorStartupFailure>,
        runtime: ConnectorRuntimeRegistry,
    ) -> Self {
        for failure in &degraded {
            failure.log();
            runtime.set_degraded(failure.clone());
        }
        Self {
            degraded,
            runtime,
            ..Self::default()
        }
    }

    fn blocked_connector_ids(&self) -> HashSet<String> {
        self.degraded
            .iter()
            .map(|failure| failure.connector_id.clone())
            .collect()
    }

    fn record_degraded(
        &mut self,
        connector_id: &str,
        kind: ConnectorKind,
        stage: ConnectorStartupStage,
    ) {
        if self
            .degraded
            .iter()
            .any(|failure| failure.connector_id == connector_id)
        {
            return;
        }
        let failure = ConnectorStartupFailure::new(connector_id, kind, stage);
        failure.log();
        self.runtime.set_degraded(failure.clone());
        self.degraded.push(failure);
    }

    #[cfg(test)]
    pub(super) fn running_count(&self) -> usize {
        self.handles.len()
    }

    #[cfg(test)]
    pub(super) fn degraded_failures(&self) -> &[ConnectorStartupFailure] {
        &self.degraded
    }

    pub(super) fn log_startup_summary(&self) {
        let statuses = self.runtime.snapshot();
        let degraded = statuses
            .iter()
            .filter(|status| status.phase == ConnectorRuntimePhase::Degraded)
            .count();
        let backoff = statuses
            .iter()
            .filter(|status| status.phase == ConnectorRuntimePhase::Backoff)
            .count();
        let starting = statuses
            .iter()
            .filter(|status| status.phase == ConnectorRuntimePhase::Starting)
            .count();
        let ready = statuses
            .iter()
            .filter(|status| status.phase == ConnectorRuntimePhase::Ready)
            .count();
        if degraded == 0 && backoff == 0 && starting == 0 {
            return;
        }
        tracing::warn!(
            degraded,
            backoff,
            starting,
            ready,
            "RunOnMine started while managed connectors were still activating or degraded"
        );
    }

    fn activate_quick_observers(&mut self, pending: Vec<PendingQuickObserver>) {
        self.observers.extend(pending.into_iter().map(|observer| {
            spawn_quick_url_observer(observer.events, observer.store, observer.generation)
        }));
    }

    fn spawn_openai_activation(&mut self, paths: AppPaths, connector: ConnectorConfig) {
        let preparation_connector = connector.clone();
        let preparation =
            async move { prepare_openai_activation(&paths, &preparation_connector).await }.boxed();
        self.spawn_openai_activation_with(
            connector,
            preparation,
            OpenAiActivationDeadlines::default(),
        );
    }

    fn spawn_openai_activation_with(
        &mut self,
        connector: ConnectorConfig,
        preparation: futures::future::BoxFuture<'static, Result<PreparedOpenAiActivation>>,
        deadlines: OpenAiActivationDeadlines,
    ) {
        self.runtime.set_starting(
            &connector.id,
            connector.kind,
            ConnectorStartupStage::Preparation,
        );
        let runtime = self.runtime.clone();
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(run_openai_activation(
            connector,
            runtime,
            shutdown_rx,
            preparation,
            deadlines,
        ));
        self.async_tasks.push(AsyncConnectorTask {
            shutdown: Some(shutdown),
            task,
        });
    }

    pub(super) async fn stop(mut self) {
        for activation in &mut self.async_tasks {
            if let Some(shutdown) = activation.shutdown.take() {
                let _ignored = shutdown.send(());
            }
        }
        for activation in self.async_tasks.drain(..) {
            let _ignored = activation.task.await;
        }
        for observer in self.observers.drain(..) {
            observer.stop().await;
        }
        for handle in self.handles.drain(..) {
            let _ignored = handle.stop().await;
        }
    }
}

pub(super) async fn start_external_connectors(
    paths: &AppPaths,
    config: &AppConfig,
    degraded: Vec<ConnectorStartupFailure>,
    runtime: ConnectorRuntimeRegistry,
) -> Result<ManagedConnectors> {
    let mut managed = ManagedConnectors::with_degraded(degraded, runtime);
    let mut pending_observers = Vec::new();
    if let Err(error) =
        start_external_connectors_inner(paths, config, &mut managed, &mut pending_observers).await
    {
        managed.stop().await;
        return Err(error);
    }
    managed.activate_quick_observers(pending_observers);
    Ok(managed)
}

struct ExternalConnectorStartContext<'a> {
    paths: &'a AppPaths,
    origin: &'a Url,
    supervisor: &'a ProcessSupervisor,
    quick_runtime: &'a QuickTunnelRuntimeStore,
}

async fn start_quick_connector(
    context: &ExternalConnectorStartContext<'_>,
    connector: &ConnectorConfig,
    managed: &mut ManagedConnectors,
    pending_observers: &mut Vec<PendingQuickObserver>,
) -> Result<()> {
    context.quick_runtime.clear_connector(&connector.id)?;
    let settings = connector
        .cloudflare_quick
        .as_ref()
        .context("Cloudflare Quick settings are missing")?;
    let resolved = resolve_connector_binary(
        &context.paths.data_dir,
        &context.paths.state_dir,
        BinaryKind::Cloudflared,
        ReleaseProvider::Cloudflared,
        settings.cloudflared_path.as_deref(),
    )?
    .context("cloudflared is not installed; run the connector setup again")?;
    warn_unpinned_binary(&connector.id, resolved.trust, &resolved.binary.path);
    let binary = resolved.binary;
    BinaryProbe::run_compatible(&binary, Duration::from_secs(10)).await?;
    let tunnel = QuickTunnelConfig::builder(context.origin.clone())
        .metrics_address(format!("127.0.0.1:{}", settings.metrics_port).parse()?)
        .build()?;
    let mut handle = context.supervisor.start(
        tunnel.command(&binary)?,
        tunnel.health_check()?,
        RestartPolicy::default(),
    )?;
    let generation = match context.quick_runtime.begin(&connector.id) {
        Ok(generation) => generation,
        Err(error) => {
            let _ignored = handle.stop().await;
            return Err(error);
        }
    };
    let events = handle
        .take_initial_events()
        .unwrap_or_else(|| handle.subscribe());
    pending_observers.push(PendingQuickObserver {
        events,
        store: context.quick_runtime.clone(),
        generation,
    });
    managed.handles.push(handle);
    Ok(())
}

async fn start_named_connector(
    context: &ExternalConnectorStartContext<'_>,
    connector: &ConnectorConfig,
    managed: &mut ManagedConnectors,
) -> Result<()> {
    let settings = connector
        .cloudflare_named
        .as_ref()
        .context("Cloudflare Named Tunnel settings are missing")?;
    let resolved = resolve_connector_binary(
        &context.paths.data_dir,
        &context.paths.state_dir,
        BinaryKind::Cloudflared,
        ReleaseProvider::Cloudflared,
        settings.cloudflared_path.as_deref(),
    )?
    .context("cloudflared is not installed; run the connector setup again")?;
    warn_unpinned_binary(&connector.id, resolved.trust, &resolved.binary.path);
    let binary = resolved.binary;
    BinaryProbe::run_compatible(&binary, Duration::from_secs(10)).await?;
    let connector_dir = context
        .paths
        .data_dir
        .join("connectors")
        .join(&connector.id);
    ensure_private_directory(&connector_dir)?;
    let tunnel = NamedTunnelConfig::builder(
        &settings.tunnel_id,
        settings.credentials_file.clone(),
        &settings.hostname,
        context.origin.join("mcp")?,
        connector_dir.join("cloudflared.yml"),
    )
    .metrics_address(format!("127.0.0.1:{}", settings.metrics_port).parse()?)
    .build()?;
    tunnel.write_config()?;
    managed.handles.push(context.supervisor.start(
        tunnel.command(&binary)?,
        tunnel.health_check()?,
        RestartPolicy::default(),
    )?);
    Ok(())
}

async fn start_synchronous_connector(
    context: &ExternalConnectorStartContext<'_>,
    connector: &ConnectorConfig,
    managed: &mut ManagedConnectors,
    pending_observers: &mut Vec<PendingQuickObserver>,
) -> Result<()> {
    match connector.kind {
        ConnectorKind::CloudflareQuick => {
            start_quick_connector(context, connector, managed, pending_observers).await
        }
        ConnectorKind::CloudflareOauth => start_named_connector(context, connector, managed).await,
        ConnectorKind::OpenAiTunnel => unreachable!("OpenAI activation is asynchronous"),
        ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => Ok(()),
    }
}

async fn start_external_connectors_inner(
    paths: &AppPaths,
    config: &AppConfig,
    managed: &mut ManagedConnectors,
    pending_observers: &mut Vec<PendingQuickObserver>,
) -> Result<()> {
    let supervisor = ProcessSupervisor;
    let origin = Url::parse(&format!("http://127.0.0.1:{}", config.port))?;
    let quick_runtime = QuickTunnelRuntimeStore::new(paths);
    let context = ExternalConnectorStartContext {
        paths,
        origin: &origin,
        supervisor: &supervisor,
        quick_runtime: &quick_runtime,
    };
    let blocked = managed.blocked_connector_ids();
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.enabled)
        .filter(|connector| !blocked.contains(connector.id.as_str()))
    {
        if connector.kind == ConnectorKind::OpenAiTunnel {
            managed.spawn_openai_activation(paths.clone(), connector.clone());
            continue;
        }
        if matches!(
            connector.kind,
            ConnectorKind::CloudflareQuick | ConnectorKind::CloudflareOauth
        ) {
            managed.runtime.set_starting(
                &connector.id,
                connector.kind,
                ConnectorStartupStage::Process,
            );
        }
        if let Err(error) =
            start_synchronous_connector(&context, connector, managed, pending_observers).await
        {
            tracing::error!(
                connector_id = %connector.id,
                kind = ?connector.kind,
                error = ?error,
                "connector preparation failed"
            );
            managed.record_degraded(
                &connector.id,
                connector.kind,
                ConnectorStartupStage::Process,
            );
        } else if matches!(
            connector.kind,
            ConnectorKind::CloudflareQuick | ConnectorKind::CloudflareOauth
        ) {
            managed.runtime.set_ready(&connector.id, connector.kind);
        }
    }
    Ok(())
}

struct PreparedOpenAiActivation {
    binary: runonmine_connectors::InstalledBinary,
    profile: OpenAiTunnelProfile,
    runtime_key: secrecy::SecretString,
}

async fn run_openai_activation(
    connector: ConnectorConfig,
    runtime: ConnectorRuntimeRegistry,
    mut shutdown: oneshot::Receiver<()>,
    preparation: futures::future::BoxFuture<'static, Result<PreparedOpenAiActivation>>,
    deadlines: OpenAiActivationDeadlines,
) {
    let connector_id = connector.id.clone();
    let kind = connector.kind;
    let preparation = with_deadline(
        deadlines.preparation,
        preparation,
        "OpenAI connector preparation exceeded its deadline",
    );
    tokio::pin!(preparation);
    let prepared = tokio::select! {
        _ = &mut shutdown => {
            runtime.set_stopped(&connector_id, kind);
            return;
        }
        result = &mut preparation => {
            let Ok(prepared) = result else {
                mark_openai_degraded(
                    &runtime,
                    &connector_id,
                    kind,
                    ConnectorStartupStage::Preparation,
                );
                return;
            };
            prepared
        }
    };

    if shutdown_requested(&mut shutdown) {
        runtime.set_stopped(&connector_id, kind);
        return;
    }
    runtime.set_starting(&connector_id, kind, ConnectorStartupStage::Process);
    let Ok((handle, mut events)) = start_openai_supervisor(&prepared) else {
        mark_openai_degraded(
            &runtime,
            &connector_id,
            kind,
            ConnectorStartupStage::Process,
        );
        return;
    };
    runtime.set_starting(&connector_id, kind, ConnectorStartupStage::Readiness);
    let Some(handle) = await_openai_readiness_or_shutdown(
        handle,
        &mut events,
        &mut shutdown,
        &runtime,
        &connector_id,
        kind,
        deadlines.readiness,
    )
    .await
    else {
        return;
    };
    runtime.set_ready(&connector_id, kind);
    tracing::info!(connector_id = %connector_id, "OpenAI connector is ready");
    observe_openai_runtime(handle, events, shutdown, runtime, connector_id, kind).await;
}

fn shutdown_requested(shutdown: &mut oneshot::Receiver<()>) -> bool {
    match shutdown.try_recv() {
        Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => true,
        Err(tokio::sync::oneshot::error::TryRecvError::Empty) => false,
    }
}

fn start_openai_supervisor(
    prepared: &PreparedOpenAiActivation,
) -> Result<(
    SupervisorHandle,
    tokio::sync::broadcast::Receiver<ProcessEvent>,
)> {
    let runtime_key = SecretValue::new(prepared.runtime_key.expose_secret().to_owned())?;
    let command = prepared
        .profile
        .run_command(&prepared.binary, runtime_key)?;
    let readiness = prepared.profile.readiness_check()?;
    let supervisor = ProcessSupervisor;
    let mut handle = supervisor.start(command, readiness, RestartPolicy::default())?;
    let events = handle
        .take_initial_events()
        .unwrap_or_else(|| handle.subscribe());
    Ok((handle, events))
}

async fn await_openai_readiness_or_shutdown(
    handle: SupervisorHandle,
    events: &mut tokio::sync::broadcast::Receiver<ProcessEvent>,
    shutdown: &mut oneshot::Receiver<()>,
    runtime: &ConnectorRuntimeRegistry,
    connector_id: &str,
    kind: ConnectorKind,
    readiness_deadline: Duration,
) -> Option<SupervisorHandle> {
    let readiness = wait_for_openai_readiness(events, readiness_deadline);
    tokio::pin!(readiness);
    tokio::select! {
        _ = &mut *shutdown => {
            let _ignored = handle.stop().await;
            runtime.set_stopped(connector_id, kind);
            None
        }
        result = &mut readiness => {
            if result.is_err() {
                let _ignored = handle.stop().await;
                mark_openai_degraded(
                    runtime,
                    connector_id,
                    kind,
                    ConnectorStartupStage::Readiness,
                );
                return None;
            }
            Some(handle)
        }
    }
}

async fn observe_openai_runtime(
    handle: SupervisorHandle,
    mut events: tokio::sync::broadcast::Receiver<ProcessEvent>,
    mut shutdown: oneshot::Receiver<()>,
    runtime: ConnectorRuntimeRegistry,
    connector_id: String,
    kind: ConnectorKind,
) {
    let mut handle = Some(handle);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                stop_supervisor(&mut handle).await;
                runtime.set_stopped(&connector_id, kind);
                return;
            }
            event = events.recv() => {
                if apply_openai_runtime_event(&runtime, &connector_id, kind, &event) {
                    stop_supervisor(&mut handle).await;
                    return;
                }
            }
        }
    }
}

async fn stop_supervisor(handle: &mut Option<SupervisorHandle>) {
    if let Some(handle) = handle.take() {
        let _ignored = handle.stop().await;
    }
}

fn apply_openai_runtime_event(
    runtime: &ConnectorRuntimeRegistry,
    connector_id: &str,
    kind: ConnectorKind,
    event: &Result<ProcessEvent, tokio::sync::broadcast::error::RecvError>,
) -> bool {
    match event {
        Ok(ProcessEvent::HealthChanged { healthy: true, .. }) => {
            runtime.set_ready(connector_id, kind);
        }
        Ok(
            ProcessEvent::HealthChanged { healthy: false, .. }
            | ProcessEvent::StateChanged {
                state: ProcessState::Starting { .. },
            },
        ) => {
            runtime.set_starting(connector_id, kind, ConnectorStartupStage::Readiness);
        }
        Ok(
            ProcessEvent::RestartScheduled { .. }
            | ProcessEvent::StateChanged {
                state: ProcessState::Backoff { .. },
            },
        ) => {
            runtime.set_backoff(connector_id, kind, ConnectorStartupStage::Readiness);
        }
        Ok(ProcessEvent::StateChanged {
            state:
                ProcessState::Stopped {
                    cleanup: runonmine_connectors::CleanupState::NotRequired,
                },
        }) => {
            runtime.set_stopped(connector_id, kind);
            return true;
        }
        Ok(ProcessEvent::StateChanged {
            state: ProcessState::Failed { .. },
        })
        | Err(tokio::sync::broadcast::error::RecvError::Closed) => {
            mark_openai_degraded(runtime, connector_id, kind, ConnectorStartupStage::Process);
            return true;
        }
        Ok(
            ProcessEvent::StateChanged { .. }
            | ProcessEvent::StandardOutput { .. }
            | ProcessEvent::StandardError { .. },
        ) => {}
        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
            tracing::warn!(connector_id = %connector_id, skipped, "OpenAI connector state observer lagged");
        }
    }
    false
}

fn warn_unpinned_binary(connector_id: &str, trust: ExternalBinaryTrust, path: &std::path::Path) {
    if trust == ExternalBinaryTrust::ExternalUnpinned {
        tracing::warn!(
            connector_id,
            binary_path = %path.display(),
            "connector is using an unpinned external binary"
        );
    }
}

fn mark_openai_degraded(
    runtime: &ConnectorRuntimeRegistry,
    connector_id: &str,
    kind: ConnectorKind,
    stage: ConnectorStartupStage,
) {
    tracing::warn!(connector_id = %connector_id, ?kind, ?stage, "OpenAI connector activation degraded");
    let failure = ConnectorStartupFailure::new(connector_id, kind, stage);
    failure.log();
    runtime.set_degraded(failure);
}

async fn prepare_openai_activation(
    paths: &AppPaths,
    connector: &ConnectorConfig,
) -> Result<PreparedOpenAiActivation> {
    let settings = connector
        .openai_tunnel
        .as_ref()
        .context("OpenAI tunnel settings are missing")?;
    let resolved = resolve_connector_binary(
        &paths.data_dir,
        &paths.state_dir,
        BinaryKind::OpenAiTunnelClient,
        ReleaseProvider::OpenAiTunnelClient,
        settings.tunnel_client_path.as_deref(),
    )?
    .context("tunnel-client is not installed; run the connector setup again")?;
    warn_unpinned_binary(&connector.id, resolved.trust, &resolved.binary.path);
    let binary = resolved.binary;
    BinaryProbe::run_compatible(&binary, Duration::from_secs(10)).await?;
    let connector_dir = paths.data_dir.join("connectors").join(&connector.id);
    let profile_directory = connector_dir.join("openai-profiles");
    let health_directory = paths.state_dir.join("connectors").join(&connector.id);
    ensure_private_directory(&profile_directory)?;
    ensure_private_directory(&health_directory)?;
    let target = OpenAiMcpTarget::runonmine_stdio(runonmine_cli_executable()?, &connector.id)?;
    let profile = OpenAiTunnelProfile::builder(&settings.profile, &settings.tunnel_id, target)
        .profile_directory(profile_directory.clone())
        .health_address(format!("127.0.0.1:{}", settings.health_port).parse()?)
        .health_url_file(health_directory.join("tunnel-health.url"))
        .build()?;
    let profile_file = profile_directory.join(format!("{}.yaml", profile.profile()));
    if !profile_file.exists() {
        let initialized = run_once(
            profile.init_command(&binary)?,
            Duration::from_secs(30),
            128 * 1_024,
        )
        .await?;
        if !initialized.success {
            bail!("tunnel-client profile initialization failed");
        }
        restrict_private_file(&profile_file)?;
    }
    let secrets = runonmine_core::secrets::default_secret_store(paths)?;
    let runtime_key = required_secret(
        secrets.as_ref(),
        &format!("connector.{}.runtime_api_key", connector.id),
    )?;
    let doctor = run_once(
        profile.doctor_command(
            &binary,
            SecretValue::new(runtime_key.expose_secret().to_owned())?,
        )?,
        Duration::from_secs(30),
        256 * 1_024,
    )
    .await?;
    if !doctor.success {
        bail!("tunnel-client doctor failed; run `runonmine doctor` for guidance");
    }
    Ok(PreparedOpenAiActivation {
        binary,
        profile,
        runtime_key,
    })
}

async fn with_deadline<T>(
    deadline: Duration,
    future: impl std::future::Future<Output = Result<T>>,
    message: &'static str,
) -> Result<T> {
    match tokio::time::timeout(deadline, future).await {
        Ok(result) => result,
        Err(_) => bail!(message),
    }
}

async fn wait_for_openai_readiness(
    events: &mut tokio::sync::broadcast::Receiver<ProcessEvent>,
    deadline: Duration,
) -> Result<()> {
    with_deadline(
        deadline,
        async {
            loop {
                match events.recv().await {
                    Ok(ProcessEvent::HealthChanged { healthy: true, .. }) => return Ok(()),
                    Ok(ProcessEvent::StateChanged {
                        state: ProcessState::Failed { .. } | ProcessState::Stopped { .. },
                    }) => bail!("OpenAI connector supervisor stopped before readiness"),
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        bail!("OpenAI connector supervisor closed before readiness")
                    }
                }
            }
        },
        "OpenAI connector readiness exceeded its deadline",
    )
    .await
}

fn spawn_quick_url_observer(
    mut events: tokio::sync::broadcast::Receiver<ProcessEvent>,
    store: QuickTunnelRuntimeStore,
    generation: QuickTunnelGeneration,
) -> QuickObserverHandle {
    let handle_store = store.clone();
    let handle_generation = generation.clone();
    let task = tokio::spawn(async move {
        let cleanup = QuickRuntimeCleanup {
            store: store.clone(),
            generation: generation.clone(),
        };
        loop {
            match events.recv().await {
                Ok(
                    ProcessEvent::StandardOutput { line } | ProcessEvent::StandardError { line },
                ) => {
                    if let Some(url) = parse_quick_tunnel_url(&line)
                        && store.set_url(&generation, &url).is_err()
                    {
                        tracing::warn!(
                            connector_id = generation.connector_id(),
                            "failed to persist Quick Tunnel runtime URL"
                        );
                    }
                }
                Ok(
                    ProcessEvent::HealthChanged { healthy: false, .. }
                    | ProcessEvent::RestartScheduled { .. }
                    | ProcessEvent::StateChanged {
                        state: ProcessState::Starting { .. } | ProcessState::Backoff { .. },
                    },
                ) => {
                    let _ignored = store.clear_url(&generation);
                }
                Ok(ProcessEvent::StateChanged {
                    state: ProcessState::Failed { .. } | ProcessState::Stopped { .. },
                })
                | Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Ok(ProcessEvent::HealthChanged { .. } | ProcessEvent::StateChanged { .. }) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        connector_id = generation.connector_id(),
                        skipped,
                        "Quick Tunnel runtime observer lagged"
                    );
                    let _ignored = store.clear_url(&generation);
                }
            }
        }
        drop(cleanup);
    });
    QuickObserverHandle {
        task: Some(task),
        store: handle_store,
        generation: handle_generation,
    }
}

#[derive(Debug)]
struct QuickObserverHandle {
    task: Option<tokio::task::JoinHandle<()>>,
    store: QuickTunnelRuntimeStore,
    generation: QuickTunnelGeneration,
}

impl QuickObserverHandle {
    async fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ignored = task.await;
        }
        let _ignored = self.store.finish(&self.generation);
    }
}

impl Drop for QuickObserverHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ignored = self.store.finish(&self.generation);
    }
}

#[derive(Debug)]
struct QuickRuntimeCleanup {
    store: QuickTunnelRuntimeStore,
    generation: QuickTunnelGeneration,
}

impl Drop for QuickRuntimeCleanup {
    fn drop(&mut self) {
        let _ignored = self.store.finish(&self.generation);
    }
}

fn ensure_private_directory(path: &std::path::Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked connector directory");
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_private_file(path: &std::path::Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).context("connector profile was not created")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("connector profile must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn runonmine_cli_executable() -> Result<PathBuf> {
    let current = std::env::current_exe()?.canonicalize()?;
    let expected = if current
        .file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name == "runonmine")
    {
        current
    } else {
        let filename = if cfg!(windows) {
            "runonmine.exe"
        } else {
            "runonmine"
        };
        current
            .parent()
            .context("agent executable has no parent directory")?
            .join(filename)
    };
    if !expected.is_file() {
        bail!("runonmine CLI is not installed next to the agent executable");
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use runonmine_core::{
        CloudflareQuickSettings, ConnectorConfig, OpenAiTunnelSettings, PolicyPreset,
    };

    #[cfg(unix)]
    #[tokio::test]
    async fn healthy_remote_supervisor_survives_later_connector_failure() -> Result<()> {
        use runonmine_connectors::ProcessState;
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let cloudflared = temporary.path().join("cloudflared");
        std::fs::write(
            &cloudflared,
            br#"#!/bin/sh
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' 'cloudflared version 2026.7.2'
  exit 0
fi
printf '%s\n' 'https://healthy.trycloudflare.com'
trap 'exit 0' TERM INT
while :; do /bin/sleep 1; done
"#,
        )?;
        std::fs::set_permissions(&cloudflared, std::fs::Permissions::from_mode(0o700))?;

        let mut quick = ConnectorConfig::local_default();
        quick.id = "healthy-quick".to_owned();
        quick.name = "Healthy Quick".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.enabled = true;
        quick.cloudflare_quick = Some(CloudflareQuickSettings {
            cloudflared_path: Some(cloudflared),
            ..CloudflareQuickSettings::default()
        });

        let openai = ConnectorConfig {
            id: "broken-openai".to_owned(),
            name: "Broken OpenAI".to_owned(),
            kind: ConnectorKind::OpenAiTunnel,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: std::collections::BTreeMap::default(),
            tool_overrides: std::collections::BTreeMap::default(),
            policy_rules: Vec::new(),
            public_base_url: None,
            cloudflare_quick: None,
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: Some(OpenAiTunnelSettings {
                tunnel_id: "tunnel_0123456789abcdef0123456789abcdef".to_owned(),
                profile: "runonmine".to_owned(),
                tunnel_client_path: Some(temporary.path().join("missing-tunnel-client")),
                health_port: 47_823,
            }),
        };
        let mut config = AppConfig::default();
        config.connectors.push(quick);
        config.connectors.push(openai);
        config.validate()?;
        config.save(&paths.config_file())?;

        let runtime = ConnectorRuntimeRegistry::default();
        let managed =
            start_external_connectors(&paths, &config, Vec::new(), runtime.clone()).await?;
        wait_for_runtime_phase(&runtime, "broken-openai", ConnectorRuntimePhase::Degraded).await?;
        assert_eq!(managed.handles.len(), 1);
        assert!(managed.degraded.is_empty());
        assert!(matches!(
            managed.handles[0].state(),
            ProcessState::Starting { .. } | ProcessState::Running { .. }
        ));
        managed.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn connector_startup_failures_are_degraded_without_aborting_local_agent() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;

        let mut local = ConnectorConfig::local_http_default();
        local.enabled = true;

        let mut quick = ConnectorConfig::local_default();
        quick.id = "broken-quick".to_owned();
        quick.name = "Broken Quick".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.enabled = true;
        quick.cloudflare_quick = Some(CloudflareQuickSettings {
            cloudflared_path: Some(temporary.path().join("missing-cloudflared")),
            ..CloudflareQuickSettings::default()
        });

        let openai = ConnectorConfig {
            id: "broken-openai".to_owned(),
            name: "Broken OpenAI".to_owned(),
            kind: ConnectorKind::OpenAiTunnel,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: std::collections::BTreeMap::default(),
            tool_overrides: std::collections::BTreeMap::default(),
            policy_rules: Vec::new(),
            public_base_url: None,
            cloudflare_quick: None,
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: Some(OpenAiTunnelSettings {
                tunnel_id: "tunnel_0123456789abcdef0123456789abcdef".to_owned(),
                profile: "runonmine".to_owned(),
                tunnel_client_path: Some(temporary.path().join("missing-tunnel-client")),
                health_port: 47_823,
            }),
        };
        let config = AppConfig {
            connectors: vec![local, quick, openai],
            ..AppConfig::default()
        };
        config.validate()?;

        let runtime = ConnectorRuntimeRegistry::default();
        let managed = tokio::time::timeout(
            Duration::from_millis(250),
            start_external_connectors(&paths, &config, Vec::new(), runtime.clone()),
        )
        .await
        .context("managed connector startup blocked on OpenAI preparation")??;
        assert!(managed.handles.is_empty());
        assert_eq!(managed.degraded.len(), 1);
        assert_eq!(managed.degraded[0].connector_id, "broken-quick");
        wait_for_runtime_phase(&runtime, "broken-openai", ConnectorRuntimePhase::Degraded).await?;
        let statuses = runtime.snapshot();
        assert_eq!(
            statuses
                .iter()
                .filter(|status| status.phase == ConnectorRuntimePhase::Degraded)
                .count(),
            2
        );
        assert!(statuses.iter().any(|status| {
            status.connector_id == "broken-openai"
                && status.kind == ConnectorKind::OpenAiTunnel
                && status.stage == Some(ConnectorStartupStage::Preparation)
        }));
        managed.stop().await;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn incompatible_external_binary_degrades_only_its_connector() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let cloudflared = temporary.path().join("old-cloudflared");
        std::fs::write(
            &cloudflared,
            br#"#!/bin/sh
if [ "${1:-}" = "--version" ]; then printf '%s\n' 'cloudflared version 2024.12.1'; exit 0; fi
exit 0
"#,
        )?;
        std::fs::set_permissions(&cloudflared, std::fs::Permissions::from_mode(0o700))?;

        let mut local = ConnectorConfig::local_http_default();
        local.enabled = true;
        let mut quick = ConnectorConfig::local_default();
        quick.id = "incompatible-quick".to_owned();
        quick.name = "Incompatible Quick".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.enabled = true;
        quick.cloudflare_quick = Some(CloudflareQuickSettings {
            cloudflared_path: Some(cloudflared),
            ..CloudflareQuickSettings::default()
        });
        let config = AppConfig {
            connectors: vec![local, quick],
            ..AppConfig::default()
        };
        config.validate()?;

        let runtime = ConnectorRuntimeRegistry::default();
        let managed =
            start_external_connectors(&paths, &config, Vec::new(), runtime.clone()).await?;
        assert!(managed.handles.is_empty());
        assert_eq!(managed.degraded.len(), 1);
        assert_eq!(managed.degraded[0].connector_id, "incompatible-quick");
        assert_runtime_phase(
            &runtime,
            "incompatible-quick",
            ConnectorRuntimePhase::Degraded,
        )?;
        managed.stop().await;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn changed_pinned_external_binary_degrades_only_its_connector() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let cloudflared = temporary.path().join("external-cloudflared");
        std::fs::write(
            &cloudflared,
            b"#!/bin/sh
printf '%s\n' 'https://pinned.trycloudflare.com'
",
        )?;
        std::fs::set_permissions(&cloudflared, std::fs::Permissions::from_mode(0o700))?;
        runonmine_connectors::external_binary_pin_store(&paths.state_dir)
            .pin(BinaryKind::Cloudflared, &cloudflared)?;
        std::fs::write(
            &cloudflared,
            b"#!/bin/sh
exit 1
",
        )?;
        std::fs::set_permissions(&cloudflared, std::fs::Permissions::from_mode(0o700))?;

        let mut local = ConnectorConfig::local_http_default();
        local.enabled = true;
        let mut quick = ConnectorConfig::local_default();
        quick.id = "changed-pinned-quick".to_owned();
        quick.name = "Changed pinned Quick".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.enabled = true;
        quick.cloudflare_quick = Some(CloudflareQuickSettings {
            cloudflared_path: Some(cloudflared),
            ..CloudflareQuickSettings::default()
        });
        let config = AppConfig {
            connectors: vec![local, quick],
            ..AppConfig::default()
        };
        config.validate()?;

        let runtime = ConnectorRuntimeRegistry::default();
        let managed =
            start_external_connectors(&paths, &config, Vec::new(), runtime.clone()).await?;
        assert!(managed.handles.is_empty());
        assert_eq!(managed.degraded.len(), 1);
        assert_eq!(managed.degraded[0].connector_id, "changed-pinned-quick");
        assert_runtime_phase(
            &runtime,
            "changed-pinned-quick",
            ConnectorRuntimePhase::Degraded,
        )?;
        managed.stop().await;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn corrupt_quick_runtime_state_is_scoped_to_that_connector() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;

        let mut local = ConnectorConfig::local_http_default();
        local.enabled = true;
        let mut quick = ConnectorConfig::local_default();
        quick.id = "corrupt-runtime-quick".to_owned();
        quick.name = "Corrupt runtime Quick".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.enabled = true;
        quick.cloudflare_quick = Some(CloudflareQuickSettings::default());
        let config = AppConfig {
            connectors: vec![local, quick],
            ..AppConfig::default()
        };
        config.validate()?;

        let store = QuickTunnelRuntimeStore::new(&paths);
        let _generation = store.begin("corrupt-runtime-quick")?;
        let runtime_directory = paths.state_dir.join("quick-tunnel-runtime");
        let record_path = std::fs::read_dir(&runtime_directory)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .context("Quick runtime test record is missing")?;
        std::fs::remove_file(&record_path)?;
        let outside = temporary.path().join("outside-runtime-state");
        std::fs::write(&outside, b"outside")?;
        symlink(&outside, &record_path)?;

        let runtime = ConnectorRuntimeRegistry::default();
        let managed =
            start_external_connectors(&paths, &config, Vec::new(), runtime.clone()).await?;
        assert!(managed.handles.is_empty());
        assert_eq!(managed.degraded.len(), 1);
        assert_eq!(managed.degraded[0].connector_id, "corrupt-runtime-quick");
        assert_runtime_phase(
            &runtime,
            "corrupt-runtime-quick",
            ConnectorRuntimePhase::Degraded,
        )?;
        assert_eq!(std::fs::read(&outside)?, b"outside");
        managed.stop().await;
        Ok(())
    }

    async fn wait_for_runtime_phase(
        runtime: &ConnectorRuntimeRegistry,
        connector_id: &str,
        phase: ConnectorRuntimePhase,
    ) -> Result<()> {
        with_deadline(
            Duration::from_secs(2),
            async {
                loop {
                    if runtime
                        .snapshot()
                        .iter()
                        .any(|status| status.connector_id == connector_id && status.phase == phase)
                    {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            },
            "connector runtime state did not reach the expected phase",
        )
        .await
    }

    #[test]
    fn openai_runtime_events_cover_ready_backoff_recovery_and_stop() -> Result<()> {
        let runtime = ConnectorRuntimeRegistry::default();
        let connector_id = "runtime-openai";
        let kind = ConnectorKind::OpenAiTunnel;
        runtime.set_starting(connector_id, kind, ConnectorStartupStage::Readiness);

        assert!(!apply_openai_runtime_event(
            &runtime,
            connector_id,
            kind,
            &Ok(ProcessEvent::HealthChanged {
                healthy: true,
                detail: "ready".to_owned(),
            }),
        ));
        assert_runtime_phase(&runtime, connector_id, ConnectorRuntimePhase::Ready)?;

        assert!(!apply_openai_runtime_event(
            &runtime,
            connector_id,
            kind,
            &Ok(ProcessEvent::RestartScheduled {
                attempt: 2,
                delay_ms: 1_000,
            }),
        ));
        assert_runtime_phase(&runtime, connector_id, ConnectorRuntimePhase::Backoff)?;

        assert!(!apply_openai_runtime_event(
            &runtime,
            connector_id,
            kind,
            &Ok(ProcessEvent::HealthChanged {
                healthy: true,
                detail: "recovered".to_owned(),
            }),
        ));
        assert_runtime_phase(&runtime, connector_id, ConnectorRuntimePhase::Ready)?;

        assert!(apply_openai_runtime_event(
            &runtime,
            connector_id,
            kind,
            &Ok(ProcessEvent::StateChanged {
                state: ProcessState::Stopped {
                    cleanup: runonmine_connectors::CleanupState::NotRequired
                },
            }),
        ));
        assert_runtime_phase(&runtime, connector_id, ConnectorRuntimePhase::Stopped)?;
        Ok(())
    }

    fn assert_runtime_phase(
        runtime: &ConnectorRuntimeRegistry,
        connector_id: &str,
        expected: ConnectorRuntimePhase,
    ) -> Result<()> {
        let status = runtime
            .snapshot()
            .into_iter()
            .find(|status| status.connector_id == connector_id)
            .context("connector runtime status is missing")?;
        assert_eq!(status.phase, expected);
        Ok(())
    }

    #[tokio::test]
    async fn async_activation_returns_immediately_and_shutdown_cancels_preparation() -> Result<()> {
        #[derive(Debug)]
        struct CancellationFlag(Arc<AtomicBool>);

        impl Drop for CancellationFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let connector = test_openai_connector("slow-openai");
        let runtime = ConnectorRuntimeRegistry::default();
        let mut managed = ManagedConnectors::with_degraded(Vec::new(), runtime.clone());
        let started = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));
        let started_for_future = Arc::clone(&started);
        let cancelled_for_future = Arc::clone(&cancelled);
        let preparation = async move {
            started_for_future.store(true, Ordering::Release);
            let _flag = CancellationFlag(cancelled_for_future);
            std::future::pending::<Result<PreparedOpenAiActivation>>().await
        }
        .boxed();
        let launched = std::time::Instant::now();
        managed.spawn_openai_activation_with(
            connector,
            preparation,
            OpenAiActivationDeadlines {
                preparation: Duration::from_secs(30),
                readiness: Duration::from_secs(30),
            },
        );
        assert!(launched.elapsed() < Duration::from_millis(50));
        with_deadline(
            Duration::from_secs(1),
            async {
                while !started.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
                Ok(())
            },
            "OpenAI preparation future was never polled",
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(1), managed.stop())
            .await
            .context("managed connector shutdown waited for OpenAI preparation")?;
        assert!(cancelled.load(Ordering::Acquire));
        assert!(runtime.snapshot().iter().any(|status| {
            status.connector_id == "slow-openai" && status.phase == ConnectorRuntimePhase::Stopped
        }));
        Ok(())
    }

    #[tokio::test]
    async fn preparation_deadline_marks_async_connector_degraded() -> Result<()> {
        let connector = test_openai_connector("deadline-openai");
        let runtime = ConnectorRuntimeRegistry::default();
        let mut managed = ManagedConnectors::with_degraded(Vec::new(), runtime.clone());
        managed.spawn_openai_activation_with(
            connector,
            std::future::pending::<Result<PreparedOpenAiActivation>>().boxed(),
            OpenAiActivationDeadlines {
                preparation: Duration::from_millis(20),
                readiness: Duration::from_secs(1),
            },
        );
        wait_for_runtime_phase(&runtime, "deadline-openai", ConnectorRuntimePhase::Degraded)
            .await?;
        let status = runtime
            .snapshot()
            .into_iter()
            .find(|status| status.connector_id == "deadline-openai")
            .context("deadline connector status is missing")?;
        assert_eq!(status.stage, Some(ConnectorStartupStage::Preparation));
        assert_eq!(
            status.message.as_deref(),
            Some("connector preparation did not complete")
        );
        managed.stop().await;
        Ok(())
    }

    fn test_openai_connector(id: &str) -> ConnectorConfig {
        ConnectorConfig {
            id: id.to_owned(),
            name: "OpenAI activation test".to_owned(),
            kind: ConnectorKind::OpenAiTunnel,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: std::collections::BTreeMap::default(),
            tool_overrides: std::collections::BTreeMap::default(),
            policy_rules: Vec::new(),
            public_base_url: None,
            cloudflare_quick: None,
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: Some(OpenAiTunnelSettings {
                tunnel_id: "tunnel_0123456789abcdef0123456789abcdef".to_owned(),
                profile: "runonmine".to_owned(),
                tunnel_client_path: None,
                health_port: 47_823,
            }),
        }
    }

    #[tokio::test]
    async fn connector_deadline_cancels_a_pending_activation() {
        let result = with_deadline(
            Duration::from_millis(20),
            std::future::pending::<Result<()>>(),
            "deadline reached",
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn readiness_requires_a_healthy_event_before_deadline() -> Result<()> {
        let (events, mut receiver) = tokio::sync::broadcast::channel(8);
        events.send(ProcessEvent::HealthChanged {
            healthy: false,
            detail: "starting".to_owned(),
        })?;
        events.send(ProcessEvent::HealthChanged {
            healthy: true,
            detail: "ready".to_owned(),
        })?;
        wait_for_openai_readiness(&mut receiver, Duration::from_secs(1)).await?;

        let (_events, mut receiver) = tokio::sync::broadcast::channel(1);
        assert!(
            wait_for_openai_readiness(&mut receiver, Duration::from_millis(20))
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn quick_url_observer_uses_ephemeral_generation_state_only() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let mut quick = ConnectorConfig::local_default();
        quick.id = "quick-connector".to_owned();
        quick.name = "Quick connector".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.cloudflare_quick = Some(CloudflareQuickSettings::default());
        let config = AppConfig {
            connectors: vec![quick],
            ..AppConfig::default()
        };
        config.save(&paths.config_file())?;
        let durable_before = std::fs::read(paths.config_file())?;

        let store = QuickTunnelRuntimeStore::new(&paths);
        let generation = store.begin("quick-connector")?;
        let (sender, _) = tokio::sync::broadcast::channel(16);
        let pending = vec![PendingQuickObserver {
            events: sender.subscribe(),
            store: store.clone(),
            generation: generation.clone(),
        }];
        let mut managed = ManagedConnectors::default();
        managed.activate_quick_observers(pending);

        let first = Url::parse("https://first-observer.trycloudflare.com/")?;
        sender.send(ProcessEvent::StandardError {
            line: first.to_string(),
        })?;
        wait_for_quick_url(&store, "quick-connector", Some(&first)).await?;
        assert_eq!(std::fs::read(paths.config_file())?, durable_before);

        sender.send(ProcessEvent::RestartScheduled {
            attempt: 1,
            delay_ms: 50,
        })?;
        wait_for_quick_url(&store, "quick-connector", None).await?;

        let second = Url::parse("https://second-observer.trycloudflare.com/")?;
        sender.send(ProcessEvent::StandardOutput {
            line: second.to_string(),
        })?;
        wait_for_quick_url(&store, "quick-connector", Some(&second)).await?;
        assert_eq!(std::fs::read(paths.config_file())?, durable_before);

        sender.send(ProcessEvent::StateChanged {
            state: ProcessState::Stopped {
                cleanup: runonmine_connectors::CleanupState::NotRequired,
            },
        })?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if store.get("quick-connector")?.is_none() {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("Quick runtime record was not removed after process stop")??;
        assert!(!store.set_url(&generation, &second)?);
        managed.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn aborting_quick_observer_removes_generation_state() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let store = QuickTunnelRuntimeStore::new(&paths);
        let generation = store.begin("aborted-quick")?;
        let (_sender, receiver) = tokio::sync::broadcast::channel(4);
        let mut managed = ManagedConnectors::default();
        managed.activate_quick_observers(vec![PendingQuickObserver {
            events: receiver,
            store: store.clone(),
            generation,
        }]);
        managed.stop().await;
        assert!(store.get("aborted-quick")?.is_none());
        Ok(())
    }

    async fn wait_for_quick_url(
        store: &QuickTunnelRuntimeStore,
        connector_id: &str,
        expected: Option<&Url>,
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let current = store
                    .get(connector_id)?
                    .and_then(|record| record.public_url);
                if current.as_ref() == expected {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("Quick runtime URL did not reach the expected state")??;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn connector_artifacts_are_private_and_symlinks_are_rejected() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temporary = tempfile::tempdir()?;
        let private_dir = temporary.path().join("private");
        ensure_private_directory(&private_dir)?;
        assert_eq!(
            std::fs::metadata(&private_dir)?.permissions().mode() & 0o777,
            0o700
        );

        let profile = private_dir.join("profile.yml");
        std::fs::write(&profile, b"profile")?;
        restrict_private_file(&profile)?;
        assert_eq!(
            std::fs::metadata(&profile)?.permissions().mode() & 0o777,
            0o600
        );

        let directory_target = temporary.path().join("directory-target");
        std::fs::create_dir(&directory_target)?;
        let directory_link = temporary.path().join("directory-link");
        symlink(&directory_target, &directory_link)?;
        assert!(ensure_private_directory(&directory_link).is_err());

        let file_target = temporary.path().join("file-target");
        std::fs::write(&file_target, b"target")?;
        let file_link = temporary.path().join("file-link");
        symlink(&file_target, &file_link)?;
        assert!(restrict_private_file(&file_link).is_err());
        Ok(())
    }
}
