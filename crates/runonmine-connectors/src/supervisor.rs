use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::{broadcast, watch};

use crate::health::{HealthCheck, HealthChecker};
use crate::process::{CommandSpec, Redactor};

const LOG_READ_BYTES: usize = 4 * 1024;
const MAX_LOG_EVENT_BYTES: usize = 16 * 1024;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const STABLE_RUNTIME: Duration = Duration::from_mins(1);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProcessState {
    Starting { attempt: u32 },
    Running { pid: Option<u32>, attempt: u32 },
    Backoff { attempt: u32, delay_ms: u64 },
    Stopped,
    Failed { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ProcessEvent {
    StateChanged { state: ProcessState },
    StandardOutput { line: String },
    StandardError { line: String },
    HealthChanged { healthy: bool, detail: String },
    RestartScheduled { attempt: u32, delay_ms: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestartPolicy {
    pub restart_on_clean_exit: bool,
    pub max_restarts: Option<u32>,
    pub initial_backoff: Duration,
    pub maximum_backoff: Duration,
    pub backoff_multiplier: u32,
    pub startup_grace: Duration,
    pub health_interval: Duration,
    pub unhealthy_threshold: u32,
    pub shutdown_timeout: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            restart_on_clean_exit: true,
            max_restarts: None,
            initial_backoff: Duration::from_secs(1),
            maximum_backoff: Duration::from_mins(1),
            backoff_multiplier: 2,
            startup_grace: Duration::from_secs(3),
            health_interval: Duration::from_secs(5),
            unhealthy_threshold: 3,
            shutdown_timeout: Duration::from_secs(10),
        }
    }
}

impl RestartPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.initial_backoff.is_zero()
            || self.maximum_backoff < self.initial_backoff
            || self.backoff_multiplier < 1
            || self.health_interval.is_zero()
            || self.unhealthy_threshold < 1
            || self.shutdown_timeout.is_zero()
        {
            bail!("invalid connector restart policy");
        }
        Ok(())
    }

    fn delay_for_restart(&self, restart: u32) -> Duration {
        let exponent = restart.saturating_sub(1).min(31);
        let factor = self.backoff_multiplier.saturating_pow(exponent);
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.maximum_backoff)
    }

    fn permits_restart(&self, restarts: u32) -> bool {
        self.max_restarts.is_none_or(|maximum| restarts <= maximum)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcessSupervisor;

impl ProcessSupervisor {
    pub fn start(
        &self,
        command: CommandSpec,
        health: HealthCheck,
        policy: RestartPolicy,
    ) -> Result<SupervisorHandle> {
        policy.validate()?;
        let runtime = tokio::runtime::Handle::try_current()
            .context("connector supervisor requires an active Tokio runtime")?;
        let checker = HealthChecker::new()?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let (state_tx, state_rx) = watch::channel(ProcessState::Starting { attempt: 1 });
        let (event_tx, _) = broadcast::channel(256);
        let initial_events = event_tx.subscribe();
        let task_events = event_tx.clone();
        let task = runtime.spawn(async move {
            run_supervisor(
                command,
                health,
                policy,
                checker,
                stop_rx,
                state_tx,
                task_events,
            )
            .await;
        });
        Ok(SupervisorHandle {
            stop: stop_tx,
            state: state_rx,
            events: event_tx,
            initial_events: Some(initial_events),
            task: Some(task),
        })
    }
}

pub struct SupervisorHandle {
    stop: watch::Sender<bool>,
    state: watch::Receiver<ProcessState>,
    events: broadcast::Sender<ProcessEvent>,
    initial_events: Option<broadcast::Receiver<ProcessEvent>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl fmt::Debug for SupervisorHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisorHandle")
            .field("state", &self.state.borrow().clone())
            .finish_non_exhaustive()
    }
}

impl SupervisorHandle {
    pub fn state(&self) -> ProcessState {
        self.state.borrow().clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ProcessEvent> {
        self.events.subscribe()
    }

    pub fn take_initial_events(&mut self) -> Option<broadcast::Receiver<ProcessEvent>> {
        self.initial_events.take()
    }

    pub async fn stop(mut self) -> Result<ProcessState> {
        self.stop
            .send(true)
            .context("connector supervisor has already stopped")?;
        let final_state = loop {
            let state = self.state.borrow().clone();
            if matches!(state, ProcessState::Stopped | ProcessState::Failed { .. }) {
                break state;
            }
            if self.state.changed().await.is_err() {
                break self.state.borrow().clone();
            }
        };
        if let Some(task) = self.task.take() {
            task.await.context("connector supervisor task failed")?;
        }
        Ok(final_state)
    }
}

impl Drop for SupervisorHandle {
    fn drop(&mut self) {
        let _ignored = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

enum ChildOutcome {
    Stopped,
    Exited {
        success: bool,
        detail: String,
        stable: bool,
    },
    Unhealthy {
        stable: bool,
    },
}

async fn run_supervisor(
    command: CommandSpec,
    health: HealthCheck,
    policy: RestartPolicy,
    checker: HealthChecker,
    mut stop: watch::Receiver<bool>,
    state: watch::Sender<ProcessState>,
    events: broadcast::Sender<ProcessEvent>,
) {
    let redactor = Arc::new(command.redactor());
    let mut attempt = 1_u32;
    let mut restarts = 0_u32;

    loop {
        if *stop.borrow() {
            publish_state(&state, &events, ProcessState::Stopped);
            return;
        }
        publish_state(&state, &events, ProcessState::Starting { attempt });
        let mut child = match command.spawn_grouped() {
            Ok(child) => child,
            Err(_error) => {
                restarts = restarts.saturating_add(1);
                if !policy.permits_restart(restarts) {
                    publish_state(
                        &state,
                        &events,
                        ProcessState::Failed {
                            reason: "connector process could not be started".to_owned(),
                        },
                    );
                    return;
                }
                if wait_backoff(restarts, &policy, &mut stop, &state, &events).await {
                    publish_state(&state, &events, ProcessState::Stopped);
                    return;
                }
                attempt = attempt.saturating_add(1);
                continue;
            }
        };

        let pid = child.inner().id();
        let stdout_task = child.inner().stdout.take().map(|stdout| {
            spawn_output_reader(stdout, false, Arc::clone(&redactor), events.clone())
        });
        let stderr_task =
            child.inner().stderr.take().map(|stderr| {
                spawn_output_reader(stderr, true, Arc::clone(&redactor), events.clone())
            });
        publish_state(&state, &events, ProcessState::Running { pid, attempt });

        let outcome =
            monitor_child(&mut child, &health, &checker, &policy, &mut stop, &events).await;
        let (_stdout, _stderr) = tokio::join!(
            drain_output_task(stdout_task),
            drain_output_task(stderr_task)
        );

        match outcome {
            ChildOutcome::Stopped => {
                publish_state(&state, &events, ProcessState::Stopped);
                return;
            }
            ChildOutcome::Exited {
                success,
                detail,
                stable,
            } => {
                if success && !policy.restart_on_clean_exit {
                    publish_state(&state, &events, ProcessState::Stopped);
                    return;
                }
                if stable {
                    restarts = 0;
                }
                restarts = restarts.saturating_add(1);
                if !policy.permits_restart(restarts) {
                    publish_state(&state, &events, ProcessState::Failed { reason: detail });
                    return;
                }
            }
            ChildOutcome::Unhealthy { stable } => {
                if stable {
                    restarts = 0;
                }
                restarts = restarts.saturating_add(1);
                if !policy.permits_restart(restarts) {
                    publish_state(
                        &state,
                        &events,
                        ProcessState::Failed {
                            reason: "connector failed its readiness check".to_owned(),
                        },
                    );
                    return;
                }
            }
        }

        if wait_backoff(restarts, &policy, &mut stop, &state, &events).await {
            publish_state(&state, &events, ProcessState::Stopped);
            return;
        }
        attempt = attempt.saturating_add(1);
    }
}

async fn monitor_child(
    child: &mut command_group::AsyncGroupChild,
    health: &HealthCheck,
    checker: &HealthChecker,
    policy: &RestartPolicy,
    stop: &mut watch::Receiver<bool>,
    events: &broadcast::Sender<ProcessEvent>,
) -> ChildOutcome {
    let started = tokio::time::Instant::now();
    let first_check = tokio::time::Instant::now() + policy.startup_grace;
    let mut health_interval = tokio::time::interval_at(first_check, policy.health_interval);
    health_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut process_interval = tokio::time::interval(Duration::from_millis(250));
    process_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failed_health_checks = 0_u32;
    let mut healthy_once = false;

    loop {
        tokio::select! {
            _ = process_interval.tick() => {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        return ChildOutcome::Exited {
                            success: status.success(),
                            detail: if status.success() {
                                "connector process exited".to_owned()
                            } else {
                                "connector process exited with an error".to_owned()
                            },
                            stable: healthy_once || started.elapsed() >= STABLE_RUNTIME,
                        };
                    }
                    Ok(None) => {}
                    Err(_error) => {
                        terminate_child(child, policy.shutdown_timeout).await;
                        return ChildOutcome::Exited {
                            success: false,
                            detail: "connector process status could not be read".to_owned(),
                            stable: healthy_once || started.elapsed() >= STABLE_RUNTIME,
                        };
                    }
                }
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    terminate_child(child, policy.shutdown_timeout).await;
                    return ChildOutcome::Stopped;
                }
            }
            _ = health_interval.tick(), if !matches!(health, HealthCheck::Disabled) => {
                let result = checker.check(health).await;
                let _ignored = events.send(ProcessEvent::HealthChanged {
                    healthy: result.healthy,
                    detail: result.detail,
                });
                if result.healthy {
                    healthy_once = true;
                    failed_health_checks = 0;
                } else {
                    failed_health_checks = failed_health_checks.saturating_add(1);
                    if failed_health_checks >= policy.unhealthy_threshold {
                        terminate_child(child, policy.shutdown_timeout).await;
                        return ChildOutcome::Unhealthy {
                            stable: healthy_once || started.elapsed() >= STABLE_RUNTIME,
                        };
                    }
                }
            }
        }
    }
}

async fn terminate_child(child: &mut command_group::AsyncGroupChild, timeout: Duration) {
    // `command-group` maps this to a Unix process group and a Windows Job Object,
    // so descendants are terminated as part of the same operation.
    let _ignored = child.start_kill();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if tokio::time::Instant::now() >= deadline => return,
            Ok(None) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
}

async fn wait_backoff(
    restart: u32,
    policy: &RestartPolicy,
    stop: &mut watch::Receiver<bool>,
    state: &watch::Sender<ProcessState>,
    events: &broadcast::Sender<ProcessEvent>,
) -> bool {
    let delay = policy.delay_for_restart(restart);
    let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
    let next_attempt = restart.saturating_add(1);
    publish_state(
        state,
        events,
        ProcessState::Backoff {
            attempt: next_attempt,
            delay_ms,
        },
    );
    let _ignored = events.send(ProcessEvent::RestartScheduled {
        attempt: next_attempt,
        delay_ms,
    });
    tokio::select! {
        () = tokio::time::sleep(delay) => false,
        changed = stop.changed() => changed.is_err() || *stop.borrow(),
    }
}

fn publish_state(
    state: &watch::Sender<ProcessState>,
    events: &broadcast::Sender<ProcessEvent>,
    next: ProcessState,
) {
    state.send_replace(next.clone());
    let _ignored = events.send(ProcessEvent::StateChanged { state: next });
}

fn spawn_output_reader<R>(
    reader: R,
    standard_error: bool,
    redactor: Arc<Redactor>,
    events: broadcast::Sender<ProcessEvent>,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = reader;
        let mut buffer = [0_u8; LOG_READ_BYTES];
        let mut pending = Vec::with_capacity(MAX_LOG_EVENT_BYTES + redactor.overlap_len());
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    while !pending.is_empty() {
                        let (text, consumed) = redactor.redact_prefix(&pending, pending.len());
                        emit_log_text(&events, standard_error, &text);
                        pending.drain(..consumed);
                    }
                    return;
                }
                Ok(read) => {
                    pending.extend_from_slice(&buffer[..read]);
                    drain_pending_log(&mut pending, standard_error, &redactor, &events);
                }
                Err(_) => return,
            }
        }
    })
}

fn drain_pending_log(
    pending: &mut Vec<u8>,
    standard_error: bool,
    redactor: &Redactor,
    events: &broadcast::Sender<ProcessEvent>,
) {
    let overlap = redactor.overlap_len();
    loop {
        let newline_end = pending
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1);
        let safe_prefix = match newline_end {
            Some(end) if end <= MAX_LOG_EVENT_BYTES => end,
            Some(_) if pending.len() > overlap => {
                MAX_LOG_EVENT_BYTES.min(pending.len().saturating_sub(overlap))
            }
            None if pending.len() > MAX_LOG_EVENT_BYTES.saturating_add(overlap) => {
                MAX_LOG_EVENT_BYTES
            }
            Some(_) | None => return,
        };
        if safe_prefix == 0 {
            return;
        }
        let (text, consumed) = redactor.redact_prefix(pending, safe_prefix);
        emit_log_text(events, standard_error, text.trim_end_matches(['\r', '\n']));
        pending.drain(..consumed);
    }
}

fn emit_log_text(events: &broadcast::Sender<ProcessEvent>, standard_error: bool, text: &str) {
    if text.is_empty() {
        return;
    }
    let mut start = 0;
    while start < text.len() {
        let mut end = start.saturating_add(MAX_LOG_EVENT_BYTES).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            end = text.len();
        }
        let line = text[start..end].to_owned();
        let event = if standard_error {
            ProcessEvent::StandardError { line }
        } else {
            ProcessEvent::StandardOutput { line }
        };
        let _ignored = events.send(event);
        start = end;
    }
}

async fn drain_output_task(task: Option<tokio::task::JoinHandle<()>>) {
    let Some(mut task) = task else {
        return;
    };
    if tokio::time::timeout(OUTPUT_DRAIN_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ignored = task.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded() {
        let policy = RestartPolicy {
            initial_backoff: Duration::from_secs(2),
            maximum_backoff: Duration::from_secs(10),
            backoff_multiplier: 2,
            ..RestartPolicy::default()
        };
        assert_eq!(policy.delay_for_restart(1), Duration::from_secs(2));
        assert_eq!(policy.delay_for_restart(2), Duration::from_secs(4));
        assert_eq!(policy.delay_for_restart(3), Duration::from_secs(8));
        assert_eq!(policy.delay_for_restart(4), Duration::from_secs(10));
        assert_eq!(policy.delay_for_restart(u32::MAX), Duration::from_secs(10));
    }

    #[test]
    fn policy_rejects_restart_storm_configuration() {
        let policy = RestartPolicy {
            initial_backoff: Duration::ZERO,
            ..RestartPolicy::default()
        };
        assert!(policy.validate().is_err());
    }
}
