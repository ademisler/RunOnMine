//! Supervision and verified installation for `RunOnMine`'s external tunnel clients.
//!
//! This crate deliberately owns no credentials. Callers obtain secrets from the
//! platform secret store and pass them as [`SecretValue`] instances. Debug output,
//! process events, and command descriptions always redact those values.

pub mod binary;
pub mod cloudflare;
pub mod health;
pub mod installer;
pub mod openai;
pub mod process;
pub mod supervisor;

pub use binary::{BinaryDiscovery, BinaryKind, BinaryProbe, DoctorReport, InstalledBinary};
pub use health::{HealthCheck, HealthCheckResult, HealthChecker};
pub use installer::{
    ArtifactFormat, BinaryInstaller, GitHubReleaseResolver, InstallReceipt, ReleaseChannel,
    ReleaseProvider, Sha256Digest, VerifiedArtifact,
};
pub use process::{
    CommandArg, CommandSpec, EnvironmentValue, OneShotOutput, SecretValue, run_once,
};
pub use supervisor::{
    ProcessEvent, ProcessState, ProcessSupervisor, RestartPolicy, SupervisorHandle,
};
