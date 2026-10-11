use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use runonmine_platform::helper::{
    AdminProgramRule, HelperInstallOptions, HelperManager, ProgramProfileDocument,
    resolve_install_owner, serve_installed,
};

#[derive(Debug, Parser)]
#[command(
    name = "runonmine-helper",
    version,
    about = "RunOnMine opt-in privileged helper"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install the privileged helper as an operating-system service.
    Install {
        /// Unix UID allowed to connect. Required without a sudo caller.
        #[arg(long, conflicts_with = "owner_sid")]
        owner_uid: Option<u32>,
        /// Windows SID allowed to connect. Defaults to the elevated caller SID.
        #[arg(long, conflicts_with = "owner_uid")]
        owner_sid: Option<String>,
        /// Root-controlled executable to permit with no arguments. May be repeated.
        #[arg(long = "allow-program", value_name = "ABSOLUTE_PATH")]
        allowed_programs: Vec<PathBuf>,
        /// Versioned JSON document with executable-specific invocation profiles.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        profile_file: Option<PathBuf>,
    },
    /// Remove the helper service, binary, policy and local IPC endpoint.
    Uninstall,
    /// Report installed, running and authenticated health state.
    Status,
    /// Run the helper server. Intended only for the installed system service.
    #[command(hide = true)]
    Serve,
    /// Enter the Windows Service Control Manager dispatcher.
    #[cfg(windows)]
    #[command(hide = true)]
    Service,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("runonmine-helper: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    #[cfg(windows)]
    if matches!(cli.command, Command::Service) {
        return windows_service_host::dispatch();
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create the helper runtime")?;
    runtime.block_on(run_async(cli.command))
}

async fn run_async(command: Command) -> Result<()> {
    match command {
        Command::Install {
            owner_uid,
            owner_sid,
            allowed_programs,
            profile_file,
        } => {
            let owner = resolve_install_owner(owner_uid, owner_sid)?;
            let mut program_profiles = allowed_programs
                .into_iter()
                .map(AdminProgramRule::no_arguments)
                .collect::<Vec<_>>();
            if let Some(profile_file) = profile_file {
                program_profiles.extend(ProgramProfileDocument::load(&profile_file)?.programs);
            }
            let manager = HelperManager::discover()?;
            manager
                .install(HelperInstallOptions {
                    owner,
                    allowed_programs: program_profiles,
                })
                .await?;
            println!("RunOnMine privileged helper installed and health-checked.");
        }
        Command::Uninstall => {
            HelperManager::discover()?.uninstall()?;
            println!("RunOnMine privileged helper removed.");
        }
        Command::Status => {
            let status = HelperManager::discover()?.status().await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::Serve => serve_installed().await?,
        #[cfg(windows)]
        Command::Service => anyhow::bail!("the Windows service dispatcher was not entered"),
    }
    Ok(())
}

#[cfg(windows)]
mod windows_service_host {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use anyhow::{Context, Result};
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    const SERVICE_NAME: &str = "RunOnMineHelper";

    define_windows_service!(ffi_service_main, service_main);

    pub(super) fn dispatch() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("failed to enter the Windows service dispatcher")
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            tracing::error!(error = %error, "privileged helper service stopped");
        }
    }

    fn run_service() -> Result<()> {
        let stopping = Arc::new(AtomicBool::new(false));
        let stopping_for_handler = Arc::clone(&stopping);
        let event_handler = move |control| match control {
            ServiceControl::Stop => {
                stopping_for_handler.store(true, Ordering::Release);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .context("failed to register the Windows service control handler")?;
        status_handle.set_service_status(service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP,
        ))?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("failed to create the helper service runtime")?;
        runtime.block_on(async {
            let server = tokio::spawn(runonmine_platform::helper::serve_installed());
            loop {
                if stopping.load(Ordering::Acquire) {
                    server.abort();
                    let _ignored = server.await;
                    break;
                }
                if server.is_finished() {
                    server.await.context("helper server task failed")??;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Result::<()>::Ok(())
        })?;

        status_handle.set_service_status(service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
        ))?;
        Ok(())
    }

    fn service_status(state: ServiceState, accepted: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn install_rejects_conflicting_owner_identities() {
        assert!(
            Cli::try_parse_from([
                "runonmine-helper",
                "install",
                "--owner-uid",
                "1000",
                "--owner-sid",
                "S-1-5-21-1-2-3-1001",
            ])
            .is_err()
        );
    }

    #[test]
    fn install_preserves_absolute_allowlisted_programs() -> Result<()> {
        let cli = Cli::try_parse_from([
            "runonmine-helper",
            "install",
            "--owner-uid",
            "1000",
            "--allow-program",
            "/usr/bin/example",
        ])?;
        let Command::Install {
            owner_uid,
            owner_sid,
            allowed_programs,
            profile_file,
        } = cli.command
        else {
            anyhow::bail!("unexpected helper command");
        };
        assert_eq!(owner_uid, Some(1000));
        assert!(owner_sid.is_none());
        assert_eq!(allowed_programs, vec![PathBuf::from("/usr/bin/example")]);
        assert!(profile_file.is_none());
        Ok(())
    }

    #[test]
    fn install_accepts_an_absolute_program_profile_file() -> Result<()> {
        let cli = Cli::try_parse_from([
            "runonmine-helper",
            "install",
            "--owner-uid",
            "1000",
            "--profile-file",
            "/tmp/admin-profile.json",
        ])?;
        let Command::Install { profile_file, .. } = cli.command else {
            anyhow::bail!("unexpected helper command");
        };
        assert_eq!(profile_file, Some(PathBuf::from("/tmp/admin-profile.json")));
        Ok(())
    }

    #[test]
    fn hidden_serve_command_remains_parseable_for_service_managers() -> Result<()> {
        let cli = Cli::try_parse_from(["runonmine-helper", "serve"])?;
        assert!(matches!(cli.command, Command::Serve));
        Ok(())
    }
}
