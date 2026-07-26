use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use tempfile::TempDir;

const TEST_MASTER_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

struct IsolatedCli {
    root: TempDir,
    home: PathBuf,
    project: PathBuf,
}

impl IsolatedCli {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let project = root.path().join("project");
        for directory in [
            &home,
            &project,
            &root.path().join("xdg-config"),
            &root.path().join("xdg-state"),
            &root.path().join("xdg-data"),
        ] {
            fs::create_dir_all(directory)?;
        }
        Ok(Self {
            root,
            home,
            project,
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_runonmine"));
        command
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("APPDATA", self.root.path().join("appdata"))
            .env("LOCALAPPDATA", self.root.path().join("localappdata"))
            .env("XDG_CONFIG_HOME", self.root.path().join("xdg-config"))
            .env("XDG_STATE_HOME", self.root.path().join("xdg-state"))
            .env("XDG_DATA_HOME", self.root.path().join("xdg-data"))
            .env("RUNONMINE_TEST_FILE_SECRETS", "1")
            .env("RUNONMINE_MASTER_KEY", TEST_MASTER_KEY)
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("XDG_RUNTIME_DIR");
        command
    }

    fn run(&self, arguments: &[&str]) -> Result<Output> {
        self.command()
            .args(arguments)
            .output()
            .with_context(|| format!("failed to run runonmine {}", arguments.join(" ")))
    }

    fn run_ok(&self, arguments: &[&str]) -> Result<String> {
        let output = self.run(arguments)?;
        if !output.status.success() {
            bail!(
                "runonmine {} failed\nstdout:\n{}\nstderr:\n{}",
                arguments.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        Ok(String::from_utf8(output.stdout)?)
    }
}

fn config_path_from_setup(output: &str) -> Result<PathBuf> {
    let path = output
        .lines()
        .find_map(|line| line.strip_prefix("Config: "))
        .context("setup output did not include a config path")?;
    Ok(PathBuf::from(path))
}

fn assert_below(path: &Path, parent: &Path) -> Result<()> {
    if !path.starts_with(parent) {
        bail!(
            "isolated command escaped its temporary home: {} is not below {}",
            path.display(),
            parent.display()
        );
    }
    Ok(())
}

#[test]
fn setup_policy_lock_and_purge_run_as_an_isolated_user_flow() -> Result<()> {
    let cli = IsolatedCli::new()?;
    let project = cli.project.to_string_lossy().into_owned();
    let setup = cli.run_ok(&["setup", "--root", &project])?;
    assert!(setup.contains("RunOnMine is initialized."));
    assert!(setup.contains("Allowed roots: 1"));

    let config_path = config_path_from_setup(&setup)?;
    assert_below(&config_path, cli.root.path())?;
    assert!(config_path.is_file());

    let policy = cli.run_ok(&["policy", "show"])?;
    assert!(policy.contains("Local stdio"));
    assert!(policy.contains("AdminExec: Deny"));

    let connectors = cli.run_ok(&["connect", "list"])?;
    assert!(connectors.contains("LocalStdio"));
    assert!(connectors.contains("LocalHttp"));
    assert!(connectors.contains("enabled=false"));

    let approvals = cli.run_ok(&["approvals", "list"])?;
    assert!(approvals.contains("No pending approvals."));
    let _audit = cli.run_ok(&["audit", "tail", "--limit", "5"])?;

    let locked = cli.run_ok(&["lock"])?;
    assert!(locked.contains("RunOnMine is locked."));
    assert!(locked.contains("Cleared temporary grants:"));

    let purged = cli.run_ok(&["uninstall", "--purge", "--confirm", "PURGE"])?;
    assert!(purged.contains("permanently removed"));
    assert!(!config_path.exists());
    Ok(())
}

#[test]
fn destructive_commands_fail_closed_without_exact_confirmation() -> Result<()> {
    let cli = IsolatedCli::new()?;
    let project = cli.project.to_string_lossy().into_owned();
    let setup = cli.run_ok(&["setup", "--root", &project])?;
    let config_path = config_path_from_setup(&setup)?;

    let purge = cli.run(&["uninstall", "--purge"])?;
    assert!(!purge.status.success());
    assert!(String::from_utf8_lossy(&purge.stderr).contains("--confirm"));
    assert!(config_path.is_file());

    let missing_root = cli.run(&["setup", "--root", "/path/that/does/not/exist"])?;
    assert!(!missing_root.status.success());
    assert!(String::from_utf8_lossy(&missing_root.stderr).contains("does not exist"));
    assert!(config_path.is_file());
    Ok(())
}
