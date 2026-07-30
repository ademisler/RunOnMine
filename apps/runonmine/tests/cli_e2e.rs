use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use runonmine_core::{
    AppConfig, CloudflareNamedSettings, ConnectorConfig, ConnectorKind, OAuthOwnerSettings,
    PolicyPreset,
};
use tempfile::TempDir;
use url::Url;

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

    let bundle_path = cli.root.path().join("support.zip");
    let bundle_path_text = bundle_path.to_string_lossy().into_owned();
    let bundle = cli.run_ok(&["support-bundle", "--output", &bundle_path_text])?;
    assert!(bundle.contains("Created redacted support bundle"));
    assert!(bundle_path.is_file());
    assert_below(&bundle_path, cli.root.path())?;
    let mut archive = zip::ZipArchive::new(fs::File::open(&bundle_path)?)?;
    let mut bundle_contents = String::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        bundle_contents.push_str(entry.name());
        bundle_contents.push('\n');
        entry.read_to_string(&mut bundle_contents)?;
        bundle_contents.push('\n');
    }
    assert!(bundle_contents.contains("manifest.json"));
    assert!(bundle_contents.contains("summary.json"));
    assert!(bundle_contents.contains("audit-summary.json"));
    assert!(!bundle_contents.contains(&project));

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

#[test]
fn local_http_credentials_never_reach_standard_output() -> Result<()> {
    let cli = IsolatedCli::new()?;
    let project = cli.project.to_string_lossy().into_owned();
    cli.run_ok(&["setup", "--root", &project])?;

    let first_output = cli.root.path().join("local-http-first.json");
    let first_output_text = first_output.to_string_lossy().into_owned();
    let enabled = cli.run_ok(&[
        "connect",
        "local-http",
        "enable",
        "--token-output",
        &first_output_text,
    ])?;
    let first: serde_json::Value = serde_json::from_slice(&fs::read(&first_output)?)?;
    let first_token = first["bearer_token"]
        .as_str()
        .context("credential export omitted bearer_token")?;
    assert_eq!(first["authorization_scheme"], "Bearer");
    assert!(enabled.contains("Bearer token stored"));
    assert!(!enabled.contains(first_token));
    assert!(!enabled.contains("Bearer token:"));

    let status = cli.run_ok(&["connect", "local-http", "status"])?;
    assert!(status.contains("Token configured: true"));
    assert!(!status.contains(first_token));
    assert!(!status.contains("Bearer token:"));

    let legacy_reveal = cli.run(&["connect", "local-http", "status", "--show-token"])?;
    assert!(!legacy_reveal.status.success());
    assert!(String::from_utf8_lossy(&legacy_reveal.stderr).contains("unexpected argument"));

    let rotated = cli.run_ok(&["connect", "local-http", "rotate"])?;
    assert!(!rotated.contains(first_token));
    assert!(!rotated.contains("Bearer token:"));

    let second_output = cli.root.path().join("local-http-second.json");
    let second_output_text = second_output.to_string_lossy().into_owned();
    let exported = cli.run_ok(&[
        "connect",
        "local-http",
        "status",
        "--token-output",
        &second_output_text,
    ])?;
    let second: serde_json::Value = serde_json::from_slice(&fs::read(&second_output)?)?;
    let second_token = second["bearer_token"]
        .as_str()
        .context("rotated credential export omitted bearer_token")?;
    assert_ne!(first_token, second_token);
    assert!(!exported.contains(second_token));
    assert!(!exported.contains("Bearer token:"));

    let overwrite = cli.run(&[
        "connect",
        "local-http",
        "status",
        "--token-output",
        &second_output_text,
    ])?;
    assert!(!overwrite.status.success());
    assert!(String::from_utf8_lossy(&overwrite.stderr).contains("refusing to overwrite"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&first_output)?.permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&second_output)?.permissions().mode() & 0o777,
            0o600
        );
    }

    let disabled = cli.run_ok(&["connect", "local-http", "disable"])?;
    assert!(disabled.contains("token was deleted"));
    Ok(())
}

fn configure_oauth_test_connector(
    cli: &IsolatedCli,
    config_path: &Path,
    connector_id: &str,
) -> Result<()> {
    let tunnel_credentials = cli.root.path().join("tunnel-credentials.json");
    fs::write(&tunnel_credentials, b"{}")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&tunnel_credentials, fs::Permissions::from_mode(0o600))?;
    }
    let mut config = AppConfig::load(config_path)?;
    config.connectors.push(ConnectorConfig {
        id: connector_id.to_owned(),
        name: "OAuth test connector".to_owned(),
        kind: ConnectorKind::CloudflareOauth,
        enabled: false,
        policy_preset: PolicyPreset::Safe,
        pack_overrides: BTreeMap::default(),
        tool_overrides: BTreeMap::default(),
        policy_rules: Vec::new(),
        public_base_url: Some(Url::parse("https://mcp.example.com/")?),
        cloudflare_quick: None,
        cloudflare_named: Some(CloudflareNamedSettings {
            tunnel_id: "00000000-0000-4000-8000-000000000456".to_owned(),
            credentials_file: tunnel_credentials,
            hostname: "mcp.example.com".to_owned(),
            cloudflared_path: None,
            metrics_port: 47_824,
        }),
        oauth_owner: Some(OAuthOwnerSettings {
            github_login: "owner".to_owned(),
            github_id: 42,
        }),
        openai_tunnel: None,
    });
    config.save(config_path)
}

fn initial_access_token(path: &Path) -> Result<String> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    value["initial_access_token"]
        .as_str()
        .map(str::to_owned)
        .context("OAuth registration export omitted initial_access_token")
}

#[test]
fn oauth_registration_token_is_owner_exported_and_rotated_without_stdout_leak() -> Result<()> {
    let cli = IsolatedCli::new()?;
    let project = cli.project.to_string_lossy().into_owned();
    let setup = cli.run_ok(&["setup", "--root", &project])?;
    let config_path = config_path_from_setup(&setup)?;
    let connector_id = "00000000-0000-4000-8000-000000000123";

    configure_oauth_test_connector(&cli, &config_path, connector_id)?;

    let first_output = cli.root.path().join("oauth-registration-first.json");
    let first_output_text = first_output.to_string_lossy().into_owned();
    let rotated = cli.run_ok(&[
        "oauth",
        "registration-token",
        "rotate",
        connector_id,
        "--output",
        &first_output_text,
    ])?;
    let first: serde_json::Value = serde_json::from_slice(&fs::read(&first_output)?)?;
    let first_token = initial_access_token(&first_output)?;
    assert_eq!(first["authorization_scheme"], "Bearer");
    assert_eq!(
        first["registration_endpoint"],
        "https://mcp.example.com/oauth/register"
    );
    assert!(!rotated.contains(first_token.as_str()));
    assert!(!rotated.contains("initial_access_token"));

    let exported_output = cli.root.path().join("oauth-registration-exported.json");
    let exported_output_text = exported_output.to_string_lossy().into_owned();
    let exported = cli.run_ok(&[
        "oauth",
        "registration-token",
        "export",
        connector_id,
        "--output",
        &exported_output_text,
    ])?;
    let same: serde_json::Value = serde_json::from_slice(&fs::read(&exported_output)?)?;
    assert_eq!(same["initial_access_token"], first_token);
    assert!(!exported.contains(first_token.as_str()));

    let second_output = cli.root.path().join("oauth-registration-second.json");
    let second_output_text = second_output.to_string_lossy().into_owned();
    let second_rotation = cli.run_ok(&[
        "oauth",
        "registration-token",
        "rotate",
        connector_id,
        "--output",
        &second_output_text,
    ])?;
    let second_token = initial_access_token(&second_output)?;
    assert_ne!(first_token, second_token);
    assert!(!second_rotation.contains(second_token.as_str()));

    let overwrite = cli.run(&[
        "oauth",
        "registration-token",
        "export",
        connector_id,
        "--output",
        &second_output_text,
    ])?;
    assert!(!overwrite.status.success());
    assert!(String::from_utf8_lossy(&overwrite.stderr).contains("refusing to overwrite"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for output in [&first_output, &exported_output, &second_output] {
            assert_eq!(fs::metadata(output)?.permissions().mode() & 0o777, 0o600);
        }
    }
    Ok(())
}
