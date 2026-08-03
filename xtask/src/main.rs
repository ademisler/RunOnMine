use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zip::write::SimpleFileOptions;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(name = "xtask")]
struct Cli {
    #[command(subcommand)]
    command: XtaskCommand,
}

#[derive(Debug, Subcommand)]
enum XtaskCommand {
    /// Create a portable archive, SBOM and SHA-256 files from built binaries.
    Package {
        #[arg(long)]
        target: String,
        /// Build the standalone Linux desktop package variant.
        #[arg(long)]
        desktop: bool,
    },
    /// Merge the two macOS architecture builds into universal binaries.
    UniversalMacos,
    /// Copy one target's binaries into cargo-packager's isolated input folder.
    StagePackager {
        #[arg(long)]
        target: String,
        /// Stage the standalone Linux desktop package variant.
        #[arg(long)]
        desktop: bool,
    },
    /// Create SHA-256 files for every regular artifact in dist/.
    Checksums,
    /// Validate a generated `CycloneDX` SBOM for one exact release target.
    ValidateSbom {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        target: String,
        /// Validate the standalone Linux desktop package manifest.
        #[arg(long)]
        desktop: bool,
    },
    /// Fail unless all package and packager versions match the workspace version.
    VerifyVersions,
    /// Update package-manager configuration versions from the workspace version.
    SyncVersions,
    /// Fail unless a release tag exactly matches the workspace version.
    VerifyReleaseTag {
        #[arg(long)]
        tag: String,
    },
    /// Run the repository quality gates through one local command.
    Verify {
        /// Run only the supported headless workspace checks.
        #[arg(long)]
        headless: bool,
        /// Skip the full-history Gitleaks scan when it is unavailable locally.
        #[arg(long)]
        skip_secret_scan: bool,
    },
    /// Report and enforce the manual release-acceptance gates for a profile.
    ReleaseReadiness {
        #[arg(long, default_value = "private-beta")]
        profile: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        XtaskCommand::Package { target, desktop } => package(&target, desktop),
        XtaskCommand::UniversalMacos => universal_macos(),
        XtaskCommand::StagePackager { target, desktop } => stage_packager(&target, desktop),
        XtaskCommand::Checksums => checksums(),
        XtaskCommand::ValidateSbom {
            path,
            target,
            desktop,
        } => validate_sbom_file(&path, &target, desktop),
        XtaskCommand::VerifyVersions => verify_versions(),
        XtaskCommand::SyncVersions => sync_versions(),
        XtaskCommand::VerifyReleaseTag { tag } => verify_release_tag(&tag),
        XtaskCommand::Verify {
            headless,
            skip_secret_scan,
        } => verify(headless, skip_secret_scan),
        XtaskCommand::ReleaseReadiness { profile } => release_readiness(&profile),
    }
}

const PACKAGER_CONFIGS: [&str; 5] = [
    "packaging/Packager.macos.toml",
    "packaging/Packager.windows.toml",
    "packaging/Packager.linux-x86_64.toml",
    "packaging/Packager.linux-aarch64.toml",
    "packaging/Packager.linux-desktop-x86_64.toml",
];

fn packager_string(table: &toml::Table, relative: &str, keys: &[&str]) -> Result<String> {
    keys.iter()
        .find_map(|key| table.get(*key).and_then(toml::Value::as_str))
        .map(str::to_owned)
        .with_context(|| format!("{relative} has no {} field", keys.join("/")))
}

fn packager_string_array(table: &toml::Table, relative: &str, key: &str) -> Result<Vec<String>> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .with_context(|| format!("{relative} has no {key} array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("{relative} {key} must contain only strings"))
        })
        .collect()
}

fn validate_windows_packager_config(table: &toml::Table, relative: &str) -> Result<()> {
    if packager_string(table, relative, &["target-triple", "targetTriple"])?
        != "x86_64-pc-windows-msvc"
    {
        bail!("{relative} must package the x86_64-pc-windows-msvc release target");
    }
    if packager_string_array(table, relative, "icons")? != ["assets/runonmine.ico"] {
        bail!("{relative} must use the checked-in RunOnMine Windows icon");
    }
    let binaries = table
        .get("binaries")
        .and_then(toml::Value::as_array)
        .with_context(|| format!("{relative} has no binaries array"))?;
    let mut paths = BTreeMap::new();
    for binary in binaries {
        let binary = binary
            .as_table()
            .with_context(|| format!("{relative} binaries must be tables"))?;
        let path = packager_string(binary, relative, &["path"])?;
        let main = binary
            .get("main")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        paths.insert(path, main);
    }
    let expected = BTreeMap::from([
        ("runonmine".to_owned(), false),
        ("runonmine-agent".to_owned(), false),
        ("runonmine-desktop".to_owned(), true),
        ("runonmine-helper".to_owned(), false),
    ]);
    if paths != expected {
        bail!("{relative} must package the exact four-binary Windows desktop manifest");
    }

    let nsis = table
        .get("nsis")
        .and_then(toml::Value::as_table)
        .with_context(|| format!("{relative} has no nsis table"))?;
    for (label, keys, expected) in [
        ("install mode", &["installMode"][..], "currentUser"),
        (
            "installer icon",
            &["installer-icon"][..],
            "assets/runonmine.ico",
        ),
        (
            "header image",
            &["header-image"][..],
            "assets/windows-header.bmp",
        ),
        (
            "sidebar image",
            &["sidebar-image"][..],
            "assets/windows-sidebar.bmp",
        ),
    ] {
        let actual = packager_string(nsis, relative, keys)?;
        if actual != expected {
            bail!("{relative} {label} must be {expected:?}; received {actual:?}");
        }
    }
    let languages = packager_string_array(nsis, relative, "languages")?;
    if languages != ["English", "French", "Turkish"] {
        bail!("{relative} must expose the English, French and Turkish NSIS languages");
    }
    let appdata_paths = packager_string_array(nsis, relative, "appdata-paths")?;
    if appdata_paths
        != [
            r"$APPDATA\RunOnMine\RunOnMine",
            r"$LOCALAPPDATA\RunOnMine\RunOnMine",
        ]
    {
        bail!("{relative} must bind uninstall data choices to the standard RunOnMine roots");
    }
    Ok(())
}

fn validate_packager_config(relative: &str, content: &str) -> Result<String> {
    let parsed: toml::Value =
        toml::from_str(content).with_context(|| format!("failed to parse {relative} as TOML"))?;
    let table = parsed
        .as_table()
        .with_context(|| format!("{relative} must contain one packager table"))?;
    let name = packager_string(table, relative, &["name"])?;
    if name != "runonmine" {
        bail!("{relative} must declare name = \"runonmine\" for cargo-packager");
    }
    let version = packager_string(table, relative, &["version"])?;
    for (label, keys, expected) in [
        (
            "license",
            &["license-file", "licenseFile"][..],
            "../LICENSE",
        ),
        (
            "binaries directory",
            &["binaries-dir", "binariesDir"][..],
            "../target/packager-input",
        ),
        ("output directory", &["out-dir", "outDir"][..], "../dist"),
    ] {
        let actual = packager_string(table, relative, keys)?;
        if actual != expected {
            bail!(
                "{relative} {label} must be {expected:?} because cargo-packager resolves paths from packaging/; received {actual:?}"
            );
        }
    }
    let resources = table
        .get("resources")
        .and_then(toml::Value::as_array)
        .with_context(|| format!("{relative} has no resources array"))?;
    if !resources
        .iter()
        .any(|resource| resource.as_str() == Some("../README.md"))
    {
        bail!("{relative} must package ../README.md relative to packaging/");
    }
    if relative == "packaging/Packager.windows.toml" {
        validate_windows_packager_config(table, relative)?;
    }
    Ok(version)
}

fn verify_versions() -> Result<()> {
    let root = workspace_root()?;
    let metadata_output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked", "--no-deps"])
        .current_dir(&root)
        .output()
        .context("cargo metadata failed while verifying versions")?;
    if !metadata_output.status.success() {
        bail!("cargo metadata failed while verifying versions");
    }
    let metadata: Value = serde_json::from_slice(&metadata_output.stdout)?;
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .context("cargo metadata has no workspace members")?;
    let members = workspace_members
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    for package in metadata["packages"]
        .as_array()
        .context("cargo metadata has no packages")?
    {
        let Some(id) = package["id"].as_str() else {
            continue;
        };
        if !members.contains(id) {
            continue;
        }
        let name = package["name"].as_str().unwrap_or("unknown");
        let version = package["version"].as_str().unwrap_or("unknown");
        if version != VERSION {
            bail!("workspace package {name} has version {version}; expected {VERSION}");
        }
    }
    for relative in PACKAGER_CONFIGS {
        let path = root.join(relative);
        let content = fs::read_to_string(&path)?;
        let declared = validate_packager_config(relative, &content)?;
        if declared != VERSION {
            bail!("{relative} has version {declared}; expected {VERSION}");
        }
    }
    println!("All RunOnMine package versions match {VERSION}.");
    Ok(())
}

fn sync_versions() -> Result<()> {
    let root = workspace_root()?;
    for relative in PACKAGER_CONFIGS {
        let path = root.join(relative);
        let content = fs::read_to_string(&path)?;
        let mut replaced = false;
        let updated = content
            .lines()
            .map(|line| {
                if !replaced && line.starts_with("version = \"") {
                    replaced = true;
                    format!("version = \"{VERSION}\"")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        if !replaced {
            bail!("{relative} has no version field");
        }
        fs::write(path, updated)?;
    }
    verify_versions()
}

fn verify_release_tag(tag: &str) -> Result<()> {
    let expected = format!("v{VERSION}");
    if tag != expected {
        bail!("release tag must be {expected}, received {tag}");
    }
    Ok(())
}

fn verify(headless: bool, skip_secret_scan: bool) -> Result<()> {
    verify_versions()?;
    run_checked("cargo", &["fmt", "--all", "--check"])?;
    if !headless {
        run_checked(
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        )?;
        run_checked(
            "cargo",
            &["test", "--workspace", "--all-features", "--locked"],
        )?;
    }
    run_checked(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--exclude",
            "runonmine-desktop",
            "--no-default-features",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run_checked(
        "cargo",
        &[
            "test",
            "--workspace",
            "--exclude",
            "runonmine-desktop",
            "--no-default-features",
            "--locked",
        ],
    )?;
    run_checked("cargo", &["audit", "--deny", "warnings"])?;
    run_checked(
        "cargo",
        &["audit", "--deny", "warnings", "--file", "fuzz/Cargo.lock"],
    )?;
    run_checked("cargo", &["deny", "check"])?;
    if !skip_secret_scan {
        run_checked("gitleaks", &["git", "--redact", "--no-banner", "--verbose"])?;
    }
    println!("RunOnMine verification passed.");
    Ok(())
}

fn run_checked(program: &str, arguments: &[&str]) -> Result<()> {
    let root = workspace_root()?;
    let status = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .status()
        .with_context(|| format!("failed to start {program}"))?;
    if !status.success() {
        bail!("{program} {} failed with {status}", arguments.join(" "));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseGateManifest {
    schema: u32,
    gate: Vec<ReleaseGate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseGate {
    id: String,
    description: String,
    status: String,
    required_for: Vec<String>,
    #[serde(default)]
    evidence: String,
}

fn release_readiness(profile: &str) -> Result<()> {
    if !matches!(profile, "private-beta" | "public-beta") {
        bail!("release profile must be private-beta or public-beta");
    }
    let path = workspace_root()?.join("acceptance/release-gates.toml");
    let manifest: ReleaseGateManifest = toml::from_str(&fs::read_to_string(&path)?)?;
    if manifest.schema != 1 {
        bail!("unsupported release-gate schema {}", manifest.schema);
    }
    let pending = pending_release_gates(&manifest, profile)?;
    if pending.is_empty() {
        println!("All {profile} acceptance gates passed.");
        return Ok(());
    }
    for gate in &pending {
        eprintln!("{} [{}]: {}", gate.id, gate.status, gate.description);
        if !gate.evidence.trim().is_empty() {
            eprintln!("  evidence/blocker: {}", gate.evidence);
        }
    }
    bail!(
        "{} required {profile} acceptance gate(s) are not passed",
        pending.len()
    )
}

fn pending_release_gates<'a>(
    manifest: &'a ReleaseGateManifest,
    profile: &str,
) -> Result<Vec<&'a ReleaseGate>> {
    let mut pending = Vec::new();
    let mut identifiers = std::collections::BTreeSet::new();
    for gate in &manifest.gate {
        if gate.id.trim().is_empty() || !identifiers.insert(gate.id.as_str()) {
            bail!("release gate identifiers must be non-empty and unique");
        }
        if !matches!(gate.status.as_str(), "pending" | "blocked" | "passed") {
            bail!(
                "release gate {} has invalid status {}",
                gate.id,
                gate.status
            );
        }
        if gate.status == "passed" && gate.evidence.trim().is_empty() {
            bail!("passed release gate {} must include evidence", gate.id);
        }
        if gate.required_for.iter().any(|item| item == profile) && gate.status != "passed" {
            pending.push(gate);
        }
    }
    Ok(pending)
}

const HEADLESS_BINARIES: [&str; 3] = ["runonmine", "runonmine-agent", "runonmine-helper"];
const DESKTOP_BINARIES: [&str; 4] = [
    "runonmine",
    "runonmine-agent",
    "runonmine-desktop",
    "runonmine-helper",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseTarget {
    LinuxX86_64,
    LinuxAarch64,
    MacosX86_64,
    MacosAarch64,
    MacosUniversal,
    WindowsX86_64,
}

impl ReleaseTarget {
    const ALL: [Self; 6] = [
        Self::LinuxX86_64,
        Self::LinuxAarch64,
        Self::MacosX86_64,
        Self::MacosAarch64,
        Self::MacosUniversal,
        Self::WindowsX86_64,
    ];

    fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|target| target.as_str() == value)
            .with_context(|| format!("unsupported release target: {value}"))
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "x86_64-unknown-linux-gnu",
            Self::LinuxAarch64 => "aarch64-unknown-linux-gnu",
            Self::MacosX86_64 => "x86_64-apple-darwin",
            Self::MacosAarch64 => "aarch64-apple-darwin",
            Self::MacosUniversal => "universal-apple-darwin",
            Self::WindowsX86_64 => "x86_64-pc-windows-msvc",
        }
    }

    const fn binaries(self) -> &'static [&'static str] {
        match self {
            Self::LinuxX86_64 | Self::LinuxAarch64 => &HEADLESS_BINARIES,
            Self::MacosX86_64 | Self::MacosAarch64 | Self::MacosUniversal | Self::WindowsX86_64 => {
                &DESKTOP_BINARIES
            }
        }
    }

    const fn executable_suffix(self) -> &'static str {
        match self {
            Self::WindowsX86_64 => ".exe",
            _ => "",
        }
    }

    const fn archive_extension(self) -> &'static str {
        match self {
            Self::WindowsX86_64 => "zip",
            _ => "tar.gz",
        }
    }
}

fn package_binaries(target: ReleaseTarget, desktop: bool) -> Result<&'static [&'static str]> {
    if desktop {
        if target != ReleaseTarget::LinuxX86_64 {
            bail!("the desktop package variant is supported only for x86_64-unknown-linux-gnu");
        }
        return Ok(&DESKTOP_BINARIES);
    }
    Ok(target.binaries())
}

#[cfg(test)]
fn expected_binaries(target: &str, desktop: bool) -> Result<&'static [&'static str]> {
    package_binaries(ReleaseTarget::parse(target)?, desktop)
}

fn package(target: &str, desktop: bool) -> Result<()> {
    let release_target = ReleaseTarget::parse(target)?;
    let binaries = package_binaries(release_target, desktop)?;
    let root = workspace_root()?;
    let release_dir = root
        .join("target")
        .join(release_target.as_str())
        .join("release");
    let dist = root.join("dist");
    fs::create_dir_all(&dist)?;
    let package_prefix = if desktop {
        "runonmine-desktop"
    } else {
        "runonmine"
    };
    let package_name = format!(
        "{package_prefix}-{VERSION}-{}-unsigned",
        release_target.as_str()
    );
    let staging = root
        .join("target")
        .join("package-staging")
        .join(&package_name);
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;

    let mut included = Vec::new();
    for binary in binaries {
        let filename = format!("{binary}{}", release_target.executable_suffix());
        let source = release_dir.join(&filename);
        if !source.is_file() {
            bail!(
                "required release binary is missing for {}: {filename}",
                release_target.as_str()
            );
        }
        fs::copy(&source, staging.join(&filename))?;
        included.push(filename);
    }
    fs::copy(root.join("LICENSE"), staging.join("LICENSE"))?;
    fs::copy(root.join("README.md"), staging.join("README.md"))?;
    let sbom_path = dist.join(format!("{package_name}.sbom.json"));
    let sbom = cyclonedx_sbom(&root, release_target, &included)?;
    validate_sbom(&sbom, release_target, binaries)?;
    fs::write(&sbom_path, serde_json::to_vec_pretty(&sbom)?)?;

    let archive = match release_target.archive_extension() {
        "zip" => {
            let path = dist.join(format!("{package_name}.zip"));
            write_zip(&staging, &path)?;
            path
        }
        "tar.gz" => {
            let path = dist.join(format!("{package_name}.tar.gz"));
            write_tar_gz(&staging, &path, &package_name)?;
            path
        }
        _ => unreachable!("release target archive extension is exhaustive"),
    };
    write_checksum(&archive)?;
    write_checksum(&sbom_path)?;
    println!("Packaged {}", archive.display());
    Ok(())
}

fn universal_macos() -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("universal macOS binaries can only be assembled on macOS");
    }
    let root = workspace_root()?;
    let arm = root.join("target/aarch64-apple-darwin/release");
    let intel = root.join("target/x86_64-apple-darwin/release");
    let output = root.join("target/universal-apple-darwin/release");
    if output.exists() {
        fs::remove_dir_all(&output)?;
    }
    fs::create_dir_all(&output)?;

    for binary in DESKTOP_BINARIES {
        let arm_binary = arm.join(binary);
        let intel_binary = intel.join(binary);
        if !arm_binary.is_file() || !intel_binary.is_file() {
            bail!("both architecture builds are required for {binary}");
        }
        let universal_binary = output.join(binary);
        command_success(
            Command::new("/usr/bin/lipo").args([
                "-create",
                arm_binary.to_string_lossy().as_ref(),
                intel_binary.to_string_lossy().as_ref(),
                "-output",
                universal_binary.to_string_lossy().as_ref(),
            ]),
            "lipo failed to create a universal binary",
        )?;
        command_success(
            Command::new("/usr/bin/lipo").args([
                universal_binary.to_string_lossy().as_ref(),
                "-verify_arch",
                "arm64",
                "x86_64",
            ]),
            "lipo architecture verification failed",
        )?;
    }
    println!("Assembled universal macOS binaries in {}", output.display());
    Ok(())
}

fn stage_packager(target: &str, desktop: bool) -> Result<()> {
    let release_target = ReleaseTarget::parse(target)?;
    let binaries = package_binaries(release_target, desktop)?;
    let root = workspace_root()?;
    let source = root
        .join("target")
        .join(release_target.as_str())
        .join("release");
    let staging = root.join("target/packager-input");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;
    let expected = binaries.len();
    let mut copied = 0_usize;
    for binary in binaries {
        let filename = format!("{binary}{}", release_target.executable_suffix());
        let path = source.join(&filename);
        if path.is_file() {
            fs::copy(&path, staging.join(filename))?;
            copied += 1;
        }
    }
    if copied != expected {
        bail!(
            "expected {expected} package binaries for {}, found {copied}",
            release_target.as_str()
        );
    }
    println!("Staged {copied} binaries for cargo-packager");
    Ok(())
}

fn checksums() -> Result<()> {
    let dist = workspace_root()?.join("dist");
    if !dist.is_dir() {
        bail!("dist directory does not exist");
    }
    let mut artifacts = fs::read_dir(&dist)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .filter(|path| {
            path.extension()
                .is_none_or(|extension| extension != "sha256")
        })
        .collect::<Vec<_>>();
    artifacts.sort();
    if artifacts.is_empty() {
        bail!("dist directory contains no artifacts");
    }
    for artifact in artifacts {
        write_checksum(&artifact)?;
    }
    Ok(())
}

fn command_success(command: &mut Command, context: &str) -> Result<()> {
    let output = command.output().with_context(|| context.to_owned())?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "{context}: {}",
        stderr.trim().chars().take(1_000).collect::<String>()
    )
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(Path::to_path_buf)
        .context("xtask has no workspace parent")
}

fn cyclonedx_sbom(
    root: &Path,
    target: ReleaseTarget,
    included_binaries: &[String],
) -> Result<Value> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        bail!("cargo metadata failed while generating the SBOM");
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let lock_path = root.join("Cargo.lock");
    let lock_bytes = fs::read(&lock_path)?;
    let lock: toml::Value = toml::from_slice(&lock_bytes)?;
    build_cyclonedx_sbom(
        &metadata,
        &lock,
        &sha256_hex(&lock_bytes),
        target,
        included_binaries,
        &source_revision(root)?,
    )
}

fn build_cyclonedx_sbom(
    metadata: &Value,
    lock: &toml::Value,
    lock_sha256: &str,
    target: ReleaseTarget,
    included_binaries: &[String],
    revision: &str,
) -> Result<Value> {
    let checksums = cargo_lock_checksums(lock)?;
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata has no packages")?;
    let mut components = Vec::with_capacity(packages.len());
    for package in packages {
        let name = package["name"].as_str().unwrap_or("unknown");
        let version = package["version"].as_str().unwrap_or("unknown");
        let id = package["id"]
            .as_str()
            .with_context(|| format!("cargo metadata package {name} has no id"))?;
        let source = package["source"].as_str();
        let license = package["license"].as_str();
        let mut component = json!({
            "type": if source.is_some() { "library" } else { "application" },
            "bom-ref": id,
            "name": name,
            "version": version,
            "purl": format!("pkg:cargo/{name}@{version}")
        });
        if let Some(license) = license {
            component["licenses"] = json!([{"expression": license}]);
        }
        if let Some(source) = source {
            component["properties"] = json!([{
                "name": "cargo:source",
                "value": source
            }]);
            if source.starts_with("git+") {
                component["externalReferences"] = json!([{
                    "type": "vcs",
                    "url": source.trim_start_matches("git+")
                }]);
            }
        }
        let key = CargoPackageKey {
            name: name.to_owned(),
            version: version.to_owned(),
            source: source.map(str::to_owned),
        };
        if let Some(checksum) = checksums.get(&key) {
            component["hashes"] = json!([{
                "alg": "SHA-256",
                "content": checksum
            }]);
        }
        components.push(component);
    }

    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .context("cargo metadata has no dependency resolution graph")?;
    let dependencies = nodes
        .iter()
        .map(|node| {
            let reference = node["id"].as_str().unwrap_or("unknown");
            let mut depends_on = node["dependencies"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            depends_on.sort_unstable();
            depends_on.dedup();
            json!({"ref": reference, "dependsOn": depends_on})
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "RunOnMine",
                "version": VERSION
            },
            "properties": [
                {
                    "name": "runonmine:cargo-lock-sha256",
                    "value": lock_sha256
                },
                {
                    "name": "runonmine:release-target",
                    "value": target.as_str()
                },
                {
                    "name": "runonmine:source-revision",
                    "value": revision
                },
                {
                    "name": "runonmine:included-binaries",
                    "value": included_binaries.join(",")
                }
            ]
        },
        "components": components,
        "dependencies": dependencies
    }))
}

fn source_revision(root: &Path) -> Result<String> {
    if let Ok(revision) = std::env::var("GITHUB_SHA")
        && revision.len() == 40
        && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Ok(revision.to_ascii_lowercase());
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .context("git failed while resolving SBOM provenance")?;
    if !output.status.success() {
        bail!("git failed while resolving SBOM provenance");
    }
    let revision = String::from_utf8(output.stdout)?.trim().to_owned();
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("SBOM provenance revision is invalid");
    }
    Ok(revision.to_ascii_lowercase())
}

fn validate_sbom_file(path: &Path, target: &str, desktop: bool) -> Result<()> {
    let release_target = ReleaseTarget::parse(target)?;
    let binaries = package_binaries(release_target, desktop)?;
    let value: Value = serde_json::from_slice(&fs::read(path)?)?;
    validate_sbom(&value, release_target, binaries)
}

fn validate_sbom(value: &Value, target: ReleaseTarget, binaries: &[&str]) -> Result<()> {
    if value["bomFormat"] != "CycloneDX" || value["specVersion"] != "1.6" {
        bail!("SBOM is not CycloneDX 1.6");
    }
    let serial = value["serialNumber"]
        .as_str()
        .context("SBOM serial number is missing")?;
    if !serial.starts_with("urn:uuid:") {
        bail!("SBOM serial number is invalid");
    }
    let components = value["components"]
        .as_array()
        .context("SBOM components are missing")?;
    if components.is_empty() {
        bail!("SBOM contains no components");
    }
    let dependencies = value["dependencies"]
        .as_array()
        .context("SBOM dependencies are missing")?;
    if dependencies.is_empty() {
        bail!("SBOM contains no dependency graph");
    }
    let properties = value["metadata"]["properties"]
        .as_array()
        .context("SBOM provenance properties are missing")?;
    let property = |name: &str| {
        properties.iter().find_map(|item| {
            (item["name"].as_str() == Some(name))
                .then(|| item["value"].as_str())
                .flatten()
        })
    };
    if property("runonmine:release-target") != Some(target.as_str()) {
        bail!("SBOM release target does not match the requested target");
    }
    let revision =
        property("runonmine:source-revision").context("SBOM source revision is missing")?;
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("SBOM source revision is invalid");
    }
    let lock_hash =
        property("runonmine:cargo-lock-sha256").context("SBOM Cargo.lock hash is missing")?;
    if lock_hash.len() != 64 || !lock_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("SBOM Cargo.lock hash is invalid");
    }
    let included = property("runonmine:included-binaries")
        .context("SBOM included-binaries property is missing")?;
    let expected = binaries
        .iter()
        .map(|binary| format!("{binary}{}", target.executable_suffix()))
        .collect::<Vec<_>>()
        .join(",");
    if included != expected {
        bail!("SBOM binary manifest does not match the release target");
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CargoPackageKey {
    name: String,
    version: String,
    source: Option<String>,
}

fn cargo_lock_checksums(lock: &toml::Value) -> Result<BTreeMap<CargoPackageKey, String>> {
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .context("Cargo.lock has no package list")?;
    let mut checksums = BTreeMap::new();
    for package in packages {
        let Some(table) = package.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(checksum) = table.get("checksum").and_then(toml::Value::as_str) else {
            continue;
        };
        let source = table
            .get("source")
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
        checksums.insert(
            CargoPackageKey {
                name: name.to_owned(),
                version: version.to_owned(),
                source,
            },
            checksum.to_owned(),
        );
    }
    Ok(checksums)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_tar_gz(staging: &Path, output: &Path, package_name: &str) -> Result<()> {
    let file = File::create(output)?;
    let encoder = GzEncoder::new(file, Compression::best());
    let mut archive = tar::Builder::new(encoder);
    archive.append_dir_all(package_name, staging)?;
    let encoder = archive.into_inner()?;
    encoder.finish()?.sync_all()?;
    Ok(())
}

fn write_zip(staging: &Path, output: &Path) -> Result<()> {
    let file = File::create(output)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for entry in fs::read_dir(staging)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        zip.start_file(entry.file_name().to_string_lossy(), options)?;
        let mut source = File::open(entry.path())?;
        std::io::copy(&mut source, &mut zip)?;
    }
    zip.finish()?.sync_all()?;
    Ok(())
}

fn write_checksum(path: &Path) -> Result<()> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1_024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let filename = path
        .file_name()
        .context("artifact has no file name")?
        .to_string_lossy();
    let checksum = format!("{}  {filename}\n", hex::encode(digest.finalize()));
    let checksum_path = path.with_file_name(format!("{filename}.sha256"));
    let mut output = File::create(checksum_path)?;
    output.write_all(checksum.as_bytes())?;
    output.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packager_config_requires_a_name_and_config_relative_paths() -> Result<()> {
        let valid = r#"
name = "runonmine"
version = "1.2.3"
licenseFile = "../LICENSE"
binariesDir = "../target/packager-input"
outDir = "../dist"
resources = ["../README.md"]
"#;
        assert_eq!(
            validate_packager_config("packaging/test.toml", valid)?,
            "1.2.3"
        );
        assert!(
            validate_packager_config(
                "packaging/test.toml",
                &valid.replacen("name = \"runonmine\"\n", "", 1),
            )
            .is_err()
        );
        assert!(
            validate_packager_config(
                "packaging/test.toml",
                &valid.replace("../target/packager-input", "target/packager-input"),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn windows_packager_contract_rejects_schema_drift() -> Result<()> {
        let valid = r#"
name = "runonmine"
version = "1.2.3"
license-file = "../LICENSE"
binaries-dir = "../target/packager-input"
out-dir = "../dist"
target-triple = "x86_64-pc-windows-msvc"
resources = ["../README.md"]
icons = ["assets/runonmine.ico"]
binaries = [
  { path = "runonmine-desktop", main = true },
  { path = "runonmine", main = false },
  { path = "runonmine-agent", main = false },
  { path = "runonmine-helper", main = false },
]

[nsis]
installMode = "currentUser"
installer-icon = "assets/runonmine.ico"
header-image = "assets/windows-header.bmp"
sidebar-image = "assets/windows-sidebar.bmp"
languages = ["English", "French", "Turkish"]
appdata-paths = ['$APPDATA\RunOnMine\RunOnMine', '$LOCALAPPDATA\RunOnMine\RunOnMine']
"#;
        let relative = "packaging/Packager.windows.toml";
        assert_eq!(validate_packager_config(relative, valid)?, "1.2.3");
        assert!(
            validate_packager_config(relative, &valid.replace("installMode", "install-mode"))
                .is_err()
        );
        assert!(
            validate_packager_config(relative, &valid.replace("currentUser", "perMachine"))
                .is_err()
        );
        assert!(
            validate_packager_config(
                relative,
                &valid.replace("assets/runonmine.ico", "assets/other.ico"),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn sbom_contains_dependency_edges_and_lockfile_checksums() -> Result<()> {
        let metadata = json!({
            "packages": [
                {
                    "name": "app",
                    "version": "1.0.0",
                    "id": "path+file:///app#1.0.0",
                    "source": null,
                    "license": "MIT"
                },
                {
                    "name": "dependency",
                    "version": "2.0.0",
                    "id": "registry+https://github.com/rust-lang/crates.io-index#dependency@2.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "license": "Apache-2.0"
                }
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "path+file:///app#1.0.0",
                        "dependencies": ["registry+https://github.com/rust-lang/crates.io-index#dependency@2.0.0"]
                    },
                    {
                        "id": "registry+https://github.com/rust-lang/crates.io-index#dependency@2.0.0",
                        "dependencies": []
                    }
                ]
            }
        });
        let lock: toml::Value = toml::from_str(
            r#"
                version = 4

                [[package]]
                name = "dependency"
                version = "2.0.0"
                source = "registry+https://github.com/rust-lang/crates.io-index"
                checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "#,
        )?;
        let sbom = build_cyclonedx_sbom(
            &metadata,
            &lock,
            &"a".repeat(64),
            ReleaseTarget::LinuxX86_64,
            &[
                "runonmine".to_owned(),
                "runonmine-agent".to_owned(),
                "runonmine-helper".to_owned(),
            ],
            &"b".repeat(40),
        )?;
        assert_eq!(
            sbom["dependencies"][0]["dependsOn"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            sbom["components"][1]["hashes"][0]["content"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(sbom["metadata"]["properties"][0]["value"], "a".repeat(64));
        validate_sbom(&sbom, ReleaseTarget::LinuxX86_64, &HEADLESS_BINARIES)?;
        Ok(())
    }

    #[test]
    fn release_profiles_require_only_their_declared_gates() -> Result<()> {
        let manifest = ReleaseGateManifest {
            schema: 1,
            gate: vec![
                ReleaseGate {
                    id: "private".to_owned(),
                    description: "private gate".to_owned(),
                    status: "pending".to_owned(),
                    required_for: vec!["private-beta".to_owned(), "public-beta".to_owned()],
                    evidence: String::new(),
                },
                ReleaseGate {
                    id: "public".to_owned(),
                    description: "public gate".to_owned(),
                    status: "blocked".to_owned(),
                    required_for: vec!["public-beta".to_owned()],
                    evidence: "certificate required".to_owned(),
                },
                ReleaseGate {
                    id: "done".to_owned(),
                    description: "completed gate".to_owned(),
                    status: "passed".to_owned(),
                    required_for: vec!["private-beta".to_owned()],
                    evidence: "report".to_owned(),
                },
            ],
        };
        assert_eq!(pending_release_gates(&manifest, "private-beta")?.len(), 1);
        assert_eq!(pending_release_gates(&manifest, "public-beta")?.len(), 2);
        Ok(())
    }

    #[test]
    fn passed_release_gate_requires_evidence() {
        let manifest = ReleaseGateManifest {
            schema: 1,
            gate: vec![ReleaseGate {
                id: "gate".to_owned(),
                description: "completed gate".to_owned(),
                status: "passed".to_owned(),
                required_for: vec!["private-beta".to_owned()],
                evidence: String::new(),
            }],
        };
        assert!(pending_release_gates(&manifest, "private-beta").is_err());
    }

    #[test]
    fn package_manifest_is_exact_for_each_platform_family() -> Result<()> {
        assert_eq!(
            expected_binaries("x86_64-unknown-linux-gnu", false)?,
            &HEADLESS_BINARIES
        );
        assert_eq!(
            expected_binaries("x86_64-unknown-linux-gnu", true)?,
            &DESKTOP_BINARIES
        );
        assert_eq!(
            expected_binaries("universal-apple-darwin", false)?,
            &DESKTOP_BINARIES
        );
        assert_eq!(
            expected_binaries("x86_64-pc-windows-msvc", false)?,
            &DESKTOP_BINARIES
        );
        assert!(expected_binaries("aarch64-unknown-linux-gnu", true).is_err());
        assert!(expected_binaries("universal-apple-darwin", true).is_err());
        for spoofed in [
            "x86_64-unknown-linux-gnu-extra",
            "linux",
            "windows-x86_64-pc-windows-msvc",
            "universal-apple-darwin-debug",
        ] {
            assert!(ReleaseTarget::parse(spoofed).is_err(), "accepted {spoofed}");
        }
        Ok(())
    }
}
