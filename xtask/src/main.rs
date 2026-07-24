use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use flate2::Compression;
use flate2::write::GzEncoder;
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
    },
    /// Merge the two macOS architecture builds into universal binaries.
    UniversalMacos,
    /// Copy one target's binaries into cargo-packager's isolated input folder.
    StagePackager {
        #[arg(long)]
        target: String,
    },
    /// Create SHA-256 files for every regular artifact in dist/.
    Checksums,
    /// Fail unless all package and packager versions match the workspace version.
    VerifyVersions,
    /// Update package-manager configuration versions from the workspace version.
    SyncVersions,
    /// Fail unless a release tag exactly matches the workspace version.
    VerifyReleaseTag {
        #[arg(long)]
        tag: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        XtaskCommand::Package { target } => package(&target),
        XtaskCommand::UniversalMacos => universal_macos(),
        XtaskCommand::StagePackager { target } => stage_packager(&target),
        XtaskCommand::Checksums => checksums(),
        XtaskCommand::VerifyVersions => verify_versions(),
        XtaskCommand::SyncVersions => sync_versions(),
        XtaskCommand::VerifyReleaseTag { tag } => verify_release_tag(&tag),
    }
}

const PACKAGER_CONFIGS: [&str; 4] = [
    "packaging/Packager.macos.toml",
    "packaging/Packager.windows.toml",
    "packaging/Packager.linux-x86_64.toml",
    "packaging/Packager.linux-aarch64.toml",
];

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
        let declared = content
            .lines()
            .find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'))
            .with_context(|| format!("{relative} has no version field"))?;
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

const BINARIES: [&str; 4] = [
    "runonmine",
    "runonmine-agent",
    "runonmine-desktop",
    "runonmine-helper",
];

fn package(target: &str) -> Result<()> {
    validate_target(target)?;
    let root = workspace_root()?;
    let release_dir = root.join("target").join(target).join("release");
    let dist = root.join("dist");
    fs::create_dir_all(&dist)?;
    let package_name = format!("runonmine-{VERSION}-{target}-unsigned");
    let staging = root
        .join("target")
        .join("package-staging")
        .join(&package_name);
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;

    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let mut included = Vec::new();
    for binary in BINARIES {
        let filename = format!("{binary}{suffix}");
        let source = release_dir.join(&filename);
        if source.is_file() {
            fs::copy(&source, staging.join(&filename))?;
            included.push(filename);
        }
    }
    if included.len() < 3 {
        bail!("expected release binaries are missing for {target}");
    }
    fs::copy(root.join("LICENSE"), staging.join("LICENSE"))?;
    fs::copy(root.join("README.md"), staging.join("README.md"))?;
    let sbom_path = dist.join(format!("{package_name}.sbom.json"));
    fs::write(
        &sbom_path,
        serde_json::to_vec_pretty(&cyclonedx_sbom(&root)?)?,
    )?;

    let archive = if target.contains("windows") {
        let path = dist.join(format!("{package_name}.zip"));
        write_zip(&staging, &path)?;
        path
    } else {
        let path = dist.join(format!("{package_name}.tar.gz"));
        write_tar_gz(&staging, &path, &package_name)?;
        path
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

    for binary in BINARIES {
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
                "-verify_arch",
                "arm64",
                "x86_64",
                universal_binary.to_string_lossy().as_ref(),
            ]),
            "lipo architecture verification failed",
        )?;
    }
    println!("Assembled universal macOS binaries in {}", output.display());
    Ok(())
}

fn stage_packager(target: &str) -> Result<()> {
    validate_target(target)?;
    let root = workspace_root()?;
    let source = root.join("target").join(target).join("release");
    let staging = root.join("target/packager-input");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let expected = if target.contains("linux") { 3 } else { 4 };
    let mut copied = 0_usize;
    for binary in BINARIES {
        let filename = format!("{binary}{suffix}");
        let path = source.join(&filename);
        if path.is_file() {
            fs::copy(&path, staging.join(filename))?;
            copied += 1;
        }
    }
    if copied != expected {
        bail!("expected {expected} package binaries for {target}, found {copied}");
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

fn validate_target(target: &str) -> Result<()> {
    if target.is_empty()
        || target.len() > 100
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("invalid Rust target name");
    }
    Ok(())
}

fn cyclonedx_sbom(root: &Path) -> Result<Value> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        bail!("cargo metadata failed while generating the SBOM");
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata has no packages")?;
    let components = packages
        .iter()
        .map(|package| {
            let name = package["name"].as_str().unwrap_or("unknown");
            let version = package["version"].as_str().unwrap_or("unknown");
            let license = package["license"].as_str();
            let mut component = json!({
                "type": "library",
                "name": name,
                "version": version,
                "purl": format!("pkg:cargo/{name}@{version}")
            });
            if let Some(license) = license {
                component["licenses"] = json!([{"expression": license}]);
            }
            component
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "RunOnMine", "version": VERSION}},
        "components": components
    }))
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
    let checksum = format!("{:x}  {filename}\n", digest.finalize());
    let checksum_path = path.with_file_name(format!("{filename}.sha256"));
    let mut output = File::create(checksum_path)?;
    output.write_all(checksum.as_bytes())?;
    output.sync_all()?;
    Ok(())
}
