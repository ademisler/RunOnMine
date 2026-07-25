use std::collections::BTreeMap;
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

const HEADLESS_BINARIES: [&str; 3] = ["runonmine", "runonmine-agent", "runonmine-helper"];
const DESKTOP_BINARIES: [&str; 4] = [
    "runonmine",
    "runonmine-agent",
    "runonmine-desktop",
    "runonmine-helper",
];

fn expected_binaries(target: &str) -> &'static [&'static str] {
    if target.contains("linux") {
        &HEADLESS_BINARIES
    } else {
        &DESKTOP_BINARIES
    }
}

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
    for binary in expected_binaries(target) {
        let filename = format!("{binary}{suffix}");
        let source = release_dir.join(&filename);
        if !source.is_file() {
            bail!("required release binary is missing for {target}: {filename}");
        }
        fs::copy(&source, staging.join(&filename))?;
        included.push(filename);
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
    for binary in DESKTOP_BINARIES {
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
    let lock_path = root.join("Cargo.lock");
    let lock_bytes = fs::read(&lock_path)?;
    let lock: toml::Value = toml::from_slice(&lock_bytes)?;
    build_cyclonedx_sbom(&metadata, &lock, &sha256_hex(&lock_bytes))
}

fn build_cyclonedx_sbom(metadata: &Value, lock: &toml::Value, lock_sha256: &str) -> Result<Value> {
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
            "properties": [{
                "name": "runonmine:cargo-lock-sha256",
                "value": lock_sha256
            }]
        },
        "components": components,
        "dependencies": dependencies
    }))
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
    format!("{:x}", Sha256::digest(bytes))
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let sbom = build_cyclonedx_sbom(&metadata, &lock, "lock-hash")?;
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
        assert_eq!(sbom["metadata"]["properties"][0]["value"], "lock-hash");
        Ok(())
    }

    #[test]
    fn package_manifest_is_exact_for_each_platform_family() {
        assert_eq!(
            expected_binaries("x86_64-unknown-linux-gnu"),
            &HEADLESS_BINARIES
        );
        assert_eq!(
            expected_binaries("universal-apple-darwin"),
            &DESKTOP_BINARIES
        );
        assert_eq!(
            expected_binaries("x86_64-pc-windows-msvc"),
            &DESKTOP_BINARIES
        );
    }
}
