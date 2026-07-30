use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::{DateTime, Utc};
use runonmine_core::AppPaths;

mod archive;
mod redaction;
mod report;

use archive::{BundleEntry, write_zip_atomically};
use redaction::{collect_redacted_logs, known_sensitive_values};
use report::{audit_report, build_support_summary, config_report, state_report};

const BUNDLE_SCHEMA_VERSION: u32 = 2;
const README: &str = "RunOnMine redacted support bundle\n\n\
This archive is generated from bounded summaries. It does not include the raw\n\
configuration file, state database, browser profiles, credential store, audit\n\
arguments, connector identifiers, hostnames, URLs, or filesystem roots. Log\n\
fragments are bounded and redacted. Review the archive before sharing it.\n";

pub(super) fn create_support_bundle(output: Option<&Path>) -> Result<()> {
    let paths = AppPaths::discover()?;
    let generated_at = Utc::now();
    let output = output.map_or_else(
        || default_output_path(generated_at),
        |path| Ok(path.to_path_buf()),
    )?;
    create_support_bundle_for_paths(&paths, &output, generated_at)?;
    println!("Created redacted support bundle at {}.", output.display());
    println!("Review the ZIP before sharing it.");
    Ok(())
}

fn default_output_path(generated_at: DateTime<Utc>) -> Result<PathBuf> {
    let filename = format!(
        "runonmine-support-{}.zip",
        generated_at.format("%Y%m%dT%H%M%SZ")
    );
    Ok(std::env::current_dir()?.join(filename))
}

fn create_support_bundle_for_paths(
    paths: &AppPaths,
    output: &Path,
    generated_at: DateTime<Utc>,
) -> Result<()> {
    let (config_report, config) = config_report(paths);
    let known_values = known_sensitive_values(paths, config.as_ref());
    let log_entries = collect_redacted_logs(&paths.log_dir, &known_values)?;
    let audit_report = audit_report(paths);
    let state_report = state_report(&audit_report);
    let summary = build_support_summary(
        BUNDLE_SCHEMA_VERSION,
        generated_at,
        config_report,
        state_report,
        log_entries.len(),
    );

    let mut entries = vec![
        BundleEntry {
            path: "README.txt".to_owned(),
            bytes: README.as_bytes().to_vec(),
        },
        BundleEntry {
            path: "summary.json".to_owned(),
            bytes: serde_json::to_vec_pretty(&summary)?,
        },
        BundleEntry {
            path: "audit-summary.json".to_owned(),
            bytes: serde_json::to_vec_pretty(&audit_report)?,
        },
    ];
    entries.extend(log_entries);
    write_zip_atomically(output, generated_at, &entries)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Read;

    use super::archive::sha256_hex;
    use super::*;
    use runonmine_core::{AppConfig, AuditEvent, AuditOutcome, StateStore};

    #[test]
    fn support_bundle_excludes_raw_sensitive_values() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let private_root = temporary.path().join("private-project");
        fs::create_dir_all(&private_root)?;

        let mut config = AppConfig {
            allowed_roots: vec![private_root.clone()],
            ..AppConfig::default()
        };
        config.connectors[0].id = "connector-secret-123".to_owned();
        config.connectors[0].name = "Alice Production".to_owned();
        config.save(&paths.config_file())?;

        let log_secret = "top-secret-token-value-123456789";
        let email = "alice@example.com";
        let url = "https://secret.example.com/path?token=visible";
        fs::write(paths.log_dir.join("ignored.bin"), b"short-unlabeled-secret")?;
        fs::write(
            paths.log_dir.join("agent.log"),
            format!(
                "root={} connector={} name={} token={} email={} url={}\n",
                private_root.display(),
                config.connectors[0].id,
                config.connectors[0].name,
                log_secret,
                email,
                url
            ),
        )?;

        let store = StateStore::open(&paths.state_db())?;
        store.append_audit(&AuditEvent::new(
            &config.connectors[0].id,
            "shell_exec",
            "shell_exec",
            AuditOutcome::Failed,
            "argument-secret-hash",
            "summary contains private-project",
        ))?;
        drop(store);

        let output = temporary.path().join("support.zip");
        create_support_bundle_for_paths(&paths, &output, Utc::now())?;
        let contents = zip_contents(&output)?;
        let private_root_text = private_root.to_string_lossy().into_owned();
        for secret in [
            private_root_text.as_str(),
            config.connectors[0].id.as_str(),
            config.connectors[0].name.as_str(),
            log_secret,
            email,
            url,
            "argument-secret-hash",
            "summary contains private-project",
            "short-unlabeled-secret",
        ] {
            assert!(!contents.contains(secret), "bundle leaked {secret}");
        }
        assert!(contents.contains("[REDACTED]"));
        assert!(contents.contains("shell_exec"));
        assert!(contents.contains("manifest.json"));
        verify_manifest_checksums(&output)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn support_bundle_rejects_symlink_output() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let target = temporary.path().join("target.zip");
        fs::write(&target, b"existing")?;
        let output = temporary.path().join("support.zip");
        symlink(&target, &output)?;
        assert!(create_support_bundle_for_paths(&paths, &output, Utc::now()).is_err());
        Ok(())
    }

    fn verify_manifest_checksums(path: &Path) -> Result<()> {
        #[derive(serde::Deserialize)]
        struct TestManifest {
            entries: Vec<TestManifestEntry>,
        }
        #[derive(serde::Deserialize)]
        struct TestManifestEntry {
            path: String,
            size_bytes: usize,
            sha256: String,
        }

        let file = File::open(path)?;
        let mut archive = zip::ZipArchive::new(file)?;
        let manifest: TestManifest = {
            let mut entry = archive.by_name("manifest.json")?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            serde_json::from_slice(&bytes)?
        };
        for expected in manifest.entries {
            let mut entry = archive.by_name(&expected.path)?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            assert_eq!(bytes.len(), expected.size_bytes);
            assert_eq!(sha256_hex(&bytes), expected.sha256);
        }
        Ok(())
    }

    fn zip_contents(path: &Path) -> Result<String> {
        let file = File::open(path)?;
        let mut archive = zip::ZipArchive::new(file)?;
        let mut contents = String::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index)?;
            contents.push_str(entry.name());
            contents.push('\n');
            entry.read_to_string(&mut contents)?;
            contents.push('\n');
        }
        Ok(contents)
    }
}
