use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use runonmine_core::{AppConfig, AppPaths};

use super::archive::{BundleEntry, ManifestInput};

pub(super) const MAX_LOG_FILES: usize = 5;
const MAX_LOG_TAIL_BYTES: usize = 256 * 1_024;
const MAX_REDACTED_LOG_BYTES: usize = 256 * 1_024;
const MAX_LOG_DEPTH: usize = 2;
const SENSITIVE_MARKERS: [&str; 30] = [
    "authorization:",
    "authorization=",
    "authorization =",
    "set-cookie:",
    "cookie:",
    "access_token=",
    "access_token:",
    "refresh_token=",
    "refresh_token:",
    "client_secret=",
    "client_secret:",
    "private_key=",
    "private_key:",
    "api_key=",
    "api_key:",
    "api_key =",
    "api key=",
    "api key:",
    "api key =",
    "apikey=",
    "apikey:",
    "password=",
    "password:",
    "password =",
    "secret=",
    "secret:",
    "secret =",
    "token=",
    "token:",
    "token =",
];

#[derive(Debug)]
struct LogCandidate {
    path: PathBuf,
    modified: SystemTime,
}

#[derive(Debug)]
pub(super) struct CollectedLogs {
    pub(super) entries: Vec<BundleEntry>,
    pub(super) manifest_input: ManifestInput,
}

#[derive(Default)]
struct LogScanStats {
    skipped_entries: usize,
}

pub(super) fn collect_redacted_logs(
    log_dir: &Path,
    known_values: &KnownSensitiveValues,
) -> Result<CollectedLogs> {
    let source_exists = log_dir.is_dir();
    let mut candidates = Vec::new();
    let mut scan_stats = LogScanStats::default();
    collect_log_candidates(log_dir, 0, &mut candidates, &mut scan_stats)?;
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.modified));
    let omitted_by_limit = candidates.len().saturating_sub(MAX_LOG_FILES);
    candidates.truncate(MAX_LOG_FILES);

    let mut entries = Vec::with_capacity(candidates.len());
    let mut truncated_entries = 0_usize;
    for candidate in candidates {
        let Ok((bytes, input_truncated)) = read_tail(&candidate.path, MAX_LOG_TAIL_BYTES) else {
            scan_stats.skipped_entries += 1;
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let redacted = redact_text_with_known_values(&text, known_values);
        let mut redacted_bytes = redacted.into_bytes();
        let output_truncated = redacted_bytes.len() > MAX_REDACTED_LOG_BYTES;
        if output_truncated {
            redacted_bytes.truncate(MAX_REDACTED_LOG_BYTES);
            redacted_bytes.extend_from_slice(b"\n[TRUNCATED]\n");
        }
        if input_truncated || output_truncated {
            truncated_entries += 1;
        }
        entries.push(BundleEntry {
            path: format!("logs/log-{:02}.txt", entries.len() + 1),
            bytes: redacted_bytes,
        });
    }
    let skipped_entries = scan_stats.skipped_entries + omitted_by_limit;
    let status = if !source_exists {
        "missing"
    } else if skipped_entries > 0 || truncated_entries > 0 {
        "partial"
    } else {
        "complete"
    };
    Ok(CollectedLogs {
        manifest_input: ManifestInput {
            name: "redacted_logs".to_owned(),
            status,
            included_entries: entries.len(),
            skipped_entries,
            truncated_entries,
            note: "Counts only; source paths and names are intentionally excluded.",
        },
        entries,
    })
}

fn collect_log_candidates(
    directory: &Path,
    depth: usize,
    candidates: &mut Vec<LogCandidate>,
    stats: &mut LogScanStats,
) -> Result<()> {
    if depth > MAX_LOG_DEPTH {
        return Ok(());
    }
    let Ok(metadata) = fs::symlink_metadata(directory) else {
        return Ok(());
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        stats.skipped_entries += 1;
        return Ok(());
    }
    let Ok(entries) = fs::read_dir(directory) else {
        stats.skipped_entries += 1;
        return Ok(());
    };
    for entry in entries {
        let Ok(entry) = entry else {
            stats.skipped_entries += 1;
            continue;
        };
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            stats.skipped_entries += 1;
            continue;
        };
        if metadata.file_type().is_symlink() {
            stats.skipped_entries += 1;
            continue;
        }
        if metadata.is_dir() {
            collect_log_candidates(&path, depth + 1, candidates, stats)?;
        } else if metadata.is_file() && is_supported_log_file(&path) {
            candidates.push(LogCandidate {
                path,
                modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
    }
    Ok(())
}

fn is_supported_log_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "log" | "txt" | "jsonl" | "ndjson"
            )
        })
}

fn read_tail(path: &Path, maximum_bytes: usize) -> Result<(Vec<u8>, bool)> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    let maximum = u64::try_from(maximum_bytes).unwrap_or(u64::MAX);
    let truncated = length > maximum;
    if truncated {
        file.seek(SeekFrom::Start(length - maximum))?;
    }
    let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1_024));
    file.take(maximum).read_to_end(&mut bytes)?;
    Ok((bytes, truncated))
}

#[derive(Debug, Default)]
pub(super) struct KnownSensitiveValues {
    literals: Vec<String>,
    identifiers: Vec<String>,
}

pub(super) fn known_sensitive_values(
    paths: &AppPaths,
    config: Option<&AppConfig>,
) -> KnownSensitiveValues {
    let mut literals = BTreeSet::new();
    let mut identifiers = BTreeSet::new();
    for path in [
        &paths.config_dir,
        &paths.state_dir,
        &paths.data_dir,
        &paths.log_dir,
    ] {
        insert_path_value(&mut literals, path);
    }
    for variable in ["HOME", "USERPROFILE", "TMPDIR"] {
        if let Some(value) = std::env::var_os(variable) {
            let value = value.to_string_lossy().into_owned();
            if value.len() >= 3 {
                literals.insert(value);
            }
        }
    }
    if let Ok(executable) = std::env::current_exe() {
        insert_path_value(&mut literals, &executable);
    }
    if let Some(config) = config {
        for root in &config.allowed_roots {
            insert_path_value(&mut literals, root);
        }
        if let Some(path) = &config.browser.executable_path {
            insert_path_value(&mut literals, path);
        }
        if let Some(endpoint) = &config.browser.external_cdp_url {
            literals.insert(endpoint.as_str().to_owned());
        }
        for connector in &config.connectors {
            identifiers.insert(connector.id.clone());
            if connector.name.len() >= 3 {
                literals.insert(connector.name.clone());
            }
            if let Some(url) = &connector.public_base_url {
                literals.insert(url.as_str().to_owned());
            }
            if let Some(settings) = &connector.cloudflare_quick
                && let Some(path) = &settings.cloudflared_path
            {
                insert_path_value(&mut literals, path);
            }
            if let Some(settings) = &connector.cloudflare_named {
                for value in [&settings.tunnel_id, &settings.hostname] {
                    if value.len() >= 3 {
                        literals.insert(value.clone());
                    }
                }
                insert_path_value(&mut literals, &settings.credentials_file);
                if let Some(path) = &settings.cloudflared_path {
                    insert_path_value(&mut literals, path);
                }
            }
            if let Some(owner) = &connector.oauth_owner
                && owner.github_login.len() >= 3
            {
                literals.insert(owner.github_login.clone());
            }
            if let Some(settings) = &connector.openai_tunnel {
                for value in [&settings.tunnel_id, &settings.profile] {
                    if value.len() >= 3 {
                        literals.insert(value.clone());
                    }
                }
                if let Some(path) = &settings.tunnel_client_path {
                    insert_path_value(&mut literals, path);
                }
            }
        }
    }
    let mut literals = literals.into_iter().collect::<Vec<_>>();
    literals.sort_by_key(|value| std::cmp::Reverse(value.len()));
    let mut identifiers = identifiers.into_iter().collect::<Vec<_>>();
    identifiers.sort_by_key(|value| std::cmp::Reverse(value.len()));
    KnownSensitiveValues {
        literals,
        identifiers,
    }
}

fn insert_path_value(values: &mut BTreeSet<String>, path: &Path) {
    let value = path.to_string_lossy().into_owned();
    if value.len() >= 3 {
        values.insert(value);
    }
}

#[cfg(test)]
fn redact_text(input: &str, known_values: &[String]) -> String {
    redact_text_with_known_values(
        input,
        &KnownSensitiveValues {
            literals: known_values.to_vec(),
            identifiers: Vec::new(),
        },
    )
}

fn redact_text_with_known_values(input: &str, known_values: &KnownSensitiveValues) -> String {
    let mut text = strip_ansi(input).replace('\0', "");
    for value in &known_values.literals {
        text = text.replace(value, "[REDACTED]");
    }
    for identifier in &known_values.identifiers {
        text = replace_exact_identifier(&text, identifier);
    }
    let mut output = String::with_capacity(text.len());
    for line in text.lines() {
        output.push_str(&redact_line(line));
        output.push('\n');
        if output.len() >= MAX_REDACTED_LOG_BYTES {
            break;
        }
    }
    output
}

fn replace_exact_identifier(input: &str, identifier: &str) -> String {
    if identifier.is_empty() {
        return input.to_owned();
    }
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0_usize;
    while let Some(relative) = input[cursor..].find(identifier) {
        let start = cursor + relative;
        let end = start + identifier.len();
        let left_is_identity = input[..start]
            .bytes()
            .next_back()
            .is_some_and(is_identity_byte);
        let right_is_identity = input[end..].bytes().next().is_some_and(is_identity_byte);
        output.push_str(&input[cursor..start]);
        if left_is_identity || right_is_identity {
            output.push_str(identifier);
        } else {
            output.push_str("[REDACTED_IDENTIFIER]");
        }
        cursor = end;
    }
    output.push_str(&input[cursor..]);
    output
}

fn is_identity_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'[') {
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn redact_line(line: &str) -> String {
    let mut output = line.to_owned();
    let lower = output.to_ascii_lowercase();
    if let Some((index, marker)) = SENSITIVE_MARKERS
        .iter()
        .filter_map(|marker| lower.find(marker).map(|index| (index, *marker)))
        .min_by_key(|(index, _)| *index)
    {
        let value_start = index + marker.len();
        output.replace_range(value_start.., "[REDACTED]");
    }
    redact_tokens(&output)
}

fn redact_tokens(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    for token in line.split_inclusive(char::is_whitespace) {
        let whitespace_start = token
            .char_indices()
            .find_map(|(index, character)| character.is_whitespace().then_some(index))
            .unwrap_or(token.len());
        let (word, whitespace) = token.split_at(whitespace_start);
        output.push_str(&redact_word(word));
        output.push_str(whitespace);
    }
    output
}

fn redact_word(word: &str) -> String {
    if word.contains("://") {
        return "[URL]".to_owned();
    }
    let core = word.trim_matches(|character: char| {
        matches!(
            character,
            ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '\"' | '\''
        )
    });
    let candidate = core.rsplit_once('=').map_or(core, |(_, value)| value);
    if candidate.contains('@') && candidate.contains('.') {
        return word.replace(candidate, "[EMAIL]");
    }
    if looks_like_absolute_path(candidate) {
        return word.replace(candidate, "[PATH]");
    }
    if let Some(kind) = network_kind(candidate) {
        return word.replace(candidate, kind);
    }
    if looks_like_secret(candidate) {
        return word.replace(candidate, "[REDACTED]");
    }
    word.to_owned()
}

fn looks_like_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with('/')
        || value.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

fn network_kind(value: &str) -> Option<&'static str> {
    let unwrapped = value.trim_matches(|character| matches!(character, '[' | ']'));
    if unwrapped.parse::<IpAddr>().is_ok() {
        return Some("[IP]");
    }
    if let Some((host, port)) = unwrapped.rsplit_once(':')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && (host
            .trim_matches(|character| matches!(character, '[' | ']'))
            .parse::<IpAddr>()
            .is_ok()
            || looks_like_hostname(host))
    {
        return Some("[HOST]");
    }
    looks_like_hostname(unwrapped).then_some("[HOST]")
}

fn looks_like_hostname(value: &str) -> bool {
    if value.len() > 253 || !value.contains('.') || value.contains(['/', '\\']) {
        return false;
    }
    let mut labels = value.split('.');
    let Some(last) = labels.next_back() else {
        return false;
    };
    if last.len() < 2 || !last.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return false;
    }
    labels.chain(std::iter::once(last)).all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn looks_like_secret(value: &str) -> bool {
    if value.len() < 24 {
        return false;
    }
    let mut has_letter = false;
    let mut has_digit = false;
    for byte in value.bytes() {
        if byte.is_ascii_alphabetic() {
            has_letter = true;
        } else if byte.is_ascii_digit() {
            has_digit = true;
        } else if !matches!(byte, b'-' | b'_' | b'+' | b'/' | b'=' | b'.') {
            return false;
        }
    }
    has_letter && has_digit
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn labeled_secret_marker_strategy() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![
            "authorization: ",
            "AUTHORIZATION=",
            "client_secret: ",
            "Api_Key = ",
            "PASSWORD=",
            "refresh_token: ",
            "Token = ",
        ])
    }

    #[test]
    fn redaction_covers_labeled_urls_emails_and_high_entropy_values() {
        let input = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\n\
                     url=https://example.com/private\n\
                     email=owner@example.com\n\
                     opaque=abcdefghijklmnopqrstuvwxyz0123456789";
        let redacted = redact_text(input, &[]);
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz123456"));
        assert!(!redacted.contains("https://example.com"));
        assert!(!redacted.contains("owner@example.com"));
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(redacted.contains("[REDACTED]"));
        assert!(redacted.contains("[URL]"));
        assert!(redacted.contains("[EMAIL]"));
    }

    #[test]
    fn redaction_covers_paths_hosts_and_ip_addresses() {
        let input = r"path=/Users/alice/private host=secret.example.com ip=10.0.0.5 endpoint=127.0.0.1:47821 windows=C:\Users\Alice\private";
        let redacted = redact_text(input, &[]);
        for value in [
            "/Users/alice/private",
            "secret.example.com",
            "10.0.0.5",
            "127.0.0.1:47821",
            r"C:\Users\Alice\private",
        ] {
            assert!(!redacted.contains(value));
        }
        assert!(redacted.contains("[PATH]"));
        assert!(redacted.contains("[HOST]"));
        assert!(redacted.contains("[IP]"));
    }

    #[test]
    fn connector_identifiers_are_redacted_only_as_exact_identity_tokens() {
        let identifier = "00000000-0000-4000-8000-000000000123".to_owned();
        let input = format!(
            "connector={identifier} longer=prefix_{identifier}_suffix repeated=({identifier})"
        );
        let redacted = replace_exact_identifier(&input, &identifier);
        assert_eq!(redacted.matches("[REDACTED_IDENTIFIER]").count(), 2);
        assert!(redacted.contains(&format!("prefix_{identifier}_suffix")));
    }

    #[test]
    fn read_tail_is_bounded() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("large.log");
        fs::write(&path, vec![b'a'; MAX_LOG_TAIL_BYTES * 2])?;
        let (tail, truncated) = read_tail(&path, MAX_LOG_TAIL_BYTES)?;
        assert_eq!(tail.len(), MAX_LOG_TAIL_BYTES);
        assert!(truncated);
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn known_values_do_not_survive_ansi_or_nul_obfuscation(
            secret in "[A-Za-z][A-Za-z0-9_-]{7,31}",
            split_seed in any::<u8>(),
            prefix in "[a-z ]{0,20}",
            suffix in "[a-z ]{0,20}",
        ) {
            let split = 1 + usize::from(split_seed) % (secret.len() - 1);
            let obfuscated = format!("{}\0{}", &secret[..split], &secret[split..]);
            let input = format!(
                "{prefix}\x1b[31m{obfuscated}\x1b[0m{suffix}\nrepeated={secret}"
            );
            let redacted = redact_text(&input, std::slice::from_ref(&secret));
            prop_assert!(!redacted.contains(&secret));
            prop_assert!(!redacted.contains('\0'));
            prop_assert!(!redacted.contains("\x1b["));
            prop_assert!(redacted.matches("[REDACTED]").count() >= 2);
        }

        #[test]
        fn labeled_secret_values_are_removed_case_insensitively(
            marker in labeled_secret_marker_strategy(),
            value in "[A-Za-z][A-Za-z0-9_-]{5,18}",
            prefix in "[a-z ]{0,20}",
        ) {
            let input = format!("{prefix}{marker}{value}");
            let redacted = redact_text(&input, &[]);
            prop_assert!(!redacted.contains(&value));
            prop_assert!(redacted.contains("[REDACTED]"));
        }

        #[test]
        fn generated_urls_emails_and_paths_are_redacted(
            label in "[a-z]{1,10}",
            first in "[a-z][a-z0-9-]{0,10}",
            second in "[a-z][a-z0-9-]{0,10}",
            variant in 0_u8..4,
        ) {
            let (value, marker) = match variant {
                0 => (
                    format!("https://{first}.{second}.example/private?token=value"),
                    "[URL]",
                ),
                1 => (format!("{first}@{second}.example"), "[EMAIL]"),
                2 => (format!("/Users/{first}/{second}/private"), "[PATH]"),
                _ => (format!(r"C:\Users\{first}\{second}\private"), "[PATH]"),
            };
            let input = format!("{label}={value}");
            let redacted = redact_text(&input, &[]);
            prop_assert!(!redacted.contains(&value), "leaked {value} as {redacted}");
            prop_assert!(redacted.contains(marker));
        }

        #[test]
        fn generated_network_tokens_are_redacted(
            first in 1_u8..=254,
            second in any::<u8>(),
            third in any::<u8>(),
            fourth in any::<u8>(),
            port in 1_u16..=u16::MAX,
            host_label in "[a-z][a-z0-9-]{0,8}[a-z0-9]",
            variant in 0_u8..4,
        ) {
            let (value, marker) = match variant {
                0 => (format!("{first}.{second}.{third}.{fourth}"), "[IP]"),
                1 => (format!("[{first:x}{second:x}::{third:x}{fourth:x}]"), "[IP]"),
                2 => (format!("{host_label}.example"), "[HOST]"),
                _ => (format!("{host_label}.example:{port}"), "[HOST]"),
            };
            let input = format!("endpoint={value}");
            let redacted = redact_text(&input, &[]);
            prop_assert!(!redacted.contains(&value), "leaked {value} as {redacted}");
            prop_assert!(redacted.contains(marker));
        }
    }
}
