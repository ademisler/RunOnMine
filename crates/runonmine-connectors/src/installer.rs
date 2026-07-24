use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use flate2::read::GzDecoder;
use reqwest::redirect::{Attempt, Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;

use crate::binary::BinaryKind;

const RELEASE_METADATA_LIMIT: usize = 4 * 1024 * 1024;
const DEFAULT_ARTIFACT_LIMIT: usize = 128 * 1024 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseProvider {
    Cloudflared,
    OpenAiTunnelClient,
}

impl ReleaseProvider {
    fn repository(self) -> (&'static str, &'static str) {
        match self {
            Self::Cloudflared => ("cloudflare", "cloudflared"),
            Self::OpenAiTunnelClient => ("openai", "tunnel-client"),
        }
    }

    fn binary_kind(self) -> BinaryKind {
        match self {
            Self::Cloudflared => BinaryKind::Cloudflared,
            Self::OpenAiTunnelClient => BinaryKind::OpenAiTunnelClient,
        }
    }

    fn selected_asset(self, tag: &str) -> Result<SelectedAsset> {
        let platform = PlatformTarget::current()?;
        match (self, platform.os, platform.architecture) {
            (Self::Cloudflared, "macos", "x86_64") => Ok(SelectedAsset::archive(
                "cloudflared-darwin-amd64.tgz",
                ArtifactFormat::TarGz,
                "cloudflared",
            )),
            (Self::Cloudflared, "macos", "aarch64") => Ok(SelectedAsset::archive(
                "cloudflared-darwin-arm64.tgz",
                ArtifactFormat::TarGz,
                "cloudflared",
            )),
            (Self::Cloudflared, "linux", "x86_64") => {
                Ok(SelectedAsset::raw("cloudflared-linux-amd64"))
            }
            (Self::Cloudflared, "linux", "aarch64") => {
                Ok(SelectedAsset::raw("cloudflared-linux-arm64"))
            }
            (Self::Cloudflared, "windows", "x86_64") => {
                Ok(SelectedAsset::raw("cloudflared-windows-amd64.exe"))
            }
            (Self::OpenAiTunnelClient, "macos", "x86_64") => Ok(SelectedAsset::archive(
                &format!("tunnel-client-{tag}-darwin-amd64.zip"),
                ArtifactFormat::Zip,
                "tunnel-client",
            )),
            (Self::OpenAiTunnelClient, "macos", "aarch64") => Ok(SelectedAsset::archive(
                &format!("tunnel-client-{tag}-darwin-arm64.zip"),
                ArtifactFormat::Zip,
                "tunnel-client",
            )),
            (Self::OpenAiTunnelClient, "linux", "x86_64") => Ok(SelectedAsset::archive(
                &format!("tunnel-client-{tag}-linux-amd64.zip"),
                ArtifactFormat::Zip,
                "tunnel-client",
            )),
            (Self::OpenAiTunnelClient, "linux", "aarch64") => Ok(SelectedAsset::archive(
                &format!("tunnel-client-{tag}-linux-arm64.zip"),
                ArtifactFormat::Zip,
                "tunnel-client",
            )),
            (Self::OpenAiTunnelClient, "windows", "x86_64") => Ok(SelectedAsset::archive(
                &format!("tunnel-client-{tag}-windows-amd64.zip"),
                ArtifactFormat::Zip,
                "tunnel-client.exe",
            )),
            _ => {
                bail!("the official provider does not publish a supported artifact for this target")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseChannel {
    Latest,
    Tag(String),
}

impl ReleaseChannel {
    fn api_url(&self, owner: &str, repository: &str) -> Result<Url> {
        let suffix = match self {
            Self::Latest => "latest".to_owned(),
            Self::Tag(tag) => {
                validate_release_tag(tag)?;
                format!("tags/{tag}")
            }
        };
        Url::parse(&format!(
            "https://api.github.com/repos/{owner}/{repository}/releases/{suffix}"
        ))
        .context("failed to construct official release API URL")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    RawExecutable,
    TarGz,
    Zip,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn parse(value: &str) -> Result<Self> {
        let encoded = value
            .strip_prefix("sha256:")
            .context("release asset is missing its sha256 digest prefix")?;
        if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("release asset has an invalid SHA-256 digest");
        }
        let bytes =
            hex::decode(encoded).context("release asset digest is not valid hexadecimal")?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("release asset digest has the wrong length"))?;
        Ok(Self(digest))
    }

    pub fn prefixed_hex(&self) -> String {
        format!("sha256:{}", hex::encode(self.0))
    }

    fn matches(&self, actual: &[u8; 32]) -> bool {
        bool::from(self.0.ct_eq(actual))
    }

    pub fn verify_file(&self, path: &Path) -> Result<bool> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("verified binary must be a regular non-symlink file");
        }
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
        let actual: [u8; 32] = digest.finalize().into();
        Ok(self.matches(&actual))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.prefixed_hex())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedArtifact {
    pub provider: ReleaseProvider,
    pub release_tag: String,
    pub asset_name: String,
    pub download_url: Url,
    pub sha256: Sha256Digest,
    pub size: usize,
    pub format: ArtifactFormat,
    pub archive_binary_name: Option<String>,
}

impl VerifiedArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn from_manifest(
        provider: ReleaseProvider,
        release_tag: String,
        asset_name: String,
        download_url: Url,
        sha256: &str,
        size: usize,
        format: ArtifactFormat,
        archive_binary_name: Option<String>,
    ) -> Result<Self> {
        validate_release_tag(&release_tag)?;
        validate_asset_url(provider, &release_tag, &asset_name, &download_url)?;
        if size == 0 || size > DEFAULT_ARTIFACT_LIMIT {
            bail!("release asset size is outside the permitted range");
        }
        match (format, archive_binary_name.as_deref()) {
            (ArtifactFormat::RawExecutable, None) => {}
            (ArtifactFormat::TarGz | ArtifactFormat::Zip, Some(name)) => {
                validate_binary_basename(name)?;
            }
            _ => bail!("release artifact format and archive binary name do not match"),
        }
        Ok(Self {
            provider,
            release_tag,
            asset_name,
            download_url,
            sha256: Sha256Digest::parse(sha256)?,
            size,
            format,
            archive_binary_name,
        })
    }

    pub fn binary_kind(&self) -> BinaryKind {
        self.provider.binary_kind()
    }
}

#[derive(Clone, Debug)]
pub struct FetchedArtifact {
    pub final_url: Url,
    pub bytes: Vec<u8>,
}

#[async_trait]
pub trait ArtifactFetcher: Send + Sync + fmt::Debug {
    async fn fetch(&self, url: &Url, maximum_bytes: usize) -> Result<FetchedArtifact>;
}

#[derive(Clone, Debug)]
pub struct ReqwestArtifactFetcher {
    client: reqwest::Client,
}

impl ReqwestArtifactFetcher {
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(Policy::custom(validate_redirect))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_mins(5))
            .user_agent(concat!("RunOnMine/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("failed to build verified download client")?;
        Ok(Self { client })
    }
}

#[async_trait]
impl ArtifactFetcher for ReqwestArtifactFetcher {
    async fn fetch(&self, url: &Url, maximum_bytes: usize) -> Result<FetchedArtifact> {
        validate_official_download_host(url)?;
        let mut response = self
            .client
            .get(url.clone())
            .header(
                "Accept",
                "application/vnd.github+json, application/octet-stream",
            )
            .send()
            .await
            .context("official download request failed")?
            .error_for_status()
            .context("official download returned an error status")?;
        validate_official_download_host(response.url())?;
        if response
            .content_length()
            .is_some_and(|length| length > maximum_bytes as u64)
        {
            bail!("official download exceeds its maximum permitted size");
        }
        let final_url = response.url().clone();
        let mut bytes = Vec::with_capacity(
            response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(maximum_bytes),
        );
        while let Some(chunk) = response.chunk().await.context("official download failed")? {
            if bytes.len().saturating_add(chunk.len()) > maximum_bytes {
                bail!("official download exceeds its maximum permitted size");
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(FetchedArtifact { final_url, bytes })
    }
}

#[derive(Clone, Debug)]
pub struct GitHubReleaseResolver {
    fetcher: Arc<dyn ArtifactFetcher>,
}

impl GitHubReleaseResolver {
    pub fn production() -> Result<Self> {
        Ok(Self {
            fetcher: Arc::new(ReqwestArtifactFetcher::new()?),
        })
    }

    pub fn with_fetcher(fetcher: Arc<dyn ArtifactFetcher>) -> Self {
        Self { fetcher }
    }

    /// Resolves a current official release without hard-coding a version or
    /// checksum. GitHub's release-asset `digest` field is mandatory.
    pub async fn resolve(
        &self,
        provider: ReleaseProvider,
        channel: &ReleaseChannel,
    ) -> Result<VerifiedArtifact> {
        let (owner, repository) = provider.repository();
        let api_url = channel.api_url(owner, repository)?;
        let response = self
            .fetcher
            .fetch(&api_url, RELEASE_METADATA_LIMIT)
            .await
            .context("failed to retrieve official release metadata")?;
        if response.final_url != api_url {
            bail!("official release metadata unexpectedly redirected");
        }
        let release: GitHubRelease = serde_json::from_slice(&response.bytes)
            .context("official release metadata is invalid")?;
        resolve_release(provider, channel, release)
    }
}

#[derive(Clone, Debug)]
pub struct BinaryInstaller {
    fetcher: Arc<dyn ArtifactFetcher>,
}

impl BinaryInstaller {
    pub fn production() -> Result<Self> {
        Ok(Self {
            fetcher: Arc::new(ReqwestArtifactFetcher::new()?),
        })
    }

    pub fn with_fetcher(fetcher: Arc<dyn ArtifactFetcher>) -> Self {
        Self { fetcher }
    }

    pub async fn install(
        &self,
        artifact: &VerifiedArtifact,
        destination: &Path,
    ) -> Result<InstallReceipt> {
        validate_destination(destination, artifact.binary_kind())?;
        let fetched = self
            .fetcher
            .fetch(&artifact.download_url, artifact.size)
            .await
            .context("failed to download verified binary artifact")?;
        validate_official_download_host(&fetched.final_url)?;
        if fetched.bytes.len() != artifact.size {
            bail!("downloaded release asset size does not match release metadata");
        }
        let actual: [u8; 32] = Sha256::digest(&fetched.bytes).into();
        if !artifact.sha256.matches(&actual) {
            bail!("downloaded release asset failed SHA-256 verification");
        }

        let parent = destination
            .parent()
            .context("binary destination has no parent directory")?;
        let archive_path = unique_temporary_path(parent, ".download")?;
        write_new_private(&archive_path, &fetched.bytes)?;
        let executable_path = unique_temporary_path(parent, ".executable")?;
        let installation = (|| -> Result<()> {
            match artifact.format {
                ArtifactFormat::RawExecutable => {
                    fs::rename(&archive_path, &executable_path)
                        .context("failed to stage verified executable")?;
                }
                ArtifactFormat::TarGz => extract_tar_gz(
                    &archive_path,
                    &executable_path,
                    artifact
                        .archive_binary_name
                        .as_deref()
                        .context("archive executable name is missing")?,
                )?,
                ArtifactFormat::Zip => extract_zip(
                    &archive_path,
                    &executable_path,
                    artifact
                        .archive_binary_name
                        .as_deref()
                        .context("archive executable name is missing")?,
                )?,
            }
            make_executable(&executable_path)?;
            fs::rename(&executable_path, destination)
                .context("failed to atomically install verified executable")?;
            Ok(())
        })();
        let _ignored = fs::remove_file(&archive_path);
        if installation.is_err() {
            let _ignored = fs::remove_file(&executable_path);
        }
        installation?;

        Ok(InstallReceipt {
            provider: artifact.provider,
            release_tag: artifact.release_tag.clone(),
            sha256: artifact.sha256.clone(),
            installed_path: destination.to_path_buf(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallReceipt {
    pub provider: ReleaseProvider,
    pub release_tag: String,
    pub sha256: Sha256Digest,
    pub installed_path: PathBuf,
}

#[derive(Deserialize)]
struct GitHubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Deserialize)]
struct GitHubAsset {
    name: String,
    size: usize,
    digest: Option<String>,
    browser_download_url: Url,
}

struct SelectedAsset {
    name: String,
    format: ArtifactFormat,
    archive_binary_name: Option<String>,
}

impl SelectedAsset {
    fn raw(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            format: ArtifactFormat::RawExecutable,
            archive_binary_name: None,
        }
    }

    fn archive(name: &str, format: ArtifactFormat, binary_name: &str) -> Self {
        Self {
            name: name.to_owned(),
            format,
            archive_binary_name: Some(binary_name.to_owned()),
        }
    }
}

struct PlatformTarget {
    os: &'static str,
    architecture: &'static str,
}

impl PlatformTarget {
    fn current() -> Result<Self> {
        let target = Self {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
        };
        if !matches!(target.os, "macos" | "linux" | "windows")
            || !matches!(target.architecture, "x86_64" | "aarch64")
        {
            bail!("external tunnel binaries are unsupported on this target");
        }
        Ok(target)
    }
}

fn resolve_release(
    provider: ReleaseProvider,
    channel: &ReleaseChannel,
    release: GitHubRelease,
) -> Result<VerifiedArtifact> {
    if release.draft {
        bail!("refusing to install a draft release");
    }
    if matches!(channel, ReleaseChannel::Latest) && release.prerelease {
        bail!("the latest stable release endpoint returned a prerelease");
    }
    if let ReleaseChannel::Tag(expected) = channel
        && &release.tag_name != expected
    {
        bail!("release metadata tag does not match the requested tag");
    }
    validate_release_tag(&release.tag_name)?;
    let selection = provider.selected_asset(&release.tag_name)?;
    let asset = release
        .assets
        .into_iter()
        .find(|asset| asset.name == selection.name)
        .context("official release does not contain the expected platform artifact")?;
    let digest = asset
        .digest
        .as_deref()
        .context("official release asset does not publish a SHA-256 digest")?;
    VerifiedArtifact::from_manifest(
        provider,
        release.tag_name,
        asset.name,
        asset.browser_download_url,
        digest,
        asset.size,
        selection.format,
        selection.archive_binary_name,
    )
}

fn validate_release_tag(tag: &str) -> Result<()> {
    if tag.is_empty()
        || tag.len() > 64
        || !tag.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
    {
        bail!("release tag contains unsupported characters");
    }
    Ok(())
}

fn validate_asset_url(
    provider: ReleaseProvider,
    tag: &str,
    asset_name: &str,
    url: &Url,
) -> Result<()> {
    let (owner, repository) = provider.repository();
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("release asset URL is not an official GitHub HTTPS URL");
    }
    let expected_path = format!("/{owner}/{repository}/releases/download/{tag}/{asset_name}");
    if url.path() != expected_path {
        bail!("release asset URL does not match the official provider repository");
    }
    Ok(())
}

fn validate_official_download_host(url: &Url) -> Result<()> {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        bail!("verified downloads require credential-free HTTPS URLs");
    }
    let Some(host) = url.host_str() else {
        bail!("verified download URL has no host");
    };
    if !matches!(
        host,
        "api.github.com" | "github.com" | "release-assets.githubusercontent.com"
    ) {
        bail!("verified download redirected outside official GitHub hosts");
    }
    Ok(())
}

fn validate_redirect(attempt: Attempt<'_>) -> reqwest::redirect::Action {
    if attempt.previous().len() >= 5 {
        return attempt.error("too many official download redirects");
    }
    if validate_official_download_host(attempt.url()).is_err() {
        return attempt.error("official download redirected to an untrusted host");
    }
    attempt.follow()
}

fn validate_destination(destination: &Path, kind: BinaryKind) -> Result<()> {
    if !destination.is_absolute() {
        bail!("managed binary destination must use an absolute path");
    }
    if destination.exists() {
        bail!("managed binary destination already exists");
    }
    let expected_name = kind.executable_name();
    if destination.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
        bail!("managed binary destination has an unexpected filename");
    }
    let parent = destination
        .parent()
        .context("managed binary destination has no parent directory")?;
    let metadata = fs::symlink_metadata(parent)
        .context("managed binary destination directory does not exist")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed binary destination directory must be a real directory");
    }
    Ok(())
}

fn unique_temporary_path(parent: &Path, suffix: &str) -> Result<PathBuf> {
    for _ in 0..128 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".runonmine-{}-{counter}{suffix}",
            std::process::id()
        ));
        if !path.exists() {
            return Ok(path);
        }
    }
    bail!("failed to allocate a unique installation staging path")
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("failed to create private installation staging file")?;
    file.write_all(bytes)
        .context("failed to write installation staging file")?;
    file.sync_all()
        .context("failed to sync installation staging file")?;
    Ok(())
}

fn create_new_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    options
        .open(path)
        .context("failed to create extracted executable")
}

fn extract_tar_gz(archive_path: &Path, destination: &Path, expected_name: &str) -> Result<()> {
    let archive_file = File::open(archive_path).context("failed to open verified tar archive")?;
    let mut archive = tar::Archive::new(GzDecoder::new(archive_file));
    let mut found = false;
    for entry in archive
        .entries()
        .context("verified tar archive is invalid")?
    {
        let mut entry = entry.context("verified tar archive entry is invalid")?;
        let path = entry.path().context("verified tar path is invalid")?;
        let matches = path.file_name().and_then(|name| name.to_str()) == Some(expected_name);
        if !matches {
            continue;
        }
        if found || !entry.header().entry_type().is_file() {
            bail!("verified tar archive has an ambiguous executable entry");
        }
        let mut output = create_new_private(destination)?;
        copy_capped(&mut entry, &mut output, DEFAULT_ARTIFACT_LIMIT)?;
        output
            .sync_all()
            .context("failed to sync extracted executable")?;
        found = true;
    }
    if !found {
        bail!("verified tar archive does not contain the expected executable");
    }
    Ok(())
}

fn extract_zip(archive_path: &Path, destination: &Path, expected_name: &str) -> Result<()> {
    let archive_file = File::open(archive_path).context("failed to open verified zip archive")?;
    let mut archive =
        zip::ZipArchive::new(archive_file).context("verified zip archive is invalid")?;
    let mut found = false;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .context("verified zip archive entry is invalid")?;
        let Some(path) = entry.enclosed_name() else {
            bail!("verified zip archive contains an unsafe path");
        };
        if entry.unix_mode().is_some_and(|mode| {
            let file_type = mode & 0o170_000;
            file_type != 0 && file_type != 0o100_000
        }) {
            bail!("verified zip archive contains a non-regular executable entry");
        }
        let matches = path.file_name().and_then(|name| name.to_str()) == Some(expected_name);
        if !matches {
            continue;
        }
        if found || !entry.is_file() {
            bail!("verified zip archive has an ambiguous executable entry");
        }
        let mut output = create_new_private(destination)?;
        copy_capped(&mut entry, &mut output, DEFAULT_ARTIFACT_LIMIT)?;
        output
            .sync_all()
            .context("failed to sync extracted executable")?;
        found = true;
    }
    if !found {
        bail!("verified zip archive does not contain the expected executable");
    }
    Ok(())
}

fn copy_capped(reader: &mut impl Read, writer: &mut impl Write, limit: usize) -> Result<()> {
    let mut limited = reader.take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1));
    let copied =
        std::io::copy(&mut limited, writer).context("failed to extract verified executable")?;
    if copied > u64::try_from(limit).unwrap_or(u64::MAX) {
        bail!("extracted executable exceeds the permitted size");
    }
    Ok(())
}

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .context("failed to set executable permissions")?;
    }
    Ok(())
}

fn validate_binary_basename(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        bail!("archive executable name must be a safe basename");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[derive(Debug)]
    struct StaticFetcher {
        final_url: Url,
        bytes: Vec<u8>,
    }

    #[async_trait]
    impl ArtifactFetcher for StaticFetcher {
        async fn fetch(&self, _url: &Url, maximum_bytes: usize) -> Result<FetchedArtifact> {
            if self.bytes.len() > maximum_bytes {
                bail!("test response is too large");
            }
            Ok(FetchedArtifact {
                final_url: self.final_url.clone(),
                bytes: self.bytes.clone(),
            })
        }
    }

    #[test]
    fn checksum_requires_a_real_sha256_digest() {
        assert!(Sha256Digest::parse("").is_err());
        assert!(Sha256Digest::parse("sha256:abc").is_err());
        assert!(Sha256Digest::parse(&format!("sha256:{}", "0".repeat(64))).is_ok());
    }

    #[test]
    fn resolver_refuses_metadata_without_digest() -> Result<()> {
        let provider = ReleaseProvider::Cloudflared;
        let selection = provider.selected_asset("2026.7.2")?;
        let release = GitHubRelease {
            tag_name: "2026.7.2".to_owned(),
            draft: false,
            prerelease: false,
            assets: vec![GitHubAsset {
                name: selection.name.clone(),
                size: 10,
                digest: None,
                browser_download_url: Url::parse(&format!(
                    "https://github.com/cloudflare/cloudflared/releases/download/2026.7.2/{}",
                    selection.name
                ))?,
            }],
        };
        assert!(resolve_release(provider, &ReleaseChannel::Latest, release).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn raw_install_verifies_digest_and_uses_atomic_destination() -> Result<()> {
        let bytes = b"verified executable bytes".to_vec();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        let url = Url::parse(
            "https://github.com/cloudflare/cloudflared/releases/download/2026.7.2/cloudflared-linux-amd64",
        )?;
        let artifact = VerifiedArtifact::from_manifest(
            ReleaseProvider::Cloudflared,
            "2026.7.2".to_owned(),
            "cloudflared-linux-amd64".to_owned(),
            url.clone(),
            &digest,
            bytes.len(),
            ArtifactFormat::RawExecutable,
            None,
        )?;
        let directory = tempdir()?;
        let destination = directory
            .path()
            .join(BinaryKind::Cloudflared.executable_name());
        let installer = BinaryInstaller::with_fetcher(Arc::new(StaticFetcher {
            final_url: url,
            bytes: bytes.clone(),
        }));
        let receipt = installer.install(&artifact, &destination).await?;
        assert_eq!(fs::read(&destination)?, bytes);
        assert_eq!(receipt.installed_path, destination);
        Ok(())
    }

    #[tokio::test]
    async fn installer_rejects_checksum_mismatch() -> Result<()> {
        let bytes = b"different bytes".to_vec();
        let url = Url::parse(
            "https://github.com/cloudflare/cloudflared/releases/download/2026.7.2/cloudflared-linux-amd64",
        )?;
        let artifact = VerifiedArtifact::from_manifest(
            ReleaseProvider::Cloudflared,
            "2026.7.2".to_owned(),
            "cloudflared-linux-amd64".to_owned(),
            url.clone(),
            &format!("sha256:{}", "0".repeat(64)),
            bytes.len(),
            ArtifactFormat::RawExecutable,
            None,
        )?;
        let directory = tempdir()?;
        let destination = directory
            .path()
            .join(BinaryKind::Cloudflared.executable_name());
        let installer = BinaryInstaller::with_fetcher(Arc::new(StaticFetcher {
            final_url: url,
            bytes,
        }));
        assert!(installer.install(&artifact, &destination).await.is_err());
        assert!(!destination.exists());
        Ok(())
    }
    #[test]
    fn persisted_digest_detects_binary_tampering() -> Result<()> {
        let directory = tempdir()?;
        let binary = directory.path().join("managed-binary");
        let original = b"trusted bytes";
        fs::write(&binary, original)?;
        let digest =
            Sha256Digest::parse(&format!("sha256:{}", hex::encode(Sha256::digest(original))))?;
        assert!(digest.verify_file(&binary)?);
        fs::write(&binary, b"tampered bytes")?;
        assert!(!digest.verify_file(&binary)?);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn persisted_digest_rejects_symlinked_binary() -> Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempdir()?;
        let target = directory.path().join("target");
        fs::write(&target, b"trusted bytes")?;
        let link = directory.path().join("link");
        symlink(&target, &link)?;
        let digest = Sha256Digest::parse(&format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"trusted bytes"))
        ))?;
        assert!(digest.verify_file(&link).is_err());
        Ok(())
    }
}
