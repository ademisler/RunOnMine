//! Threshold-signed connector release provenance embedded in the application.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::installer::{
    ArtifactFormat, ReleaseChannel, ReleaseProvider, Sha256Digest, VerifiedArtifact,
};

const ENVELOPE_VERSION: u32 = 1;
const MANIFEST_VERSION: u32 = 1;
const SIGNATURE_THRESHOLD: usize = 2;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_PAYLOAD_BYTES: usize = 48 * 1024;
const MAX_SIGNATURES: usize = 8;
const MAX_ASSETS: usize = 16;

const GLOBAL_ROOT: TrustKey = TrustKey {
    key_id: "sha256:d74dbbf1b4ad7bdd",
    public_key_base64: "qTQWDdUsijhEO7tQCs+UR0t2d36Q57kICz2IssZu2T4=",
};
const CLOUDFLARED_ROOT: TrustKey = TrustKey {
    key_id: "sha256:d6a6730f94f7c7e8",
    public_key_base64: "83gv+/oi5Xlnv6tPdwI8q2kc38WFbNY8VPiag9O91hM=",
};
const OPENAI_ROOT: TrustKey = TrustKey {
    key_id: "sha256:ba83f17223abc580",
    public_key_base64: "1EwJsuNtrpt8jPvGUXSCyFP99cfAsTw8pFxFdGDm4JU=",
};

const CLOUDFLARED_ENVELOPE: &[u8] = include_bytes!("../provenance/cloudflared.json");
const OPENAI_ENVELOPE: &[u8] = include_bytes!("../provenance/openai-tunnel-client.json");

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedProvenanceEvidence {
    envelope: String,
}

impl SignedProvenanceEvidence {
    fn new(envelope: &[u8]) -> Result<Self> {
        Ok(Self {
            envelope: std::str::from_utf8(envelope)
                .context("signed provenance envelope is not UTF-8")?
                .to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct TrustKey {
    key_id: &'static str,
    public_key_base64: &'static str,
}

impl TrustKey {
    fn verifying_key(self) -> Result<VerifyingKey> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(self.public_key_base64)
            .context("connector provenance trust root is not valid base64")?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("connector provenance trust root has the wrong length"))?;
        let derived = format!("sha256:{}", &hex::encode(Sha256::digest(bytes))[..16]);
        if derived != self.key_id {
            bail!("connector provenance trust-root identity does not match its public key");
        }
        VerifyingKey::from_bytes(&bytes)
            .context("connector provenance trust root is not a valid Ed25519 key")
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct SignedEnvelope {
    version: u32,
    payload: String,
    signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EnvelopeSignature {
    key_id: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProvenanceManifest {
    version: u32,
    provider: ReleaseProvider,
    source_repository: String,
    source_commit: String,
    release_tag: String,
    sequence: u64,
    assets: Vec<ProvenanceAsset>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProvenanceAsset {
    asset_name: String,
    download_url: url::Url,
    sha256: String,
    size: usize,
    format: ArtifactFormat,
    archive_binary_name: Option<String>,
}

#[derive(Debug)]
struct VerifiedManifest {
    manifest: ProvenanceManifest,
    evidence: SignedProvenanceEvidence,
}

pub(crate) fn validate_embedded_catalogs() -> Result<()> {
    for provider in [
        ReleaseProvider::Cloudflared,
        ReleaseProvider::OpenAiTunnelClient,
    ] {
        let _verified = verify_envelope(provider, embedded_envelope(provider))?;
    }
    Ok(())
}

pub(crate) fn resolve_signed_release(
    provider: ReleaseProvider,
    channel: &ReleaseChannel,
) -> Result<VerifiedArtifact> {
    resolve_envelope(provider, channel, embedded_envelope(provider))
}

pub(crate) fn verify_install_provenance(
    evidence: &SignedProvenanceEvidence,
    provider: ReleaseProvider,
    release_tag: &str,
    sha256: &Sha256Digest,
) -> Result<()> {
    let artifact = resolve_envelope(
        provider,
        &ReleaseChannel::Tag(release_tag.to_owned()),
        evidence.envelope.as_bytes(),
    )?;
    if &artifact.sha256 != sha256 {
        bail!("managed binary receipt digest does not match its signed provenance");
    }
    Ok(())
}

fn resolve_envelope(
    provider: ReleaseProvider,
    channel: &ReleaseChannel,
    envelope: &[u8],
) -> Result<VerifiedArtifact> {
    let verified = verify_envelope(provider, envelope)?;
    match channel {
        ReleaseChannel::Latest => {}
        ReleaseChannel::Tag(expected) if expected == &verified.manifest.release_tag => {}
        ReleaseChannel::Tag(_) => {
            bail!("signed connector provenance does not contain the requested release tag")
        }
    }
    let selection = provider.selected_asset(&verified.manifest.release_tag)?;
    let asset = verified
        .manifest
        .assets
        .iter()
        .find(|asset| asset.asset_name == selection.name)
        .context("signed connector provenance lacks the expected platform artifact")?;
    if asset.format != selection.format
        || asset.archive_binary_name != selection.archive_binary_name
    {
        bail!("signed connector provenance has an unexpected artifact format");
    }
    VerifiedArtifact::from_verified_manifest(
        provider,
        verified.manifest.release_tag,
        asset.asset_name.clone(),
        asset.download_url.clone(),
        &asset.sha256,
        asset.size,
        asset.format,
        asset.archive_binary_name.clone(),
        Some(verified.evidence),
    )
}

fn verify_envelope(provider: ReleaseProvider, bytes: &[u8]) -> Result<VerifiedManifest> {
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
        bail!("signed connector provenance envelope is outside the permitted size");
    }
    let envelope: SignedEnvelope =
        serde_json::from_slice(bytes).context("signed connector provenance envelope is invalid")?;
    if envelope.version != ENVELOPE_VERSION {
        bail!("unsupported signed connector provenance envelope version");
    }
    if envelope.signatures.len() < SIGNATURE_THRESHOLD || envelope.signatures.len() > MAX_SIGNATURES
    {
        bail!("signed connector provenance has an invalid signature count");
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .context("signed connector provenance payload is not valid base64")?;
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        bail!("signed connector provenance payload is outside the permitted size");
    }
    let manifest: ProvenanceManifest = serde_json::from_slice(&payload)
        .context("signed connector provenance payload is invalid")?;
    validate_manifest(provider, &manifest)?;

    let roots = trust_roots(provider);
    let mut seen = BTreeSet::new();
    let mut verified = BTreeSet::new();
    for candidate in &envelope.signatures {
        if !seen.insert(candidate.key_id.as_str()) {
            bail!("signed connector provenance repeats a signature identity");
        }
        let Some(root) = roots.iter().find(|root| root.key_id == candidate.key_id) else {
            continue;
        };
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(&candidate.signature)
            .context("connector provenance signature is not valid base64")?;
        let signature = Signature::from_slice(&signature_bytes)
            .context("connector provenance signature has the wrong length")?;
        root.verifying_key()?
            .verify_strict(&payload, &signature)
            .context("connector provenance signature verification failed")?;
        verified.insert(root.key_id);
    }
    if verified.len() < SIGNATURE_THRESHOLD {
        bail!("connector provenance did not meet the independent signature threshold");
    }

    Ok(VerifiedManifest {
        manifest,
        evidence: SignedProvenanceEvidence::new(bytes)?,
    })
}

fn validate_manifest(provider: ReleaseProvider, manifest: &ProvenanceManifest) -> Result<()> {
    if manifest.version != MANIFEST_VERSION {
        bail!("unsupported connector provenance manifest version");
    }
    if manifest.provider != provider {
        bail!("connector provenance provider does not match the requested provider");
    }
    let (owner, repository) = provider.repository();
    if manifest.source_repository != format!("{owner}/{repository}") {
        bail!("connector provenance source repository is not the official provider repository");
    }
    if manifest.source_commit.len() != 40
        || !manifest
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("connector provenance source commit is invalid");
    }
    if manifest.sequence == 0 {
        bail!("connector provenance sequence must be positive");
    }
    if manifest.assets.is_empty() || manifest.assets.len() > MAX_ASSETS {
        bail!("connector provenance asset count is outside the permitted range");
    }
    let mut names = BTreeSet::new();
    for asset in &manifest.assets {
        if !names.insert(asset.asset_name.as_str()) {
            bail!("connector provenance contains duplicate asset names");
        }
    }
    Ok(())
}

fn trust_roots(provider: ReleaseProvider) -> [TrustKey; SIGNATURE_THRESHOLD] {
    match provider {
        ReleaseProvider::Cloudflared => [GLOBAL_ROOT, CLOUDFLARED_ROOT],
        ReleaseProvider::OpenAiTunnelClient => [GLOBAL_ROOT, OPENAI_ROOT],
    }
}

fn embedded_envelope(provider: ReleaseProvider) -> &'static [u8] {
    match provider {
        ReleaseProvider::Cloudflared => CLOUDFLARED_ENVELOPE,
        ReleaseProvider::OpenAiTunnelClient => OPENAI_ENVELOPE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalogs_meet_the_two_root_threshold() -> Result<()> {
        validate_embedded_catalogs()?;
        for provider in [
            ReleaseProvider::Cloudflared,
            ReleaseProvider::OpenAiTunnelClient,
        ] {
            let artifact = resolve_signed_release(provider, &ReleaseChannel::Latest)?;
            assert_eq!(artifact.provider, provider);
            assert!(artifact.provenance.is_some());
        }
        Ok(())
    }

    #[test]
    fn installed_evidence_revalidates_release_identity_and_digest() -> Result<()> {
        let artifact =
            resolve_signed_release(ReleaseProvider::Cloudflared, &ReleaseChannel::Latest)?;
        let evidence = artifact
            .provenance
            .as_ref()
            .context("signed artifact lacks provenance evidence")?;
        verify_install_provenance(
            evidence,
            artifact.provider,
            &artifact.release_tag,
            &artifact.sha256,
        )?;
        let wrong = Sha256Digest::parse(&format!("sha256:{}", "0".repeat(64)))?;
        assert!(
            verify_install_provenance(evidence, artifact.provider, &artifact.release_tag, &wrong,)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn one_signature_is_not_enough() -> Result<()> {
        let mut envelope: SignedEnvelope = serde_json::from_slice(CLOUDFLARED_ENVELOPE)?;
        envelope.signatures.truncate(1);
        let encoded = serde_json::to_vec(&envelope)?;
        assert!(verify_envelope(ReleaseProvider::Cloudflared, &encoded).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_root_does_not_satisfy_threshold() -> Result<()> {
        let mut envelope: SignedEnvelope = serde_json::from_slice(CLOUDFLARED_ENVELOPE)?;
        envelope.signatures[1].key_id = envelope.signatures[0].key_id.clone();
        envelope.signatures[1].signature = envelope.signatures[0].signature.clone();
        let encoded = serde_json::to_vec(&envelope)?;
        assert!(verify_envelope(ReleaseProvider::Cloudflared, &encoded).is_err());
        Ok(())
    }

    #[test]
    fn tampered_payload_is_rejected() -> Result<()> {
        let mut envelope: SignedEnvelope = serde_json::from_slice(CLOUDFLARED_ENVELOPE)?;
        let mut payload = base64::engine::general_purpose::STANDARD.decode(&envelope.payload)?;
        let final_byte = payload
            .last_mut()
            .context("test provenance payload is unexpectedly empty")?;
        *final_byte ^= 1;
        envelope.payload = base64::engine::general_purpose::STANDARD.encode(payload);
        let encoded = serde_json::to_vec(&envelope)?;
        assert!(verify_envelope(ReleaseProvider::Cloudflared, &encoded).is_err());
        Ok(())
    }

    #[test]
    fn provider_roots_are_not_interchangeable() {
        assert!(verify_envelope(ReleaseProvider::Cloudflared, OPENAI_ENVELOPE,).is_err());
    }
}
