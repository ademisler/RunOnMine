use std::fmt;

use base64::Engine;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{OAuthError, StoreError};

/// Domain separators for persisted one-way hashes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashPurpose {
    AuthorizationCode,
    AccessToken,
    RefreshToken,
    GitHubState,
    ConsentCsrf,
    RegistrationAccess,
    RegistrationSource,
}

impl HashPurpose {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::AuthorizationCode => b"runonmine/oauth/authorization-code/v1\0",
            Self::AccessToken => b"runonmine/oauth/access-token/v1\0",
            Self::RefreshToken => b"runonmine/oauth/refresh-token/v1\0",
            Self::GitHubState => b"runonmine/oauth/github-state/v1\0",
            Self::ConsentCsrf => b"runonmine/oauth/consent-csrf/v1\0",
            Self::RegistrationAccess => b"runonmine/oauth/registration-access/v1\0",
            Self::RegistrationSource => b"runonmine/oauth/registration-source/v1\0",
        }
    }
}

/// A fixed-size keyed digest safe to persist. It never contains a raw token.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecretHash([u8; 32]);

impl SecretHash {
    pub(crate) fn from_slice(value: &[u8]) -> Result<Self, StoreError> {
        let bytes: [u8; 32] = value
            .try_into()
            .map_err(|_| StoreError::Corrupt("invalid secret hash length"))?;
        Ok(Self(bytes))
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }

    pub(crate) fn storage_key(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl fmt::Debug for SecretHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretHash([REDACTED])")
    }
}

/// Keyed hashing context. The key must be loaded from a platform secret store.
#[derive(Clone)]
pub struct TokenHasher {
    key: [u8; 32],
}

impl TokenHasher {
    pub fn new(key: [u8; 32]) -> Result<Self, OAuthError> {
        if key.iter().all(|byte| *byte == 0) {
            return Err(OAuthError::configuration());
        }
        Ok(Self { key })
    }

    pub fn generate() -> Result<Self, OAuthError> {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| OAuthError::temporarily_unavailable())?;
        Self::new(key)
    }

    #[must_use]
    pub fn hash(&self, purpose: HashPurpose, raw: &str) -> SecretHash {
        let mut input = Vec::with_capacity(purpose.label().len() + raw.len());
        input.extend_from_slice(purpose.label());
        input.extend_from_slice(raw.as_bytes());
        SecretHash(*blake3::keyed_hash(&self.key, &input).as_bytes())
    }
}

impl fmt::Debug for TokenHasher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenHasher([REDACTED])")
    }
}

pub fn generate_secret() -> Result<SecretString, OAuthError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| OAuthError::temporarily_unavailable())?;
    Ok(SecretString::from(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
    ))
}

pub(crate) fn validate_pkce_challenge(value: &str) -> bool {
    (43..=128).contains(&value.len()) && value.bytes().all(is_unreserved)
}

pub(crate) fn verify_pkce(verifier: &str, expected_challenge: &str) -> bool {
    if !(43..=128).contains(&verifier.len()) || !verifier.bytes().all(is_unreserved) {
        return false;
    }
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    challenge
        .as_bytes()
        .ct_eq(expected_challenge.as_bytes())
        .into()
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_rfc_7636_s256_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(verifier, challenge));
        assert!(!verify_pkce("wrong", challenge));
    }

    #[test]
    fn domain_separation_changes_hashes() {
        let hasher = TokenHasher::new([7_u8; 32]);
        assert!(hasher.is_ok());
        let hasher = hasher.unwrap_or_else(|_| unreachable!());
        assert_ne!(
            hasher.hash(HashPurpose::AccessToken, "same"),
            hasher.hash(HashPurpose::RefreshToken, "same")
        );
    }
}
