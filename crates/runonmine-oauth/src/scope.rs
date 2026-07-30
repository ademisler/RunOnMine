use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::OAuthError;

/// Scopes understood by the `RunOnMine` authorization server.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Scope {
    MachineRead,
    FilesRead,
    FilesWrite,
    ShellExec,
    BrowserRead,
    BrowserAct,
    DesktopControl,
    AdminExec,
}

impl Scope {
    pub const ALL: [Self; 8] = [
        Self::MachineRead,
        Self::FilesRead,
        Self::FilesWrite,
        Self::ShellExec,
        Self::BrowserRead,
        Self::BrowserAct,
        Self::DesktopControl,
        Self::AdminExec,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachineRead => "machine:read",
            Self::FilesRead => "files:read",
            Self::FilesWrite => "files:write",
            Self::ShellExec => "shell:exec",
            Self::BrowserRead => "browser:read",
            Self::BrowserAct => "browser:act",
            Self::DesktopControl => "desktop:control",
            Self::AdminExec => "admin:exec",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Scope {
    type Err = OAuthError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "machine:read" => Ok(Self::MachineRead),
            "files:read" => Ok(Self::FilesRead),
            "files:write" => Ok(Self::FilesWrite),
            "shell:exec" => Ok(Self::ShellExec),
            "browser:read" => Ok(Self::BrowserRead),
            "browser:act" => Ok(Self::BrowserAct),
            "desktop:control" => Ok(Self::DesktopControl),
            "admin:exec" => Ok(Self::AdminExec),
            _ => Err(OAuthError::invalid_scope()),
        }
    }
}

/// A canonical, de-duplicated set of OAuth scopes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScopeSet(BTreeSet<Scope>);

impl ScopeSet {
    #[must_use]
    pub fn all() -> Self {
        Self(Scope::ALL.into_iter().collect())
    }

    #[must_use]
    pub fn machine_read() -> Self {
        Self(BTreeSet::from([Scope::MachineRead]))
    }

    /// Least-privilege scope set for dynamic clients that omit `scope`.
    #[must_use]
    pub fn dynamic_registration_default() -> Self {
        Self::machine_read()
    }

    pub fn parse(value: &str) -> Result<Self, OAuthError> {
        if value.len() > 2_048 {
            return Err(OAuthError::invalid_scope());
        }
        value
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<BTreeSet<_>, _>>()
            .map(Self)
    }

    #[must_use]
    pub fn contains(&self, scope: Scope) -> bool {
        self.0.contains(&scope)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }

    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self(self.0.intersection(&other.0).copied().collect())
    }

    pub fn iter(&self) -> impl Iterator<Item = Scope> + '_ {
        self.0.iter().copied()
    }

    #[must_use]
    pub fn to_space_delimited(&self) -> String {
        self.iter().map(Scope::as_str).collect::<Vec<_>>().join(" ")
    }

    /// Applies the local policy ceiling to a token's scopes.
    #[must_use]
    pub fn constrained_by(&self, local_policy: &Self) -> Self {
        self.intersection(local_policy)
    }
}

impl FromIterator<Scope> for ScopeSet {
    fn from_iter<T: IntoIterator<Item = Scope>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl Serialize for ScopeSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_space_delimited())
    }
}

impl<'de> Deserialize<'de> for ScopeSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_scopes_and_rejects_unknown_values() {
        let parsed = ScopeSet::parse("files:read machine:read files:read");
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap_or_default();
        assert_eq!(parsed.to_space_delimited(), "machine:read files:read");
        assert!(ScopeSet::parse("files:read root:everything").is_err());
    }

    #[test]
    fn dynamic_registration_default_is_read_only_machine_metadata() {
        let default = ScopeSet::dynamic_registration_default();
        assert_eq!(default.to_space_delimited(), "machine:read");
        assert!(default.contains(Scope::MachineRead));
        assert!(!default.contains(Scope::FilesRead));
        assert!(!default.contains(Scope::ShellExec));
        assert!(!default.contains(Scope::AdminExec));
    }

    #[test]
    fn local_policy_can_only_reduce_token_scope() {
        let token = ScopeSet::parse("files:read files:write shell:exec").unwrap_or_default();
        let local = ScopeSet::parse("files:read shell:exec admin:exec").unwrap_or_default();
        assert_eq!(
            token.constrained_by(&local).to_space_delimited(),
            "files:read shell:exec"
        );
    }
}
