use std::path::{Path, PathBuf};

use anyhow::Result;
use runonmine_core::filesystem::ScopedFilesystem;
use runonmine_core::{PolicyMode, ResourceContext};
use serde::Serialize;
use url::Url;

#[derive(Debug)]
pub(super) enum OwnedPolicyResource {
    None,
    Filesystem(PathBuf),
    Browser(Url),
    Executable(PathBuf),
    Command(String),
}

impl OwnedPolicyResource {
    fn as_context(&self) -> ResourceContext<'_> {
        match self {
            Self::None => ResourceContext::None,
            Self::Filesystem(path) => ResourceContext::Filesystem(path),
            Self::Browser(url) => ResourceContext::Browser(url),
            Self::Executable(path) => ResourceContext::Executable(path),
            Self::Command(command) => ResourceContext::Command(command),
        }
    }
}

#[derive(Debug)]
pub(super) struct OwnedPolicyResources(Vec<OwnedPolicyResource>);

impl OwnedPolicyResources {
    pub(super) fn contexts(&self) -> impl Iterator<Item = ResourceContext<'_>> + '_ {
        self.0.iter().map(OwnedPolicyResource::as_context)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PreApprovalDecision {
    Allow,
    Deny,
    Ask,
}

pub(super) fn pre_approval_decision(
    modes: impl IntoIterator<Item = PolicyMode>,
    grant_allows: bool,
) -> PreApprovalDecision {
    let mut combined = PolicyMode::Allow;
    for mode in modes {
        match mode {
            PolicyMode::Deny => return PreApprovalDecision::Deny,
            PolicyMode::Ask => combined = PolicyMode::Ask,
            PolicyMode::Allow => {}
        }
    }
    if grant_allows || combined == PolicyMode::Allow {
        PreApprovalDecision::Allow
    } else {
        PreApprovalDecision::Ask
    }
}

pub(super) fn policy_resources<T: Serialize>(
    tool_name: &str,
    arguments: &T,
    filesystem: &ScopedFilesystem,
) -> Result<OwnedPolicyResources> {
    let value = serde_json::to_value(arguments)?;
    let string = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
    let resources = if tool_name == "fs_move" {
        [string("from"), string("to")]
            .into_iter()
            .flatten()
            .map(|path| {
                filesystem
                    .resolve_policy_path(Path::new(path))
                    .map(OwnedPolicyResource::Filesystem)
            })
            .collect::<Result<Vec<_>>>()?
    } else if tool_name.starts_with("fs_") {
        string("path")
            .or_else(|| string("root"))
            .or_else(|| string("from"))
            .map(|path| {
                filesystem
                    .resolve_policy_path(Path::new(path))
                    .map(|path| vec![OwnedPolicyResource::Filesystem(path)])
            })
            .transpose()?
            .unwrap_or_default()
    } else if tool_name.starts_with("browser_") {
        string("url")
            .map(Url::parse)
            .transpose()?
            .map(|url| vec![OwnedPolicyResource::Browser(url)])
            .unwrap_or_default()
    } else if matches!(tool_name, "shell_exec" | "admin_exec") {
        if let Some(command) = string("command") {
            vec![OwnedPolicyResource::Command(command.to_owned())]
        } else if let Some(program) = string("program") {
            vec![OwnedPolicyResource::Executable(PathBuf::from(program))]
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    Ok(OwnedPolicyResources(if resources.is_empty() {
        vec![OwnedPolicyResource::None]
    } else {
        resources
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn explicit_deny_wins_over_an_exact_grant() {
        assert_eq!(
            pre_approval_decision([PolicyMode::Deny], true),
            PreApprovalDecision::Deny
        );
    }

    #[test]
    fn exact_grant_satisfies_an_ask_but_not_a_deny() {
        assert_eq!(
            pre_approval_decision([PolicyMode::Ask], true),
            PreApprovalDecision::Allow
        );
        assert_eq!(
            pre_approval_decision([PolicyMode::Ask], false),
            PreApprovalDecision::Ask
        );
    }

    #[test]
    fn filesystem_move_authorizes_both_source_and_destination() -> Result<()> {
        let root = tempfile::tempdir()?;
        let filesystem = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let resources = policy_resources(
            "fs_move",
            &json!({"from": "source", "to": "restricted/target"}),
            &filesystem,
        )?;
        let paths = resources
            .contexts()
            .filter_map(|resource| match resource {
                ResourceContext::Filesystem(path) => Some(path.to_path_buf()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                root.path().join("source"),
                root.path().join("restricted/target")
            ]
        );
        Ok(())
    }

    #[test]
    fn relative_filesystem_resource_uses_selected_root_identity() -> Result<()> {
        let root = tempfile::tempdir()?;
        let filesystem = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let resources =
            policy_resources("fs_read", &json!({"path": "private/file.txt"}), &filesystem)?;
        let paths = resources
            .contexts()
            .filter_map(|resource| match resource {
                ResourceContext::Filesystem(path) => Some(path.to_path_buf()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(paths, vec![root.path().join("private/file.txt")]);
        Ok(())
    }
}
