use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use runonmine_core::filesystem::ScopedFilesystem;
use runonmine_core::{PolicyMode, ResourceContext};
use runonmine_platform::helper::canonical_program_identity;
use serde::Serialize;
use url::Url;

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub(super) struct OwnedPolicyResources(Vec<OwnedPolicyResource>);

impl OwnedPolicyResources {
    pub(super) fn browser(url: Url) -> Self {
        Self(vec![OwnedPolicyResource::Browser(url)])
    }

    pub(super) fn shell(command: String, cwd: PathBuf) -> Self {
        Self(vec![
            OwnedPolicyResource::Command(command),
            OwnedPolicyResource::Filesystem(cwd),
        ])
    }

    pub(super) fn contexts(&self) -> impl Iterator<Item = ResourceContext<'_>> + '_ {
        self.0.iter().map(OwnedPolicyResource::as_context)
    }

    pub(super) fn authorization_hash(&self, arguments: &impl Serialize) -> Result<String> {
        let identities = self
            .0
            .iter()
            .map(policy_resource_identity)
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&(arguments, identities))
            .context("authorization identity serialization failed")?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"runonmine.authorization-with-resources.v1\0");
        hasher.update(&bytes);
        Ok(hasher.finalize().to_hex().to_string())
    }
}

fn policy_resource_identity(resource: &OwnedPolicyResource) -> String {
    match resource {
        OwnedPolicyResource::None => "none".to_owned(),
        OwnedPolicyResource::Filesystem(path) => format!("filesystem:{}", path.to_string_lossy()),
        OwnedPolicyResource::Browser(url) => format!("browser:{}", browser_policy_origin(url)),
        OwnedPolicyResource::Executable(path) => format!("executable:{}", path.to_string_lossy()),
        OwnedPolicyResource::Command(command) => format!("command:{command}"),
    }
}

pub(super) fn browser_policy_origin(url: &Url) -> String {
    if matches!(url.scheme(), "http" | "https") {
        url.origin().ascii_serialization()
    } else {
        url.as_str().to_owned()
    }
}

pub(super) fn same_browser_policy_origin(left: &Url, right: &Url) -> bool {
    browser_policy_origin(left) == browser_policy_origin(right)
}

pub(super) fn canonical_shell_working_directory(cwd: Option<&Path>) -> Result<PathBuf> {
    let requested = match cwd {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let canonical = requested.canonicalize().with_context(|| {
        format!(
            "shell working directory does not exist or cannot be resolved: {}",
            requested.display()
        )
    })?;
    if !canonical.is_dir() {
        anyhow::bail!("shell working directory is not a directory");
    }
    Ok(canonical)
}

pub(super) fn browser_authorization_arguments(
    arguments: &impl Serialize,
    current_url: &Url,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(arguments)?;
    let object = value
        .as_object_mut()
        .context("browser tool arguments must serialize as an object")?;
    object.insert(
        "current_origin".to_owned(),
        serde_json::Value::String(browser_policy_origin(current_url)),
    );
    Ok(value)
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
    } else if tool_name == "shell_exec" {
        let command = string("command").unwrap_or_default().to_owned();
        let cwd = canonical_shell_working_directory(string("cwd").map(Path::new))?;
        vec![
            OwnedPolicyResource::Command(command),
            OwnedPolicyResource::Filesystem(cwd),
        ]
    } else if tool_name == "admin_exec" {
        string("program")
            .map(|program| {
                canonical_program_identity(Path::new(program))
                    .map(|path| vec![OwnedPolicyResource::Executable(path)])
            })
            .transpose()?
            .unwrap_or_default()
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
        let selected_root = filesystem
            .roots()
            .into_iter()
            .next()
            .context("selected filesystem root is missing")?;
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
                selected_root.join("source"),
                selected_root.join("restricted/target")
            ]
        );
        Ok(())
    }

    #[test]
    fn relative_filesystem_resource_uses_selected_root_identity() -> Result<()> {
        let root = tempfile::tempdir()?;
        let filesystem = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let selected_root = filesystem
            .roots()
            .into_iter()
            .next()
            .context("selected filesystem root is missing")?;
        let resources =
            policy_resources("fs_read", &json!({"path": "private/file.txt"}), &filesystem)?;
        let paths = resources
            .contexts()
            .filter_map(|resource| match resource {
                ResourceContext::Filesystem(path) => Some(path.to_path_buf()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(paths, vec![selected_root.join("private/file.txt")]);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn normal_windows_absolute_resource_matches_verbatim_selected_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let canonical = root.path().canonicalize()?;
        let canonical_text = canonical.to_string_lossy();
        let normal = canonical_text
            .strip_prefix("\\\\?\\")
            .context("Windows canonical path did not use a verbatim prefix")?;
        let target = PathBuf::from(normal).join("approved.txt");
        let filesystem = ScopedFilesystem::new(std::slice::from_ref(&canonical))?;
        let resources = policy_resources("fs_write", &json!({"path": target}), &filesystem)?;
        let paths = resources
            .contexts()
            .filter_map(|resource| match resource {
                ResourceContext::Filesystem(path) => Some(path.to_path_buf()),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(paths, vec![canonical.join("approved.txt")]);
        Ok(())
    }

    #[test]
    fn shell_working_directory_is_canonical_and_bound_to_the_grant_hash() -> Result<()> {
        let root = tempfile::tempdir()?;
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested)?;
        let equivalent = nested.join("..");
        let other = tempfile::tempdir()?;
        let command = "printf ok".to_owned();

        let canonical = canonical_shell_working_directory(Some(&equivalent))?;
        assert_eq!(canonical, root.path().canonicalize()?);
        let first_arguments = json!({
            "command": command,
            "cwd": canonical,
            "timeout_seconds": 30
        });
        let first_resources =
            OwnedPolicyResources::shell("printf ok".to_owned(), root.path().canonicalize()?);
        let same_arguments = json!({
            "command": "printf ok",
            "cwd": root.path().canonicalize()?,
            "timeout_seconds": 30
        });
        let same_resources =
            OwnedPolicyResources::shell("printf ok".to_owned(), root.path().canonicalize()?);
        let other_arguments = json!({
            "command": "printf ok",
            "cwd": other.path().canonicalize()?,
            "timeout_seconds": 30
        });
        let other_resources =
            OwnedPolicyResources::shell("printf ok".to_owned(), other.path().canonicalize()?);

        assert_eq!(
            first_resources.authorization_hash(&first_arguments)?,
            same_resources.authorization_hash(&same_arguments)?
        );
        assert_ne!(
            first_resources.authorization_hash(&first_arguments)?,
            other_resources.authorization_hash(&other_arguments)?
        );
        Ok(())
    }

    #[test]
    fn shell_working_directory_must_exist_and_be_a_directory() -> Result<()> {
        let root = tempfile::tempdir()?;
        let file = root.path().join("file");
        std::fs::write(&file, b"not a directory")?;
        assert!(canonical_shell_working_directory(Some(&file)).is_err());
        assert!(canonical_shell_working_directory(Some(&root.path().join("missing"))).is_err());
        Ok(())
    }

    #[test]
    fn shell_cwd_filesystem_rule_is_evaluated_with_the_command_rule() -> Result<()> {
        use runonmine_core::{
            Capability, ConnectorConfig, PolicyContext, PolicyEngine, PolicyMode, PolicyRule,
            PrincipalContext, PrincipalMatcher, ResourceMatcher,
        };

        let root = tempfile::tempdir()?;
        let canonical = root.path().canonicalize()?;
        let resources = OwnedPolicyResources::shell("cargo test".to_owned(), canonical.clone());
        let mut connector = ConnectorConfig::local_default();
        connector.policy_rules.push(PolicyRule {
            mode: PolicyMode::Deny,
            principal: PrincipalMatcher::Any,
            resource: ResourceMatcher::FilesystemPrefix { path: canonical },
            tool: Some("shell_exec".to_owned()),
            capability: Some(Capability::ShellExec),
        });
        let modes = resources
            .contexts()
            .map(|resource| {
                PolicyEngine
                    .evaluate_context(
                        &connector,
                        "shell_exec",
                        Capability::ShellExec,
                        &PolicyContext {
                            principal: PrincipalContext::Local,
                            resource,
                        },
                    )
                    .mode
            })
            .collect::<Vec<_>>();
        assert!(modes.contains(&PolicyMode::Deny));
        assert_eq!(
            pre_approval_decision(modes, false),
            PreApprovalDecision::Deny
        );
        Ok(())
    }

    #[test]
    fn current_browser_resources_are_origin_bound_and_never_none() -> Result<()> {
        let first = Url::parse("https://example.com/path?query=one")?;
        let same_origin = Url::parse("https://example.com/other")?;
        let other_origin = Url::parse("https://other.example/path")?;
        let arguments = json!({"selector": "#submit"});

        let first_resources = OwnedPolicyResources::browser(first.clone());
        assert!(matches!(
            first_resources.contexts().next(),
            Some(ResourceContext::Browser(url)) if url == &first
        ));
        let first_arguments = browser_authorization_arguments(&arguments, &first)?;
        let same_arguments = browser_authorization_arguments(&arguments, &same_origin)?;
        let other_arguments = browser_authorization_arguments(&arguments, &other_origin)?;
        let first_hash = first_resources.authorization_hash(&first_arguments)?;
        let same_hash =
            OwnedPolicyResources::browser(same_origin).authorization_hash(&same_arguments)?;
        let other_hash =
            OwnedPolicyResources::browser(other_origin).authorization_hash(&other_arguments)?;

        assert_eq!(first_arguments["current_origin"], "https://example.com");
        assert_eq!(first_hash, same_hash);
        assert_ne!(first_hash, other_hash);
        Ok(())
    }

    #[test]
    fn opaque_browser_pages_use_their_exact_policy_identity() -> Result<()> {
        let blank = Url::parse("about:blank")?;
        let data = Url::parse("data:text/plain,hello")?;
        assert_eq!(browser_policy_origin(&blank), "about:blank");
        assert!(!same_browser_policy_origin(&blank, &data));
        Ok(())
    }

    #[test]
    fn browser_origin_deny_is_evaluated_for_current_page_actions() -> Result<()> {
        use runonmine_core::{
            Capability, ConnectorConfig, PolicyContext, PolicyEngine, PolicyMode, PolicyRule,
            PrincipalContext, PrincipalMatcher, ResourceMatcher,
        };

        let origin = Url::parse("https://denied.example/")?;
        let page = Url::parse("https://denied.example/account")?;
        let mut connector = ConnectorConfig::local_default();
        connector.policy_rules.push(PolicyRule {
            mode: PolicyMode::Deny,
            principal: PrincipalMatcher::Any,
            resource: ResourceMatcher::BrowserOrigin { origin },
            tool: Some("browser_click".to_owned()),
            capability: Some(Capability::BrowserAct),
        });
        let resources = OwnedPolicyResources::browser(page);
        let decisions = resources
            .contexts()
            .map(|resource| {
                PolicyEngine.evaluate_context(
                    &connector,
                    "browser_click",
                    Capability::BrowserAct,
                    &PolicyContext {
                        principal: PrincipalContext::Local,
                        resource,
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].mode, PolicyMode::Deny);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn alternate_admin_path_uses_helper_canonical_policy_identity() -> Result<()> {
        use runonmine_core::{
            Capability, ConnectorConfig, PolicyContext, PolicyEngine, PolicyMode, PolicyRule,
            PrincipalContext, PrincipalMatcher, ResourceMatcher,
        };

        let filesystem = ScopedFilesystem::new(&[])?;
        let resources = policy_resources(
            "admin_exec",
            &json!({"program": "/usr/bin/../bin/id", "args": []}),
            &filesystem,
        )?;
        let canonical = canonical_program_identity(Path::new("/usr/bin/id"))?;
        assert!(matches!(
            resources.contexts().next(),
            Some(ResourceContext::Executable(path)) if path == canonical.as_path()
        ));

        let mut connector = ConnectorConfig::local_default();
        connector.policy_rules.push(PolicyRule {
            mode: PolicyMode::Deny,
            principal: PrincipalMatcher::Any,
            resource: ResourceMatcher::Executable { path: canonical },
            tool: Some("admin_exec".to_owned()),
            capability: Some(Capability::AdminExec),
        });
        let decisions = resources
            .contexts()
            .map(|resource| {
                PolicyEngine.evaluate_context(
                    &connector,
                    "admin_exec",
                    Capability::AdminExec,
                    &PolicyContext {
                        principal: PrincipalContext::Local,
                        resource,
                    },
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(decisions[0].mode, PolicyMode::Deny);
        Ok(())
    }
}
