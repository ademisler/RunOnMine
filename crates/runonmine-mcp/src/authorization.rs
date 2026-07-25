use std::path::PathBuf;

use anyhow::Result;
use runonmine_core::ResourceContext;
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
    pub(super) fn as_context(&self) -> ResourceContext<'_> {
        match self {
            Self::None => ResourceContext::None,
            Self::Filesystem(path) => ResourceContext::Filesystem(path),
            Self::Browser(url) => ResourceContext::Browser(url),
            Self::Executable(path) => ResourceContext::Executable(path),
            Self::Command(command) => ResourceContext::Command(command),
        }
    }
}

pub(super) fn policy_resource<T: Serialize>(
    tool_name: &str,
    arguments: &T,
) -> Result<OwnedPolicyResource> {
    let value = serde_json::to_value(arguments)?;
    let string = |name: &str| value.get(name).and_then(serde_json::Value::as_str);
    if tool_name.starts_with("fs_") {
        return Ok(string("path")
            .or_else(|| string("root"))
            .or_else(|| string("from"))
            .map_or(OwnedPolicyResource::None, |path| {
                OwnedPolicyResource::Filesystem(PathBuf::from(path))
            }));
    }
    if tool_name.starts_with("browser_") {
        return Ok(string("url")
            .map(Url::parse)
            .transpose()?
            .map_or(OwnedPolicyResource::None, OwnedPolicyResource::Browser));
    }
    if matches!(tool_name, "shell_exec" | "admin_exec") {
        if let Some(command) = string("command") {
            return Ok(OwnedPolicyResource::Command(command.to_owned()));
        }
        if let Some(program) = string("program") {
            return Ok(OwnedPolicyResource::Executable(PathBuf::from(program)));
        }
    }
    Ok(OwnedPolicyResource::None)
}
