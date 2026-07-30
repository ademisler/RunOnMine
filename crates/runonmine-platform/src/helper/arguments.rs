use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const MAX_COMMAND_SCHEMAS: usize = 64;
const MAX_FLAGS: usize = 64;
const MAX_POSITIONALS: usize = 64;
const MAX_CHOICES: usize = 128;
const MAX_ARGUMENT_LENGTH: usize = 8 * 1024;

/// Installation-time rule binding one executable to explicit argument schemas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminProgramRule {
    pub program: PathBuf,
    pub commands: Vec<AdminCommandSchema>,
}

impl AdminProgramRule {
    #[must_use]
    pub fn no_arguments(program: PathBuf) -> Self {
        Self {
            program,
            commands: vec![AdminCommandSchema::no_arguments()],
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.program.is_absolute() {
            bail!("admin rule executable must be an absolute path");
        }
        if self.commands.is_empty() || self.commands.len() > MAX_COMMAND_SCHEMAS {
            bail!("admin rule must contain between one and {MAX_COMMAND_SCHEMAS} command schemas");
        }
        for command in &self.commands {
            command.validate_definition()?;
        }
        Ok(())
    }

    pub(super) fn normalize(mut self) -> Result<Self> {
        self.validate()?;
        for command in &mut self.commands {
            command.normalize_path_roots()?;
        }
        Ok(self)
    }
}

/// One exact command shape for an allowlisted executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCommandSchema {
    /// Exact first argument, when this executable uses subcommands.
    pub subcommand: Option<String>,
    #[serde(default)]
    pub flags: Vec<AdminFlagSchema>,
    /// Explicit defense-in-depth deny list. It is checked before allowed flags.
    #[serde(default)]
    pub forbidden_flags: Vec<String>,
    /// Exact positional argument sequence after the optional subcommand.
    #[serde(default)]
    pub positionals: Vec<AdminArgumentSchema>,
}

impl AdminCommandSchema {
    #[must_use]
    pub fn no_arguments() -> Self {
        Self {
            subcommand: None,
            flags: Vec::new(),
            forbidden_flags: Vec::new(),
            positionals: Vec::new(),
        }
    }

    pub(super) fn validate_definition(&self) -> Result<()> {
        if let Some(subcommand) = &self.subcommand {
            validate_literal_token(subcommand, "admin subcommand")?;
            if subcommand.starts_with('-') || subcommand.starts_with('@') {
                bail!("admin subcommand may not look like a flag or response file");
            }
        }
        if self.flags.len() > MAX_FLAGS
            || self.forbidden_flags.len() > MAX_FLAGS
            || self.positionals.len() > MAX_POSITIONALS
        {
            bail!("admin command schema exceeds the supported argument limits");
        }

        let mut allowed_names = BTreeSet::new();
        for flag in &self.flags {
            flag.validate_definition()?;
            if !allowed_names.insert(flag.name.as_str()) {
                bail!("admin command schema contains a duplicate allowed flag");
            }
        }
        let mut forbidden_names = BTreeSet::new();
        for flag in &self.forbidden_flags {
            validate_flag_name(flag)?;
            if !forbidden_names.insert(flag.as_str()) {
                bail!("admin command schema contains a duplicate forbidden flag");
            }
            if allowed_names.contains(flag.as_str()) {
                bail!("an admin flag cannot be both allowed and forbidden");
            }
        }
        for positional in &self.positionals {
            positional.validate_definition()?;
        }
        Ok(())
    }

    pub(super) fn normalize_path_roots(&mut self) -> Result<()> {
        for flag in &mut self.flags {
            if let Some(value) = &mut flag.value {
                value.normalize_path_roots()?;
            }
        }
        for positional in &mut self.positionals {
            positional.normalize_path_roots()?;
        }
        Ok(())
    }

    pub(super) fn validates_loaded_roots(&self) -> Result<()> {
        self.validate_definition()?;
        for flag in &self.flags {
            if let Some(value) = &flag.value {
                value.validate_loaded_roots()?;
            }
        }
        for positional in &self.positionals {
            positional.validate_loaded_roots()?;
        }
        Ok(())
    }

    pub(super) fn permits(&self, arguments: &[String]) -> Result<bool> {
        let mut cursor = 0_usize;
        if let Some(expected) = &self.subcommand {
            if arguments.first() != Some(expected) {
                return Ok(false);
            }
            cursor = 1;
        }

        let allowed_flags = self
            .flags
            .iter()
            .map(|flag| (flag.name.as_str(), flag))
            .collect::<BTreeMap<_, _>>();
        let forbidden_flags = self
            .forbidden_flags
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut seen_flags = BTreeMap::<&str, usize>::new();
        let mut positionals = Vec::new();

        while cursor < arguments.len() {
            let argument = &arguments[cursor];
            validate_runtime_argument(argument)?;
            if argument == "--" {
                return Ok(false);
            }
            if argument.starts_with('-') {
                let (name, inline_value) = split_flag(argument);
                if forbidden_flags.contains(name) {
                    return Ok(false);
                }
                let Some(schema) = allowed_flags.get(name).copied() else {
                    return Ok(false);
                };
                let count = seen_flags.entry(name).or_default();
                *count += 1;
                if *count > 1 && !schema.repeatable {
                    return Ok(false);
                }
                match (&schema.value, inline_value) {
                    (None, None) => {}
                    (None, Some(_)) => return Ok(false),
                    (Some(value_schema), Some(value)) => {
                        if !value_schema.permits(value)? {
                            return Ok(false);
                        }
                    }
                    (Some(value_schema), None) => {
                        cursor += 1;
                        let Some(value) = arguments.get(cursor) else {
                            return Ok(false);
                        };
                        if !value_schema.permits(value)? {
                            return Ok(false);
                        }
                    }
                }
            } else {
                positionals.push(argument.as_str());
            }
            cursor += 1;
        }

        if positionals.len() != self.positionals.len() {
            return Ok(false);
        }
        for (value, schema) in positionals.into_iter().zip(&self.positionals) {
            if !schema.permits(value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminFlagSchema {
    pub name: String,
    #[serde(default)]
    pub value: Option<AdminArgumentSchema>,
    #[serde(default)]
    pub repeatable: bool,
}

impl AdminFlagSchema {
    fn validate_definition(&self) -> Result<()> {
        validate_flag_name(&self.name)?;
        if let Some(value) = &self.value {
            value.validate_definition()?;
        }
        Ok(())
    }
}

/// Constraint for one positional argument or flag value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminArgumentSchema {
    Literal {
        value: String,
    },
    Choice {
        values: Vec<String>,
    },
    Text {
        max_length: usize,
        #[serde(default)]
        allow_leading_dash: bool,
        #[serde(default)]
        allow_response_file: bool,
    },
    Path {
        roots: Vec<PathBuf>,
        #[serde(default)]
        mode: AdminPathMode,
    },
}

impl AdminArgumentSchema {
    fn validate_definition(&self) -> Result<()> {
        match self {
            Self::Literal { value } => validate_literal_token(value, "admin literal argument"),
            Self::Choice { values } => {
                if values.is_empty() || values.len() > MAX_CHOICES {
                    bail!("admin choice argument has an invalid number of values");
                }
                let mut unique = BTreeSet::new();
                for value in values {
                    validate_literal_token(value, "admin choice value")?;
                    if !unique.insert(value) {
                        bail!("admin choice argument contains duplicate values");
                    }
                }
                Ok(())
            }
            Self::Text { max_length, .. } => {
                if *max_length == 0 || *max_length > MAX_ARGUMENT_LENGTH {
                    bail!("admin text argument length is outside the supported range");
                }
                Ok(())
            }
            Self::Path { roots, .. } => {
                if roots.is_empty() || roots.len() > 32 {
                    bail!("admin path argument must have between one and 32 roots");
                }
                if roots.iter().any(|root| !root.is_absolute()) {
                    bail!("admin path roots must be absolute");
                }
                Ok(())
            }
        }
    }

    fn normalize_path_roots(&mut self) -> Result<()> {
        let Self::Path { roots, .. } = self else {
            return Ok(());
        };
        let mut normalized = roots
            .iter()
            .map(|root| normalize_policy_root(root))
            .collect::<Result<Vec<_>>>()?;
        normalized.sort();
        normalized.dedup();
        *roots = normalized;
        Ok(())
    }

    fn validate_loaded_roots(&self) -> Result<()> {
        let Self::Path { roots, .. } = self else {
            return Ok(());
        };
        for root in roots {
            if normalize_policy_root(root)? != *root {
                bail!("stored admin path root is not canonical");
            }
        }
        Ok(())
    }

    fn permits(&self, value: &str) -> Result<bool> {
        validate_runtime_argument(value)?;
        match self {
            Self::Literal { value: expected } => Ok(value == expected),
            Self::Choice { values } => Ok(values.iter().any(|choice| choice == value)),
            Self::Text {
                max_length,
                allow_leading_dash,
                allow_response_file,
            } => Ok(value.len() <= *max_length
                && (*allow_leading_dash || !value.starts_with('-'))
                && (*allow_response_file || !value.starts_with('@'))),
            Self::Path { roots, mode } => path_argument_permitted(Path::new(value), roots, *mode),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminPathMode {
    #[default]
    Existing,
    ExistingFile,
    ExistingDirectory,
    CreateOrExisting,
}

fn validate_flag_name(flag: &str) -> Result<()> {
    validate_runtime_argument(flag)?;
    if !flag.starts_with('-')
        || matches!(flag, "-" | "--")
        || flag.contains('=')
        || flag.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        bail!("admin flag names must be exact non-empty flag tokens without values");
    }
    Ok(())
}

fn validate_literal_token(value: &str, description: &str) -> Result<()> {
    validate_runtime_argument(value)?;
    if value.is_empty() {
        bail!("{description} may not be empty");
    }
    Ok(())
}

fn validate_runtime_argument(value: &str) -> Result<()> {
    if value.len() > MAX_ARGUMENT_LENGTH
        || value.is_empty()
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        bail!("admin execution contains an invalid argument");
    }
    Ok(())
}

fn split_flag(argument: &str) -> (&str, Option<&str>) {
    argument
        .split_once('=')
        .map_or((argument, None), |(name, value)| (name, Some(value)))
}

fn normalize_policy_root(root: &Path) -> Result<PathBuf> {
    if !root.is_absolute() || contains_relative_component(root) {
        bail!("admin path roots must be absolute and normalized");
    }
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to inspect admin path root {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("admin path root must be an existing non-symlink directory");
    }
    root.canonicalize()
        .with_context(|| format!("failed to canonicalize admin path root {}", root.display()))
}

fn path_argument_permitted(path: &Path, roots: &[PathBuf], mode: AdminPathMode) -> Result<bool> {
    if !path.is_absolute() || contains_relative_component(path) {
        return Ok(false);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Ok(false);
            }
            let canonical = path
                .canonicalize()
                .with_context(|| format!("failed to canonicalize admin path {}", path.display()))?;
            if !roots.iter().any(|root| canonical.starts_with(root)) {
                return Ok(false);
            }
            Ok(match mode {
                AdminPathMode::Existing | AdminPathMode::CreateOrExisting => true,
                AdminPathMode::ExistingFile => metadata.is_file(),
                AdminPathMode::ExistingDirectory => metadata.is_dir(),
            })
        }
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && mode == AdminPathMode::CreateOrExisting =>
        {
            let Some(ancestor) = nearest_existing_ancestor(path)? else {
                return Ok(false);
            };
            let canonical = ancestor.canonicalize().with_context(|| {
                format!(
                    "failed to canonicalize admin path ancestor {}",
                    ancestor.display()
                )
            })?;
            Ok(roots.iter().any(|root| canonical.starts_with(root)))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect admin path {}", path.display()))
        }
    }
}

fn nearest_existing_ancestor(path: &Path) -> Result<Option<PathBuf>> {
    let mut current = path.parent();
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Ok(None);
                }
                return Ok(Some(candidate.to_path_buf()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current = candidate.parent();
            }
            Err(error) => return Err(error).context("failed to inspect admin path ancestor"),
        }
    }
    Ok(None)
}

fn contains_relative_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service_schema(root: &Path) -> AdminCommandSchema {
        AdminCommandSchema {
            subcommand: Some("restart".to_owned()),
            flags: vec![AdminFlagSchema {
                name: "--config".to_owned(),
                value: Some(AdminArgumentSchema::Path {
                    roots: vec![root.to_path_buf()],
                    mode: AdminPathMode::ExistingFile,
                }),
                repeatable: false,
            }],
            forbidden_flags: vec!["--root".to_owned(), "--machine".to_owned()],
            positionals: vec![AdminArgumentSchema::Choice {
                values: vec!["runonmine-agent.service".to_owned()],
            }],
        }
    }

    #[test]
    fn exact_subcommand_flags_positionals_and_paths_are_enforced() -> Result<()> {
        let root = tempfile::tempdir()?;
        let config = root.path().join("agent.conf");
        fs::write(&config, b"test")?;
        let mut schema = service_schema(root.path());
        schema.normalize_path_roots()?;

        assert!(schema.permits(&[
            "restart".to_owned(),
            "--config".to_owned(),
            config.to_string_lossy().into_owned(),
            "runonmine-agent.service".to_owned(),
        ])?);
        assert!(!schema.permits(&["stop".to_owned(), "runonmine-agent.service".to_owned()])?);
        assert!(!schema.permits(&[
            "restart".to_owned(),
            "--root=/tmp".to_owned(),
            "runonmine-agent.service".to_owned(),
        ])?);
        assert!(!schema.permits(&[
            "restart".to_owned(),
            "--unknown".to_owned(),
            "runonmine-agent.service".to_owned(),
        ])?);
        assert!(!schema.permits(&[
            "restart".to_owned(),
            "--".to_owned(),
            "runonmine-agent.service".to_owned(),
        ])?);
        Ok(())
    }

    #[test]
    fn path_constraints_reject_escape_symlink_and_unapproved_creation() -> Result<()> {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let existing = root.path().join("inside.txt");
        fs::write(&existing, b"inside")?;
        let mut path = AdminArgumentSchema::Path {
            roots: vec![root.path().to_path_buf()],
            mode: AdminPathMode::CreateOrExisting,
        };
        path.normalize_path_roots()?;
        assert!(path.permits(&existing.to_string_lossy())?);
        assert!(path.permits(&root.path().join("new.txt").to_string_lossy())?);
        assert!(!path.permits(&outside.path().join("new.txt").to_string_lossy())?);
        assert!(!path.permits(&root.path().join("../escape").to_string_lossy())?);
        #[cfg(unix)]
        {
            let link = root.path().join("link");
            symlink(outside.path(), &link)?;
            assert!(!path.permits(&link.join("file").to_string_lossy())?);
        }
        Ok(())
    }

    #[test]
    fn nested_profile_schema_rejects_unknown_fields() {
        let unknown_program = br#"{
            "program":"/usr/bin/id",
            "commands":[{"subcommand":null}],
            "unexpected":true
        }"#;
        assert!(serde_json::from_slice::<AdminProgramRule>(unknown_program).is_err());

        let unknown_command = br#"{
            "subcommand":null,
            "flags":[],
            "forbidden_flags":[],
            "positionals":[],
            "unexpected":true
        }"#;
        assert!(serde_json::from_slice::<AdminCommandSchema>(unknown_command).is_err());

        let unknown_flag = br#"{
            "name":"--safe",
            "repeatable":false,
            "unexpected":true
        }"#;
        assert!(serde_json::from_slice::<AdminFlagSchema>(unknown_flag).is_err());

        let unknown_argument = br#"{
            "type":"text",
            "max_length":32,
            "unexpected":true
        }"#;
        assert!(serde_json::from_slice::<AdminArgumentSchema>(unknown_argument).is_err());
    }

    #[test]
    fn text_arguments_reject_flag_and_response_file_injection_by_default() -> Result<()> {
        let schema = AdminArgumentSchema::Text {
            max_length: 32,
            allow_leading_dash: false,
            allow_response_file: false,
        };
        assert!(schema.permits("ordinary")?);
        assert!(!schema.permits("--dangerous")?);
        assert!(!schema.permits("@arguments.txt")?);
        Ok(())
    }
}
