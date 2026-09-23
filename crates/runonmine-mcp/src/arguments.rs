use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub(super) struct EmptyArgs {}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct PathArgs {
    pub(super) path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct ListArgs {
    pub(super) path: PathBuf,
    #[serde(default)]
    pub(super) offset: usize,
    #[serde(default = "default_list_limit")]
    pub(super) limit: usize,
}

pub(super) const fn default_list_limit() -> usize {
    250
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct ReadArgs {
    pub(super) path: PathBuf,
    #[serde(default = "default_read_limit")]
    pub(super) max_bytes: usize,
}

pub(super) fn default_read_limit() -> usize {
    256 * 1_024
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct SearchArgs {
    pub(super) root: PathBuf,
    pub(super) query: String,
    #[serde(default = "default_search_limit")]
    pub(super) limit: usize,
    #[serde(default = "default_search_depth")]
    pub(super) max_depth: usize,
    #[serde(default = "default_search_nodes")]
    pub(super) max_nodes: usize,
}

pub(super) const fn default_search_limit() -> usize {
    100
}

pub(super) const fn default_search_depth() -> usize {
    16
}

pub(super) const fn default_search_nodes() -> usize {
    50_000
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct WriteArgs {
    pub(super) path: PathBuf,
    pub(super) content: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct PatchArgs {
    pub(super) path: PathBuf,
    pub(super) old_text: String,
    pub(super) new_text: String,
    #[serde(default = "one")]
    pub(super) expected_replacements: usize,
}

pub(super) const fn one() -> usize {
    1
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct MoveArgs {
    pub(super) from: PathBuf,
    pub(super) to: PathBuf,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct ShellArgs {
    pub(super) command: String,
    pub(super) cwd: Option<PathBuf>,
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct AdminExecArgs {
    pub(super) program: PathBuf,
    #[serde(default)]
    pub(super) args: Vec<String>,
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct DesktopListArgs {
    #[serde(default = "default_window_limit")]
    pub(super) limit: usize,
}

pub(super) const fn default_window_limit() -> usize {
    100
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct DesktopWindowArgs {
    pub(super) window_id: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct DesktopScreenshotArgs {
    pub(super) monitor_id: Option<u32>,
    pub(super) window_id: Option<u32>,
    #[serde(default = "default_image_quality")]
    pub(super) quality: u8,
    #[serde(default = "default_desktop_image_dimension")]
    pub(super) max_dimension: u32,
}

pub(super) const fn default_desktop_image_dimension() -> u32 {
    2_048
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct DesktopClickArgs {
    pub(super) x: i32,
    pub(super) y: i32,
    #[serde(default = "default_mouse_button")]
    pub(super) button: String,
}

pub(super) fn default_mouse_button() -> String {
    "left".to_owned()
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct DesktopTypeArgs {
    pub(super) text: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct DesktopKeyArgs {
    pub(super) key: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct PlatformScriptArgs {
    pub(super) script: String,
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct DbusCallArgs {
    pub(super) destination: String,
    pub(super) object_path: String,
    pub(super) interface: String,
    pub(super) method: String,
    #[serde(default)]
    pub(super) signature: String,
    #[serde(default)]
    pub(super) arguments: Vec<String>,
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct UrlArgs {
    pub(super) url: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct SelectorArgs {
    pub(super) selector: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct TypeArgs {
    pub(super) selector: String,
    pub(super) text: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct KeyArgs {
    pub(super) key: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct ScreenshotArgs {
    #[serde(default = "default_image_quality")]
    pub(super) quality: u8,
    #[serde(default)]
    pub(super) full_page: bool,
}

pub(super) const fn default_image_quality() -> u8 {
    70
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct EvaluateArgs {
    pub(super) expression: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct VoiceNotifyArgs {
    pub(super) text: String,
    #[serde(default = "default_voice")]
    pub(super) voice: String,
    #[serde(default)]
    pub(super) rate_percent: i32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct VoiceListenArgs {
    #[serde(default = "default_listen_seconds")]
    pub(super) listen_seconds: u64,
    #[serde(default = "default_voice_language")]
    pub(super) language: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub(super) struct VoiceAskArgs {
    pub(super) question: String,
    #[serde(default = "default_listen_seconds")]
    pub(super) listen_seconds: u64,
    #[serde(default = "default_voice")]
    pub(super) voice: String,
    #[serde(default)]
    pub(super) rate_percent: i32,
    #[serde(default = "default_voice_language")]
    pub(super) language: String,
}

fn default_voice() -> String {
    "ahmet".to_owned()
}

const fn default_listen_seconds() -> u64 {
    12
}

fn default_voice_language() -> String {
    "tr".to_owned()
}

#[derive(Debug, Serialize)]
pub(super) struct ReadOutput {
    pub(super) content: String,
    pub(super) truncated: bool,
}
