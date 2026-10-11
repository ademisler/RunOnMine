//! Cross-platform desktop discovery, capture and user-input primitives.
//!
//! The heavy native dependencies are behind the `desktop-control` feature so
//! a headless Linux agent can be built without display-system libraries.

use anyhow::{Result, bail};
use serde::Serialize;

#[cfg(all(feature = "desktop-control", windows))]
#[path = "desktop/windows.rs"]
mod windows;

#[derive(Clone, Debug, Serialize)]
pub struct DesktopWindow {
    pub id: u32,
    pub process_id: u32,
    pub application: String,
    pub title: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub minimized: bool,
    pub focused: bool,
}

#[derive(Clone, Debug)]
pub struct CapturedImage {
    pub jpeg: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ScreenshotTarget {
    pub monitor_id: Option<u32>,
    pub window_id: Option<u32>,
    pub quality: u8,
    pub max_dimension: u32,
}

#[must_use]
pub fn capture_available() -> bool {
    if !cfg!(feature = "desktop-control") {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    }
    #[cfg(any(target_os = "macos", windows))]
    {
        true
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        false
    }
}

#[must_use]
pub fn input_available() -> bool {
    if !cfg!(feature = "desktop-control") {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        // The lean default Enigo backend is X11. Wayland compositors require
        // explicit portal/libei support and therefore fail closed here.
        std::env::var_os("DISPLAY").is_some()
    }
    #[cfg(any(target_os = "macos", windows))]
    {
        true
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        false
    }
}

#[must_use]
pub fn focus_available() -> bool {
    if !capture_available() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_some() && find_xdotool().is_some()
    }
    #[cfg(any(target_os = "macos", windows))]
    {
        true
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        false
    }
}

#[cfg(feature = "desktop-control")]
pub fn list_windows(limit: usize) -> Result<Vec<DesktopWindow>> {
    let mut output = Vec::new();
    for window in xcap::Window::all()? {
        if output.len() >= limit.clamp(1, 1_000) {
            break;
        }
        let Ok(id) = window.id() else { continue };
        let Ok(process_id) = window.pid() else {
            continue;
        };
        let Ok(width) = window.width() else { continue };
        let Ok(height) = window.height() else {
            continue;
        };
        if width == 0 || height == 0 {
            continue;
        }
        output.push(DesktopWindow {
            id,
            process_id,
            application: window.app_name().unwrap_or_default(),
            title: window.title().unwrap_or_default(),
            x: window.x().unwrap_or_default(),
            y: window.y().unwrap_or_default(),
            width,
            height,
            minimized: window.is_minimized().unwrap_or(false),
            focused: window.is_focused().unwrap_or(false),
        });
    }
    Ok(output)
}

#[cfg(not(feature = "desktop-control"))]
pub fn list_windows(_limit: usize) -> Result<Vec<DesktopWindow>> {
    bail!("desktop capture support is not compiled into this binary")
}

#[cfg(feature = "desktop-control")]
pub fn screenshot(target: ScreenshotTarget) -> Result<CapturedImage> {
    use image::imageops::FilterType;
    use image::{DynamicImage, ImageEncoder as _};

    if target.monitor_id.is_some() && target.window_id.is_some() {
        bail!("choose either a monitor or a window, not both");
    }
    let image = if let Some(window_id) = target.window_id {
        let window = xcap::Window::all()?
            .into_iter()
            .find(|window| window.id().ok() == Some(window_id))
            .ok_or_else(|| anyhow::anyhow!("desktop window was not found"))?;
        window.capture_image()?
    } else {
        let monitors = xcap::Monitor::all()?;
        let monitor = if let Some(monitor_id) = target.monitor_id {
            monitors
                .into_iter()
                .find(|monitor| monitor.id().ok() == Some(monitor_id))
                .ok_or_else(|| anyhow::anyhow!("desktop monitor was not found"))?
        } else {
            monitors
                .iter()
                .find(|monitor| monitor.is_primary().unwrap_or(false))
                .cloned()
                .or_else(|| monitors.into_iter().next())
                .ok_or_else(|| anyhow::anyhow!("no desktop monitor is available"))?
        };
        monitor.capture_image()?
    };

    let max_dimension = target.max_dimension.clamp(320, 4_096);
    let (source_width, source_height) = image.dimensions();
    let longest = source_width.max(source_height);
    let width = scale_dimension(source_width, max_dimension, longest);
    let height = scale_dimension(source_height, max_dimension, longest);
    let rgb = DynamicImage::ImageRgba8(image).to_rgb8();
    let mut rgb = if (width, height) == (source_width, source_height) {
        rgb
    } else {
        image::imageops::resize(&rgb, width, height, FilterType::Lanczos3)
    };
    let mut quality = target.quality.clamp(20, 90);
    let mut encoded = Vec::new();
    loop {
        encoded.clear();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut encoded, quality).write_image(
            rgb.as_raw(),
            rgb.width(),
            rgb.height(),
            image::ExtendedColorType::Rgb8,
        )?;
        if encoded.len() <= 3 * 1024 * 1024 {
            break;
        }
        if rgb.width().max(rgb.height()) <= 640 {
            bail!("desktop screenshot exceeds the safe response limit");
        }
        let next_width = (rgb.width() * 3 / 4).max(1);
        let next_height = (rgb.height() * 3 / 4).max(1);
        rgb = image::imageops::resize(&rgb, next_width, next_height, FilterType::Lanczos3);
        quality = quality.saturating_sub(10).max(20);
    }
    Ok(CapturedImage {
        jpeg: encoded,
        width: rgb.width(),
        height: rgb.height(),
    })
}

#[cfg(feature = "desktop-control")]
fn scale_dimension(value: u32, max_dimension: u32, longest: u32) -> u32 {
    if longest <= max_dimension {
        return value.max(1);
    }
    let numerator =
        u64::from(value) * u64::from(max_dimension) + (u64::from(longest).saturating_sub(1) / 2);
    let scaled = numerator / u64::from(longest);
    u32::try_from(scaled.max(1)).unwrap_or(max_dimension)
}

#[cfg(not(feature = "desktop-control"))]
pub fn screenshot(_target: ScreenshotTarget) -> Result<CapturedImage> {
    bail!("desktop capture support is not compiled into this binary")
}

#[cfg(feature = "desktop-control")]
pub fn focus_window(window_id: u32) -> Result<()> {
    let window = xcap::Window::all()?
        .into_iter()
        .find(|window| window.id().ok() == Some(window_id))
        .ok_or_else(|| anyhow::anyhow!("desktop window was not found"))?;
    focus_window_platform(window_id, window.pid()?)
}

#[cfg(not(feature = "desktop-control"))]
pub fn focus_window(_window_id: u32) -> Result<()> {
    bail!("desktop control support is not compiled into this binary")
}

#[cfg(all(feature = "desktop-control", target_os = "macos"))]
fn focus_window_platform(_window_id: u32, process_id: u32) -> Result<()> {
    let script = format!(
        "tell application \"System Events\" to set frontmost of first process whose unix id is {process_id} to true"
    );
    let output = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()?;
    if !output.status.success() {
        bail!("the desktop window could not be focused");
    }
    Ok(())
}

#[cfg(all(feature = "desktop-control", target_os = "linux"))]
fn focus_window_platform(window_id: u32, _process_id: u32) -> Result<()> {
    let xdotool = find_xdotool().ok_or_else(|| anyhow::anyhow!("xdotool is not installed"))?;
    let output = std::process::Command::new(xdotool)
        .args(["windowactivate", "--sync", &window_id.to_string()])
        .output()?;
    if !output.status.success() {
        bail!("the desktop window could not be focused");
    }
    Ok(())
}

#[cfg(all(feature = "desktop-control", windows))]
fn focus_window_platform(window_id: u32, _process_id: u32) -> Result<()> {
    windows::focus_window(window_id)
}

#[cfg(all(
    feature = "desktop-control",
    not(any(target_os = "macos", target_os = "linux", windows))
))]
fn focus_window_platform(_window_id: u32, _process_id: u32) -> Result<()> {
    bail!("desktop window focus is unsupported on this operating system")
}

#[cfg(target_os = "linux")]
fn find_xdotool() -> Option<std::path::PathBuf> {
    ["/usr/bin/xdotool", "/usr/local/bin/xdotool"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.is_file())
}

#[cfg(feature = "desktop-control")]
pub fn click(x: i32, y: i32, button: &str) -> Result<()> {
    use enigo::{Button, Coordinate, Direction, Enigo, Mouse as _, Settings};

    let button = match button.to_ascii_lowercase().as_str() {
        "left" => Button::Left,
        "middle" => Button::Middle,
        "right" => Button::Right,
        _ => bail!("mouse button must be left, middle or right"),
    };
    let mut enigo = Enigo::new(&Settings::default())?;
    enigo.move_mouse(x, y, Coordinate::Abs)?;
    enigo.button(button, Direction::Click)?;
    Ok(())
}

#[cfg(not(feature = "desktop-control"))]
pub fn click(_x: i32, _y: i32, _button: &str) -> Result<()> {
    bail!("desktop input support is not compiled into this binary")
}

#[cfg(feature = "desktop-control")]
pub fn type_text(text: &str) -> Result<()> {
    use enigo::{Enigo, Keyboard as _, Settings};

    if text.len() > 16 * 1024 || text.contains('\0') {
        bail!("desktop text is outside the supported limit");
    }
    let mut enigo = Enigo::new(&Settings::default())?;
    enigo.text(text)?;
    Ok(())
}

#[cfg(not(feature = "desktop-control"))]
pub fn type_text(_text: &str) -> Result<()> {
    bail!("desktop input support is not compiled into this binary")
}

#[cfg(feature = "desktop-control")]
pub fn key_chord(chord: &str) -> Result<()> {
    use enigo::{Direction, Enigo, Keyboard as _, Settings};

    let parts = chord
        .split('+')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 5 {
        bail!("desktop key chord is invalid");
    }
    let keys = parts
        .iter()
        .map(|part| parse_key(part))
        .collect::<Result<Vec<_>>>()?;
    let mut enigo = Enigo::new(&Settings::default())?;
    for key in keys.iter().take(keys.len().saturating_sub(1)) {
        enigo.key(*key, Direction::Press)?;
    }
    enigo.key(
        *keys
            .last()
            .ok_or_else(|| anyhow::anyhow!("key is missing"))?,
        Direction::Click,
    )?;
    for key in keys.iter().take(keys.len().saturating_sub(1)).rev() {
        enigo.key(*key, Direction::Release)?;
    }
    Ok(())
}

#[cfg(feature = "desktop-control")]
fn parse_key(value: &str) -> Result<enigo::Key> {
    use enigo::Key;

    let normalized = value.to_ascii_lowercase();
    let key = match normalized.as_str() {
        "alt" | "option" => Key::Alt,
        "backspace" => Key::Backspace,
        "control" | "ctrl" => Key::Control,
        "delete" => Key::Delete,
        "down" | "arrowdown" => Key::DownArrow,
        "end" => Key::End,
        "enter" | "return" => Key::Return,
        "escape" | "esc" => Key::Escape,
        "f1" => Key::F1,
        "f2" => Key::F2,
        "f3" => Key::F3,
        "f4" => Key::F4,
        "f5" => Key::F5,
        "f6" => Key::F6,
        "f7" => Key::F7,
        "f8" => Key::F8,
        "f9" => Key::F9,
        "f10" => Key::F10,
        "f11" => Key::F11,
        "f12" => Key::F12,
        "home" => Key::Home,
        "left" | "arrowleft" => Key::LeftArrow,
        "meta" | "command" | "cmd" | "super" | "windows" => Key::Meta,
        "pagedown" => Key::PageDown,
        "pageup" => Key::PageUp,
        "right" | "arrowright" => Key::RightArrow,
        "shift" => Key::Shift,
        "space" => Key::Space,
        "tab" => Key::Tab,
        "up" | "arrowup" => Key::UpArrow,
        _ => {
            let mut characters = value.chars();
            let character = characters
                .next()
                .ok_or_else(|| anyhow::anyhow!("desktop key is missing"))?;
            if characters.next().is_some() || character.is_control() {
                bail!("unsupported desktop key");
            }
            Key::Unicode(character)
        }
    };
    Ok(key)
}

#[cfg(not(feature = "desktop-control"))]
pub fn key_chord(_chord: &str) -> Result<()> {
    bail!("desktop input support is not compiled into this binary")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_build_reports_no_compiled_desktop_capability() {
        if !cfg!(feature = "desktop-control") {
            assert!(!capture_available());
            assert!(!input_available());
        }
    }

    #[cfg(feature = "desktop-control")]
    #[test]
    fn key_parser_accepts_named_and_unicode_keys() -> Result<()> {
        assert_eq!(parse_key("enter")?, enigo::Key::Return);
        assert_eq!(parse_key("x")?, enigo::Key::Unicode('x'));
        assert!(parse_key("not-a-key").is_err());
        Ok(())
    }
}
