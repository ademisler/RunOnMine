//! Audited Win32 boundary for desktop window activation.

#![allow(unsafe_code)]

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::SetForegroundWindow;

pub(super) fn focus_window(window_id: u32) -> Result<()> {
    let handle = window_id as usize as HWND;
    // SAFETY: the handle comes from xcap's operating-system window
    // enumeration. SetForegroundWindow borrows the handle for this call and
    // does not take ownership of it.
    if unsafe { SetForegroundWindow(handle) } == 0 {
        bail!("the desktop window could not be focused");
    }
    Ok(())
}
