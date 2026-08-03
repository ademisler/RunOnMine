#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(feature = "desktop-ui")]
mod connector_wizard;
#[cfg(feature = "desktop-ui")]
mod credential_update;
#[cfg(feature = "desktop-ui")]
mod desktop_acceptance;
#[cfg(feature = "desktop-ui")]
mod desktop_icon;
#[cfg(feature = "desktop-ui")]
mod desktop_instance;
#[cfg(feature = "desktop-ui")]
mod desktop_process;
#[cfg(feature = "desktop-ui")]
mod desktop_shell;
#[cfg(feature = "desktop-ui")]
mod desktop_snapshot;
#[cfg(feature = "desktop-ui")]
mod layout;
#[cfg(feature = "desktop-ui")]
mod policy_editor;
#[cfg(feature = "desktop-ui")]
mod theme;

#[cfg(feature = "desktop-ui")]
mod desktop_app;

#[cfg(feature = "desktop-ui")]
fn main() -> anyhow::Result<()> {
    desktop_app::run()
}

#[cfg(not(feature = "desktop-ui"))]
fn main() {
    eprintln!("runonmine-desktop was built without the desktop-ui feature");
}
