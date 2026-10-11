use crate::desktop_icon;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopCommand {
    Show,
    Lock,
    Quit,
}

pub(crate) const DESKTOP_ACTIONS: [&str; 3] = ["show", "lock", "quit"];

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod native {
    use super::{DesktopCommand, desktop_icon};
    use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

    pub(crate) struct DesktopShell {
        tray: Option<TrayIcon>,
        open_menu_id: Option<MenuId>,
        lock_menu_id: Option<MenuId>,
        quit_menu_id: Option<MenuId>,
    }

    impl DesktopShell {
        pub(crate) fn new() -> Self {
            let mut shell = Self {
                tray: None,
                open_menu_id: None,
                lock_menu_id: None,
                quit_menu_id: None,
            };
            shell.create_tray();
            shell
        }

        pub(crate) fn is_available(&self) -> bool {
            self.tray.is_some()
        }

        pub(crate) fn try_command(&self) -> Option<DesktopCommand> {
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if self.open_menu_id.as_ref() == Some(&event.id) {
                    return Some(DesktopCommand::Show);
                }
                if self.lock_menu_id.as_ref() == Some(&event.id) {
                    return Some(DesktopCommand::Lock);
                }
                if self.quit_menu_id.as_ref() == Some(&event.id) {
                    return Some(DesktopCommand::Quit);
                }
            }
            None
        }

        pub(crate) fn set_status(&self, status: &str, _needs_attention: bool) {
            if let Some(tray) = &self.tray {
                let _result = tray.set_tooltip(Some(&format!("RunOnMine — {status}")));
            }
        }

        fn create_tray(&mut self) {
            let menu = Menu::new();
            let open = MenuItem::new("Open RunOnMine", true, None);
            let lock = MenuItem::new("Lock RunOnMine", true, None);
            let quit = MenuItem::new("Quit", true, None);
            if menu.append(&open).is_err()
                || menu.append(&lock).is_err()
                || menu.append(&quit).is_err()
            {
                return;
            }
            let Ok(icon) = tray_icon() else {
                return;
            };
            let Ok(tray) = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("RunOnMine")
                .with_icon(icon)
                .build()
            else {
                return;
            };
            self.open_menu_id = Some(open.id().clone());
            self.lock_menu_id = Some(lock.id().clone());
            self.quit_menu_id = Some(quit.id().clone());
            self.tray = Some(tray);
        }
    }

    fn tray_icon() -> Result<Icon, tray_icon::BadIcon> {
        const SIZE: u32 = 64;
        Icon::from_rgba(desktop_icon::rgba(), SIZE, SIZE)
    }
}

#[cfg(target_os = "linux")]
mod native {
    use std::sync::mpsc::{self, Receiver, Sender};

    use ksni::blocking::{Handle, TrayMethods};
    use ksni::menu::StandardItem;
    use ksni::{MenuItem, Status, ToolTip, Tray};

    use super::{DesktopCommand, desktop_icon};

    pub(crate) struct DesktopShell {
        tray: Option<Handle<LinuxTray>>,
        receiver: Receiver<DesktopCommand>,
    }

    impl DesktopShell {
        pub(crate) fn new() -> Self {
            let (sender, receiver) = mpsc::channel();
            let tray = LinuxTray {
                sender,
                status: "Starting".to_owned(),
                needs_attention: false,
            }
            .spawn()
            .ok();
            Self { tray, receiver }
        }

        pub(crate) fn is_available(&self) -> bool {
            self.tray.as_ref().is_some_and(|tray| !tray.is_closed())
        }

        pub(crate) fn try_command(&self) -> Option<DesktopCommand> {
            self.receiver.try_recv().ok()
        }

        pub(crate) fn set_status(&self, status: &str, needs_attention: bool) {
            if let Some(tray) = &self.tray {
                let status = status.to_owned();
                let _updated = tray.update(move |tray| {
                    tray.status = status;
                    tray.needs_attention = needs_attention;
                });
            }
        }
    }

    impl Drop for DesktopShell {
        fn drop(&mut self) {
            if let Some(tray) = self.tray.take() {
                tray.shutdown().wait();
            }
        }
    }

    struct LinuxTray {
        sender: Sender<DesktopCommand>,
        status: String,
        needs_attention: bool,
    }

    impl Tray for LinuxTray {
        fn id(&self) -> String {
            "runonmine-desktop".to_owned()
        }

        fn activate(&mut self, _x: i32, _y: i32) {
            let _sent = self.sender.send(DesktopCommand::Show);
        }

        fn title(&self) -> String {
            format!("RunOnMine — {}", self.status)
        }

        fn status(&self) -> Status {
            if self.needs_attention {
                Status::NeedsAttention
            } else {
                Status::Active
            }
        }

        fn icon_name(&self) -> String {
            "runonmine-desktop".to_owned()
        }

        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            let mut data = desktop_icon::rgba();
            for pixel in data.chunks_exact_mut(4) {
                pixel.rotate_right(1);
            }
            vec![ksni::Icon {
                width: 64,
                height: 64,
                data,
            }]
        }

        fn attention_icon_name(&self) -> String {
            self.icon_name()
        }

        fn attention_icon_pixmap(&self) -> Vec<ksni::Icon> {
            self.icon_pixmap()
        }

        fn tool_tip(&self) -> ToolTip {
            ToolTip {
                icon_name: self.icon_name(),
                icon_pixmap: self.icon_pixmap(),
                title: "RunOnMine".to_owned(),
                description: self.status.clone(),
            }
        }

        fn menu(&self) -> Vec<MenuItem<Self>> {
            vec![
                command_item("Open RunOnMine", self.sender.clone(), DesktopCommand::Show),
                command_item("Lock RunOnMine", self.sender.clone(), DesktopCommand::Lock),
                MenuItem::Separator,
                command_item("Quit", self.sender.clone(), DesktopCommand::Quit),
            ]
        }
    }

    fn command_item(
        label: &str,
        sender: Sender<DesktopCommand>,
        command: DesktopCommand,
    ) -> MenuItem<LinuxTray> {
        StandardItem {
            label: label.to_owned(),
            activate: Box::new(move |_tray| {
                let _sent = sender.send(command);
            }),
            ..Default::default()
        }
        .into()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod native {
    use super::DesktopCommand;

    pub(crate) struct DesktopShell;

    impl DesktopShell {
        pub(crate) fn new() -> Self {
            Self
        }

        pub(crate) fn is_available(&self) -> bool {
            false
        }

        pub(crate) fn try_command(&self) -> Option<DesktopCommand> {
            None
        }

        pub(crate) fn set_status(&self, _status: &str, _needs_attention: bool) {}
    }
}

pub(crate) use native::DesktopShell;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_shell_contract_has_the_three_security_actions() {
        assert_eq!(DESKTOP_ACTIONS, ["show", "lock", "quit"]);
    }
}
