use eframe::egui;

pub(crate) const BG: egui::Color32 = egui::Color32::from_rgb(13, 16, 20);
pub(crate) const SIDEBAR: egui::Color32 = egui::Color32::from_rgb(17, 21, 26);
pub(crate) const SURFACE: egui::Color32 = egui::Color32::from_rgb(23, 28, 34);
pub(crate) const SURFACE_HOVER: egui::Color32 = egui::Color32::from_rgb(29, 36, 43);
pub(crate) const BORDER: egui::Color32 = egui::Color32::from_rgb(44, 52, 61);
pub(crate) const TEXT: egui::Color32 = egui::Color32::from_rgb(235, 239, 244);
pub(crate) const MUTED: egui::Color32 = egui::Color32::from_rgb(145, 156, 168);
pub(crate) const ACCENT: egui::Color32 = egui::Color32::from_rgb(89, 214, 151);
pub(crate) const ACCENT_SOFT: egui::Color32 = egui::Color32::from_rgb(24, 57, 43);
pub(crate) const WARNING: egui::Color32 = egui::Color32::from_rgb(242, 184, 79);
pub(crate) const WARNING_SOFT: egui::Color32 = egui::Color32::from_rgb(61, 47, 24);
pub(crate) const DANGER: egui::Color32 = egui::Color32::from_rgb(239, 105, 105);
pub(crate) const DANGER_SOFT: egui::Color32 = egui::Color32::from_rgb(62, 29, 31);
pub(crate) const INFO: egui::Color32 = egui::Color32::from_rgb(111, 174, 255);
pub(crate) const INFO_SOFT: egui::Color32 = egui::Color32::from_rgb(27, 43, 65);

pub(crate) fn apply(context: &egui::Context) {
    let mut style = (*context.global_style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.interact_size = egui::vec2(40.0, 34.0);
    style.spacing.window_margin = egui::Margin::same(18);
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(10, 12, 15);
    style.visuals.faint_bg_color = SURFACE;
    style.visuals.code_bg_color = egui::Color32::from_rgb(10, 13, 16);
    style.visuals.window_corner_radius = egui::CornerRadius::same(14);
    style.visuals.menu_corner_radius = egui::CornerRadius::same(10);
    style.visuals.popup_shadow = egui::epaint::Shadow {
        offset: [0, 10],
        blur: 30,
        spread: 0,
        color: egui::Color32::from_black_alpha(110),
    };
    style.visuals.widgets.noninteractive.bg_fill = SURFACE;
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(30, 36, 43);
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.hovered.bg_fill = SURFACE_HOVER;
    style.visuals.widgets.hovered.bg_stroke =
        egui::Stroke::new(1.0, egui::Color32::from_rgb(65, 76, 87));
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.active.bg_fill = ACCENT_SOFT;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.selection.bg_fill = ACCENT_SOFT;
    style.visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    style.visuals.override_text_color = Some(TEXT);
    context.set_global_style(style);
    context.set_theme(egui::Theme::Dark);
}

pub(crate) fn page_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(egui::RichText::new(title).size(28.0).strong().color(TEXT));
    ui.add_space(3.0);
    ui.label(egui::RichText::new(subtitle).size(14.0).color(MUTED));
    ui.add_space(18.0);
}

pub(crate) fn section_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(egui::RichText::new(title).size(18.0).strong().color(TEXT));
    if !subtitle.is_empty() {
        ui.add_space(2.0);
        ui.label(egui::RichText::new(subtitle).size(13.0).color(MUTED));
    }
    ui.add_space(10.0);
}

pub(crate) fn card<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .corner_radius(egui::CornerRadius::same(12))
        .inner_margin(egui::Margin::same(16))
        .show(ui, add_contents)
        .inner
}

pub(crate) fn subtle_card<R>(
    ui: &mut egui::Ui,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(18, 22, 27))
        .stroke(egui::Stroke::new(1.0, BORDER))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(14))
        .show(ui, add_contents)
        .inner
}

pub(crate) fn status_badge(ui: &mut egui::Ui, label: &str, tone: StatusTone) {
    let (fill, text) = match tone {
        StatusTone::Success => (ACCENT_SOFT, ACCENT),
        StatusTone::Warning => (WARNING_SOFT, WARNING),
        StatusTone::Danger => (DANGER_SOFT, DANGER),
        StatusTone::Info => (INFO_SOFT, INFO),
        StatusTone::Neutral => (egui::Color32::from_rgb(34, 40, 47), MUTED),
    };
    egui::Frame::new()
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(20))
        .inner_margin(egui::Margin::symmetric(10, 5))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).size(12.0).strong().color(text));
        });
}

#[derive(Clone, Copy)]
pub(crate) enum StatusTone {
    Success,
    Warning,
    Danger,
    Info,
    Neutral,
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn metric(ui: &mut egui::Ui, label: &str, value: impl ToString, tone: StatusTone) {
    subtle_card(ui, |ui| {
        ui.set_min_width(150.0);
        ui.label(
            egui::RichText::new(value.to_string())
                .size(26.0)
                .strong()
                .color(TEXT),
        );
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            let color = match tone {
                StatusTone::Success => ACCENT,
                StatusTone::Warning => WARNING,
                StatusTone::Danger => DANGER,
                StatusTone::Info => INFO,
                StatusTone::Neutral => MUTED,
            };
            ui.label(egui::RichText::new("●").size(10.0).color(color));
            ui.label(egui::RichText::new(label).size(13.0).color(MUTED));
        });
    });
}

pub(crate) fn empty_state(ui: &mut egui::Ui, icon: &str, title: &str, body: &str) {
    subtle_card(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(12.0);
            ui.label(egui::RichText::new(icon).size(28.0).color(MUTED));
            ui.add_space(6.0);
            ui.label(egui::RichText::new(title).size(16.0).strong().color(TEXT));
            ui.label(egui::RichText::new(body).size(13.0).color(MUTED));
            ui.add_space(12.0);
        });
    });
}

pub(crate) fn danger_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(label).color(DANGER).strong())
        .fill(DANGER_SOFT)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(105, 48, 52)))
}

pub(crate) fn primary_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(label)
            .color(egui::Color32::from_rgb(8, 20, 14))
            .strong(),
    )
    .fill(ACCENT)
    .stroke(egui::Stroke::NONE)
}
