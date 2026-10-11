use eframe::egui;

pub(crate) const BG: egui::Color32 = egui::Color32::from_rgb(9, 14, 20);
pub(crate) const SIDEBAR: egui::Color32 = egui::Color32::from_rgb(12, 20, 29);
pub(crate) const SURFACE: egui::Color32 = egui::Color32::from_rgb(18, 28, 39);
pub(crate) const SURFACE_ALT: egui::Color32 = egui::Color32::from_rgb(14, 23, 33);
pub(crate) const SURFACE_HOVER: egui::Color32 = egui::Color32::from_rgb(24, 37, 50);
pub(crate) const BORDER: egui::Color32 = egui::Color32::from_rgb(39, 54, 69);
pub(crate) const BORDER_STRONG: egui::Color32 = egui::Color32::from_rgb(54, 72, 89);
pub(crate) const TEXT: egui::Color32 = egui::Color32::from_rgb(239, 244, 249);
pub(crate) const MUTED: egui::Color32 = egui::Color32::from_rgb(142, 158, 176);
pub(crate) const ACCENT: egui::Color32 = egui::Color32::from_rgb(22, 211, 154);
pub(crate) const ACCENT_SOFT: egui::Color32 = egui::Color32::from_rgb(12, 67, 55);
pub(crate) const WARNING: egui::Color32 = egui::Color32::from_rgb(245, 183, 58);
pub(crate) const WARNING_SOFT: egui::Color32 = egui::Color32::from_rgb(63, 48, 19);
pub(crate) const DANGER: egui::Color32 = egui::Color32::from_rgb(247, 104, 107);
pub(crate) const DANGER_SOFT: egui::Color32 = egui::Color32::from_rgb(66, 27, 33);
pub(crate) const INFO: egui::Color32 = egui::Color32::from_rgb(92, 157, 255);
pub(crate) const INFO_SOFT: egui::Color32 = egui::Color32::from_rgb(24, 43, 72);
pub(crate) const PURPLE: egui::Color32 = egui::Color32::from_rgb(165, 132, 255);
pub(crate) const PURPLE_SOFT: egui::Color32 = egui::Color32::from_rgb(48, 38, 75);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Icon {
    Home,
    Clipboard,
    Link,
    Shield,
    Key,
    FileText,
    Wrench,
    Lock,
    Monitor,
    Folder,
    Activity,
    AlertTriangle,
    Refresh,
    ChevronRight,
    Check,
    Server,
}

#[derive(Clone, Copy)]
pub(crate) enum StatusTone {
    Success,
    Warning,
    Danger,
    Info,
    Purple,
    Neutral,
}

pub(crate) fn apply(context: &egui::Context) {
    let mut style = (*context.global_style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.interact_size = egui::vec2(40.0, 36.0);
    style.spacing.window_margin = egui::Margin::same(18);
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = egui::Color32::from_rgb(7, 11, 16);
    style.visuals.faint_bg_color = SURFACE_ALT;
    style.visuals.code_bg_color = egui::Color32::from_rgb(8, 13, 18);
    style.visuals.window_corner_radius = egui::CornerRadius::same(12);
    style.visuals.menu_corner_radius = egui::CornerRadius::same(10);
    style.visuals.popup_shadow = egui::epaint::Shadow {
        offset: [0, 12],
        blur: 36,
        spread: 0,
        color: egui::Color32::from_black_alpha(135),
    };
    style.visuals.widgets.noninteractive.bg_fill = SURFACE;
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.inactive.bg_fill = SURFACE_ALT;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT);
    style.visuals.widgets.hovered.bg_fill = SURFACE_HOVER;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, BORDER_STRONG);
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

pub(crate) fn tone_colors(tone: StatusTone) -> (egui::Color32, egui::Color32) {
    match tone {
        StatusTone::Success => (ACCENT_SOFT, ACCENT),
        StatusTone::Warning => (WARNING_SOFT, WARNING),
        StatusTone::Danger => (DANGER_SOFT, DANGER),
        StatusTone::Info => (INFO_SOFT, INFO),
        StatusTone::Purple => (PURPLE_SOFT, PURPLE),
        StatusTone::Neutral => (egui::Color32::from_rgb(31, 42, 54), MUTED),
    }
}

pub(crate) fn page_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(egui::RichText::new(title).size(27.0).strong().color(TEXT));
    ui.add_space(2.0);
    ui.label(egui::RichText::new(subtitle).size(13.5).color(MUTED));
}

pub(crate) fn section_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(egui::RichText::new(title).size(16.0).strong().color(TEXT));
    if !subtitle.is_empty() {
        ui.add_space(2.0);
        ui.label(egui::RichText::new(subtitle).size(12.5).color(MUTED));
    }
    ui.add_space(10.0);
}

pub(crate) fn card<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .corner_radius(egui::CornerRadius::same(9))
        .inner_margin(egui::Margin::same(15))
        .show(ui, add_contents)
        .inner
}

pub(crate) fn subtle_card<R>(
    ui: &mut egui::Ui,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    egui::Frame::new()
        .fill(SURFACE_ALT)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .corner_radius(egui::CornerRadius::same(9))
        .inner_margin(egui::Margin::same(13))
        .show(ui, add_contents)
        .inner
}

pub(crate) fn status_badge(ui: &mut egui::Ui, label: &str, tone: StatusTone) {
    let (fill, text) = tone_colors(tone);
    egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, text.gamma_multiply(0.36)))
        .corner_radius(egui::CornerRadius::same(20))
        .inner_margin(egui::Margin::symmetric(9, 4))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).size(11.5).strong().color(text));
        });
}

pub(crate) fn icon(ui: &mut egui::Ui, icon: Icon, size: f32, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    paint_icon(ui.painter(), rect, icon, color, 1.7);
}

pub(crate) fn icon_box(ui: &mut egui::Ui, icon_kind: Icon, tone: StatusTone) {
    let (fill, color) = tone_colors(tone);
    egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(egui::CornerRadius::same(7))
        .inner_margin(egui::Margin::same(7))
        .show(ui, |ui| icon(ui, icon_kind, 18.0, color));
}

pub(crate) fn nav_item(
    ui: &mut egui::Ui,
    icon_kind: Icon,
    label: &str,
    selected: bool,
    badge: Option<usize>,
) -> egui::Response {
    let desired = egui::vec2(ui.available_width(), 42.0);
    let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::click());
    let hovered = response.hovered();
    let fill = if selected {
        ACCENT_SOFT
    } else if hovered {
        SURFACE_HOVER
    } else {
        egui::Color32::TRANSPARENT
    };
    let border = if selected {
        egui::Stroke::new(1.0, ACCENT.gamma_multiply(0.75))
    } else {
        egui::Stroke::NONE
    };
    ui.painter().rect_filled(rect, 7.0, fill);
    ui.painter()
        .rect_stroke(rect, 7.0, border, egui::StrokeKind::Inside);
    if selected {
        let accent_rect = egui::Rect::from_min_max(
            rect.left_top(),
            egui::pos2(rect.left() + 3.0, rect.bottom()),
        );
        ui.painter().rect_filled(accent_rect, 3.0, ACCENT);
    }
    let color = if selected { TEXT } else { MUTED };
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 22.0, rect.center().y),
        egui::vec2(18.0, 18.0),
    );
    paint_icon(ui.painter(), icon_rect, icon_kind, color, 1.6);
    ui.painter().text(
        egui::pos2(rect.left() + 43.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(13.5),
        color,
    );
    if let Some(count) = badge.filter(|value| *value > 0) {
        let center = egui::pos2(rect.right() - 17.0, rect.center().y);
        ui.painter().circle_filled(center, 10.0, WARNING_SOFT);
        ui.painter().text(
            center,
            egui::Align2::CENTER_CENTER,
            count.to_string(),
            egui::FontId::proportional(10.5),
            WARNING,
        );
    }
    response
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn metric_card(
    ui: &mut egui::Ui,
    icon_kind: Icon,
    title: &str,
    value: &str,
    detail: &str,
    action: &str,
    tone: StatusTone,
) -> egui::Response {
    let available = ui.available_width();
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(available, 180.0), egui::Sense::click());
    let fill = if response.hovered() {
        SURFACE_HOVER
    } else {
        SURFACE
    };
    ui.painter().rect_filled(rect, 9.0, fill);
    ui.painter().rect_stroke(
        rect,
        9.0,
        egui::Stroke::new(
            1.0,
            if response.hovered() {
                BORDER_STRONG
            } else {
                BORDER
            },
        ),
        egui::StrokeKind::Inside,
    );

    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect.shrink2(egui::vec2(14.0, 13.0)))
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    icon_box(&mut child, icon_kind, tone);
    child.add_space(8.0);
    child.label(egui::RichText::new(title).size(13.0).color(TEXT));
    child.add_space(1.0);
    child.label(egui::RichText::new(value).size(25.0).strong().color(TEXT));
    child.label(egui::RichText::new(detail).size(11.5).color(MUTED));

    let footer_y = rect.bottom() - 31.0;
    ui.painter().line_segment(
        [
            egui::pos2(rect.left(), footer_y),
            egui::pos2(rect.right(), footer_y),
        ],
        egui::Stroke::new(1.0, BORDER),
    );
    ui.painter().text(
        egui::pos2(rect.left() + 14.0, rect.bottom() - 15.5),
        egui::Align2::LEFT_CENTER,
        action,
        egui::FontId::proportional(11.5),
        MUTED,
    );
    let chevron_rect = egui::Rect::from_center_size(
        egui::pos2(rect.right() - 15.0, rect.bottom() - 15.5),
        egui::vec2(12.0, 12.0),
    );
    paint_icon(ui.painter(), chevron_rect, Icon::ChevronRight, MUTED, 1.4);
    response
}

pub(crate) fn toolbar_button(
    ui: &mut egui::Ui,
    icon_kind: Icon,
    label: &str,
    width: f32,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 36.0), egui::Sense::click());
    let fill = if response.hovered() {
        SURFACE_HOVER
    } else {
        SURFACE_ALT
    };
    ui.painter().rect_filled(rect, 7.0, fill);
    ui.painter().rect_stroke(
        rect,
        7.0,
        egui::Stroke::new(
            1.0,
            if response.hovered() {
                BORDER_STRONG
            } else {
                BORDER
            },
        ),
        egui::StrokeKind::Inside,
    );
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 18.0, rect.center().y),
        egui::vec2(16.0, 16.0),
    );
    paint_icon(ui.painter(), icon_rect, icon_kind, TEXT, 1.5);
    ui.painter().text(
        egui::pos2(rect.left() + 32.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(12.5),
        TEXT,
    );
    response
}

pub(crate) fn empty_state(ui: &mut egui::Ui, icon_kind: Icon, title: &str, body: &str) {
    subtle_card(ui, |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space(10.0);
            icon(ui, icon_kind, 30.0, MUTED);
            ui.add_space(7.0);
            ui.label(egui::RichText::new(title).size(15.0).strong().color(TEXT));
            ui.label(egui::RichText::new(body).size(12.5).color(MUTED));
            ui.add_space(10.0);
        });
    });
}

pub(crate) fn danger_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(label).color(DANGER).strong())
        .fill(DANGER_SOFT)
        .stroke(egui::Stroke::new(1.0, DANGER.gamma_multiply(0.45)))
        .corner_radius(egui::CornerRadius::same(7))
}

pub(crate) fn primary_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(label)
            .color(egui::Color32::from_rgb(5, 26, 19))
            .strong(),
    )
    .fill(ACCENT)
    .stroke(egui::Stroke::NONE)
    .corner_radius(egui::CornerRadius::same(7))
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn ring_gauge(ui: &mut egui::Ui, score: u32, label: &str) {
    let size = 148.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let center = rect.center();
    let radius = 56.0;
    ui.painter().circle_stroke(
        center,
        radius,
        egui::Stroke::new(8.0, egui::Color32::from_rgb(29, 61, 61)),
    );
    let start = -std::f32::consts::FRAC_PI_2;
    let sweep = std::f32::consts::TAU * (score.min(100) as f32 / 100.0);
    let steps = 48;
    let points = (0..=steps)
        .map(|step| {
            let angle = start + sweep * (step as f32 / steps as f32);
            center + egui::vec2(angle.cos() * radius, angle.sin() * radius)
        })
        .collect();
    ui.painter().add(egui::epaint::PathShape::line(
        points,
        egui::Stroke::new(8.0, ACCENT),
    ));
    ui.painter().text(
        center - egui::vec2(0.0, 7.0),
        egui::Align2::CENTER_CENTER,
        format!("{score}%"),
        egui::FontId::proportional(27.0),
        TEXT,
    );
    ui.painter().text(
        center + egui::vec2(0.0, 19.0),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::proportional(11.5),
        MUTED,
    );
}

fn paint_icon(
    painter: &egui::Painter,
    rect: egui::Rect,
    icon: Icon,
    color: egui::Color32,
    width: f32,
) {
    match icon {
        Icon::Home | Icon::Clipboard | Icon::Link | Icon::Shield | Icon::Key => {
            paint_navigation_icon(painter, rect, icon, color, width);
        }
        Icon::FileText | Icon::Wrench | Icon::Lock | Icon::Monitor | Icon::Folder => {
            paint_resource_icon(painter, rect, icon, color, width);
        }
        Icon::Activity
        | Icon::AlertTriangle
        | Icon::Refresh
        | Icon::ChevronRight
        | Icon::Check
        | Icon::Server => paint_status_icon(painter, rect, icon, color, width),
    }
}

fn paint_navigation_icon(
    painter: &egui::Painter,
    rect: egui::Rect,
    icon: Icon,
    color: egui::Color32,
    width: f32,
) {
    let stroke = egui::Stroke::new(width, color);
    let w = rect.width();
    let h = rect.height();
    let p = |x: f32, y: f32| egui::pos2(rect.left() + x * w, rect.top() + y * h);
    match icon {
        Icon::Home => {
            painter.line_segment([p(0.12, 0.48), p(0.50, 0.15)], stroke);
            painter.line_segment([p(0.50, 0.15), p(0.88, 0.48)], stroke);
            painter.line_segment([p(0.22, 0.42), p(0.22, 0.86)], stroke);
            painter.line_segment([p(0.78, 0.42), p(0.78, 0.86)], stroke);
            painter.line_segment([p(0.22, 0.86), p(0.78, 0.86)], stroke);
            painter.rect_stroke(
                egui::Rect::from_min_max(p(0.43, 0.60), p(0.58, 0.86)),
                1.0,
                stroke,
                egui::StrokeKind::Inside,
            );
        }
        Icon::Clipboard => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(0.20, 0.18), p(0.80, 0.88)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.rect_stroke(
                egui::Rect::from_min_max(p(0.36, 0.10), p(0.64, 0.29)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.line_segment([p(0.34, 0.48), p(0.68, 0.48)], stroke);
            painter.line_segment([p(0.34, 0.64), p(0.68, 0.64)], stroke);
        }
        Icon::Link => {
            painter.circle_stroke(p(0.35, 0.65), w * 0.23, stroke);
            painter.circle_stroke(p(0.65, 0.35), w * 0.23, stroke);
            painter.line_segment([p(0.41, 0.59), p(0.59, 0.41)], stroke);
        }
        Icon::Shield => {
            let points = vec![
                p(0.50, 0.08),
                p(0.82, 0.22),
                p(0.78, 0.62),
                p(0.50, 0.90),
                p(0.22, 0.62),
                p(0.18, 0.22),
                p(0.50, 0.08),
            ];
            painter.add(egui::epaint::PathShape::line(points, stroke));
            painter.line_segment([p(0.35, 0.49), p(0.46, 0.60)], stroke);
            painter.line_segment([p(0.46, 0.60), p(0.68, 0.36)], stroke);
        }
        Icon::Key => {
            painter.circle_stroke(p(0.35, 0.42), w * 0.22, stroke);
            painter.line_segment([p(0.50, 0.56), p(0.82, 0.84)], stroke);
            painter.line_segment([p(0.68, 0.70), p(0.77, 0.61)], stroke);
            painter.line_segment([p(0.75, 0.77), p(0.84, 0.68)], stroke);
        }
        _ => {}
    }
}

fn paint_resource_icon(
    painter: &egui::Painter,
    rect: egui::Rect,
    icon: Icon,
    color: egui::Color32,
    width: f32,
) {
    let stroke = egui::Stroke::new(width, color);
    let w = rect.width();
    let h = rect.height();
    let p = |x: f32, y: f32| egui::pos2(rect.left() + x * w, rect.top() + y * h);
    match icon {
        Icon::FileText => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(0.22, 0.10), p(0.78, 0.90)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.line_segment([p(0.58, 0.10), p(0.78, 0.30)], stroke);
            painter.line_segment([p(0.58, 0.10), p(0.58, 0.30)], stroke);
            painter.line_segment([p(0.58, 0.30), p(0.78, 0.30)], stroke);
            painter.line_segment([p(0.34, 0.50), p(0.66, 0.50)], stroke);
            painter.line_segment([p(0.34, 0.66), p(0.66, 0.66)], stroke);
        }
        Icon::Wrench => {
            painter.circle_stroke(p(0.30, 0.28), w * 0.18, stroke);
            painter.line_segment([p(0.42, 0.42), p(0.82, 0.82)], stroke);
            painter.circle_stroke(p(0.82, 0.82), w * 0.08, stroke);
        }
        Icon::Lock => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(0.22, 0.43), p(0.78, 0.88)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.add(egui::epaint::PathShape::line(
                vec![
                    p(0.34, 0.43),
                    p(0.34, 0.28),
                    p(0.42, 0.14),
                    p(0.58, 0.14),
                    p(0.66, 0.28),
                    p(0.66, 0.43),
                ],
                stroke,
            ));
        }
        Icon::Monitor => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(0.12, 0.16), p(0.88, 0.70)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.line_segment([p(0.50, 0.70), p(0.50, 0.86)], stroke);
            painter.line_segment([p(0.34, 0.86), p(0.66, 0.86)], stroke);
        }
        Icon::Folder => {
            painter.add(egui::epaint::PathShape::line(
                vec![
                    p(0.10, 0.28),
                    p(0.40, 0.28),
                    p(0.49, 0.40),
                    p(0.90, 0.40),
                    p(0.84, 0.84),
                    p(0.16, 0.84),
                    p(0.10, 0.28),
                ],
                stroke,
            ));
        }
        _ => {}
    }
}

fn paint_status_icon(
    painter: &egui::Painter,
    rect: egui::Rect,
    icon: Icon,
    color: egui::Color32,
    width: f32,
) {
    let stroke = egui::Stroke::new(width, color);
    let center = rect.center();
    let w = rect.width();
    let h = rect.height();
    let p = |x: f32, y: f32| egui::pos2(rect.left() + x * w, rect.top() + y * h);
    match icon {
        Icon::Activity => {
            painter.line_segment([p(0.08, 0.58), p(0.28, 0.58)], stroke);
            painter.line_segment([p(0.28, 0.58), p(0.40, 0.28)], stroke);
            painter.line_segment([p(0.40, 0.28), p(0.56, 0.75)], stroke);
            painter.line_segment([p(0.56, 0.75), p(0.70, 0.43)], stroke);
            painter.line_segment([p(0.70, 0.43), p(0.92, 0.43)], stroke);
        }
        Icon::AlertTriangle => {
            painter.add(egui::epaint::PathShape::line(
                vec![p(0.50, 0.08), p(0.91, 0.84), p(0.09, 0.84), p(0.50, 0.08)],
                stroke,
            ));
            painter.line_segment([p(0.50, 0.32), p(0.50, 0.59)], stroke);
            painter.circle_filled(p(0.50, 0.71), width * 0.75, color);
        }
        Icon::Refresh => paint_refresh_icon(painter, stroke, &p),
        Icon::ChevronRight => {
            painter.line_segment([p(0.34, 0.18), p(0.66, 0.50)], stroke);
            painter.line_segment([p(0.66, 0.50), p(0.34, 0.82)], stroke);
        }
        Icon::Check => {
            painter.circle_stroke(center, w * 0.42, stroke);
            painter.line_segment([p(0.28, 0.51), p(0.44, 0.67)], stroke);
            painter.line_segment([p(0.44, 0.67), p(0.73, 0.35)], stroke);
        }
        Icon::Server => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(0.14, 0.16), p(0.86, 0.43)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.rect_stroke(
                egui::Rect::from_min_max(p(0.14, 0.57), p(0.86, 0.84)),
                2.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.circle_filled(p(0.27, 0.30), width, color);
            painter.circle_filled(p(0.27, 0.70), width, color);
        }
        _ => {}
    }
}

fn paint_refresh_icon(
    painter: &egui::Painter,
    stroke: egui::Stroke,
    p: &impl Fn(f32, f32) -> egui::Pos2,
) {
    painter.add(egui::epaint::PathShape::line(
        vec![p(0.78, 0.36), p(0.88, 0.20), p(0.69, 0.18)],
        stroke,
    ));
    painter.add(egui::epaint::PathShape::line(
        vec![
            p(0.83, 0.28),
            p(0.66, 0.13),
            p(0.44, 0.10),
            p(0.24, 0.22),
            p(0.14, 0.42),
        ],
        stroke,
    ));
    painter.add(egui::epaint::PathShape::line(
        vec![p(0.22, 0.64), p(0.12, 0.80), p(0.31, 0.82)],
        stroke,
    ));
    painter.add(egui::epaint::PathShape::line(
        vec![
            p(0.17, 0.72),
            p(0.34, 0.87),
            p(0.56, 0.90),
            p(0.76, 0.78),
            p(0.86, 0.58),
        ],
        stroke,
    ));
}
