pub(crate) const DEFAULT_VIEWPORT: [f32; 2] = [1320.0, 860.0];
pub(crate) const MINIMUM_VIEWPORT: [f32; 2] = [1040.0, 680.0];
const SIDEBAR_MAX_WIDTH: f32 = 232.0;
const SIDEBAR_MAX_FRACTION: f32 = 0.25;
const SIX_METRIC_COLUMN_WIDTH: f32 = 1120.0;

pub(crate) fn sidebar_width(viewport_width: f32) -> f32 {
    SIDEBAR_MAX_WIDTH.min(viewport_width * SIDEBAR_MAX_FRACTION)
}

pub(crate) fn metric_columns(content_width: f32) -> usize {
    if content_width >= SIX_METRIC_COLUMN_WIDTH {
        6
    } else {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimum_viewport_keeps_a_stable_sidebar_and_three_metric_columns() {
        let sidebar = sidebar_width(MINIMUM_VIEWPORT[0]);
        assert!((sidebar - SIDEBAR_MAX_WIDTH).abs() < f32::EPSILON);
        let content = MINIMUM_VIEWPORT[0] - sidebar - 52.0;
        assert_eq!(metric_columns(content), 3);
    }

    #[test]
    fn wide_content_uses_all_six_metrics_without_changing_sidebar_width() {
        assert!((sidebar_width(1800.0) - SIDEBAR_MAX_WIDTH).abs() < f32::EPSILON);
        assert_eq!(metric_columns(1200.0), 6);
    }
}
