use eframe::egui;

const ICON_SIZE: usize = 64;
const ICON_SIZE_U32: u32 = 64;
const ICON_SIZE_ISIZE: isize = 64;
const BACKGROUND: [u8; 4] = [7, 28, 23, 255];
const ACCENT: [u8; 4] = [52, 211, 153, 255];

pub(crate) fn rgba() -> Vec<u8> {
    let mut pixels = vec![0_u8; ICON_SIZE * ICON_SIZE * 4];
    for y in 0..ICON_SIZE {
        for x in 0..ICON_SIZE {
            if inside_rounded_square(x, y) {
                set_pixel(&mut pixels, x, y, BACKGROUND);
            }
            if inside_mark(x, y) {
                set_pixel(&mut pixels, x, y, ACCENT);
            }
        }
    }
    pixels
}

pub(crate) fn egui_icon() -> egui::IconData {
    egui::IconData {
        rgba: rgba(),
        width: ICON_SIZE_U32,
        height: ICON_SIZE_U32,
    }
}

fn inside_rounded_square(x: usize, y: usize) -> bool {
    const INSET: isize = 3;
    const RADIUS: isize = 12;
    let x = x.cast_signed();
    let y = y.cast_signed();
    if x < INSET || y < INSET || x >= ICON_SIZE_ISIZE - INSET || y >= ICON_SIZE_ISIZE - INSET {
        return false;
    }
    let nearest_x = x.clamp(INSET + RADIUS, ICON_SIZE_ISIZE - INSET - RADIUS - 1);
    let nearest_y = y.clamp(INSET + RADIUS, ICON_SIZE_ISIZE - INSET - RADIUS - 1);
    let dx = x - nearest_x;
    let dy = y - nearest_y;
    dx * dx + dy * dy <= RADIUS * RADIUS
}

fn inside_mark(x: usize, y: usize) -> bool {
    let stem = (17..24).contains(&x) && (14..50).contains(&y);
    let upper = (21..40).contains(&x) && (14..21).contains(&y);
    let middle = (21..38).contains(&x) && (29..36).contains(&y);
    let bowl = (36..44).contains(&x) && (19..31).contains(&y);
    let leg = (34..51).contains(&y) && {
        let center = 24 + (y - 34) / 2;
        x.abs_diff(center) <= 3
    };
    stem || upper || middle || bowl || leg
}

fn set_pixel(pixels: &mut [u8], x: usize, y: usize, color: [u8; 4]) {
    let offset = (y * ICON_SIZE + x) * 4;
    pixels[offset..offset + 4].copy_from_slice(&color);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_has_expected_dimensions_and_transparency() {
        let icon = rgba();
        assert_eq!(icon.len(), ICON_SIZE * ICON_SIZE * 4);
        assert_eq!(&icon[..4], &[0, 0, 0, 0]);
        let center = ((ICON_SIZE / 2) * ICON_SIZE + ICON_SIZE / 2) * 4;
        assert_eq!(icon[center + 3], 255);
    }
}
