//! The app's badge on Windows (docs/PROTOCOL.md §11.13, §11.14 "Desktop"): the taskbar button's overlay icon, a red
//! disc with the count in white (99+ above 99), drawn here because Windows shows an icon there, not a number.

use tauri::image::Image;

const SIZE: usize = 32;
const RED: [u8; 3] = [0xc4, 0x2b, 0x1c];

/// Digits and the plus sign, 3 × 5 pixels each, one row per 3 bits.
const GLYPHS: [(char, [u8; 5]); 11] = [
    ('0', [0b111, 0b101, 0b101, 0b101, 0b111]),
    ('1', [0b010, 0b110, 0b010, 0b010, 0b111]),
    ('2', [0b111, 0b001, 0b111, 0b100, 0b111]),
    ('3', [0b111, 0b001, 0b111, 0b001, 0b111]),
    ('4', [0b101, 0b101, 0b111, 0b001, 0b001]),
    ('5', [0b111, 0b100, 0b111, 0b001, 0b111]),
    ('6', [0b111, 0b100, 0b111, 0b101, 0b111]),
    ('7', [0b111, 0b001, 0b001, 0b001, 0b001]),
    ('8', [0b111, 0b101, 0b111, 0b101, 0b111]),
    ('9', [0b111, 0b101, 0b111, 0b001, 0b111]),
    ('+', [0b000, 0b010, 0b111, 0b010, 0b000]),
];

/// The overlay for `count` unread conversations, or none for 0.
pub fn overlay(count: u32) -> Option<Image<'static>> {
    if count == 0 {
        return None;
    }
    let label = if count > 99 {
        "99+".to_string()
    } else {
        count.to_string()
    };
    let mut px = vec![0u8; SIZE * SIZE * 4];
    // The disc, with its edge smoothed over one pixel.
    let r = SIZE as f32 / 2.0;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (dx, dy) = (x as f32 + 0.5 - r, y as f32 + 0.5 - r);
            let cover = (r - (dx * dx + dy * dy).sqrt()).clamp(0.0, 1.0);
            let i = (y * SIZE + x) * 4;
            px[i..i + 3].copy_from_slice(&RED);
            px[i + 3] = (cover * 255.0).round() as u8;
        }
    }
    // The label, centred, as large as fits.
    let scale = if label.len() > 2 { 2 } else { 3 };
    let n = label.chars().count();
    let width = n * 3 * scale + (n - 1) * scale;
    let (x0, y0) = ((SIZE - width) / 2, (SIZE - 5 * scale) / 2);
    for (k, c) in label.chars().enumerate() {
        let Some((_, rows)) = GLYPHS.iter().find(|(g, _)| *g == c) else {
            continue;
        };
        let gx = x0 + k * 4 * scale;
        for (row, bits) in rows.iter().enumerate() {
            for col in 0..3 {
                if bits & (0b100 >> col) == 0 {
                    continue;
                }
                for y in y0 + row * scale..y0 + (row + 1) * scale {
                    for x in gx + col * scale..gx + (col + 1) * scale {
                        let i = (y * SIZE + x) * 4;
                        px[i..i + 4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
                    }
                }
            }
        }
    }
    Some(Image::new_owned(px, SIZE as u32, SIZE as u32))
}

#[cfg(test)]
mod tests {
    use super::overlay;

    #[test]
    fn none_for_zero() {
        assert!(overlay(0).is_none());
    }

    #[test]
    fn labels_fit() {
        for n in [1, 9, 10, 99, 100, 12345] {
            let img = overlay(n).expect("an overlay");
            assert_eq!((img.width(), img.height()), (32, 32));
        }
    }
}
