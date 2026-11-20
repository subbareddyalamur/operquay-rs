use serde::{Deserialize, Serialize};

pub mod attr {
    pub const BOLD: u16 = 1 << 0;
    pub const DIM: u16 = 1 << 1;
    pub const ITALIC: u16 = 1 << 2;
    pub const UNDERLINE: u16 = 1 << 3;
    pub const BLINK: u16 = 1 << 4;
    pub const INVERSE: u16 = 1 << 5;
    pub const HIDDEN: u16 = 1 << 6;
    pub const STRIKETHROUGH: u16 = 1 << 7;
    pub const WIDE_CONTINUATION: u16 = 1 << 8;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TermColor {
    #[default]
    Default,
    Indexed(u8),
    Rgb(u8, u8, u8),
}

impl TermColor {
    /// Convert color into packed `u32`:
    /// `0x0000_0000` = default,
    /// `0x0100_00II` = indexed 256-color,
    /// `0x02RR_GGBB` = 24-bit `TrueColor`.
    #[must_use]
    pub const fn to_packed_u32(self) -> u32 {
        match self {
            Self::Default => 0,
            Self::Indexed(idx) => 0x0100_0000 | (idx as u32),
            Self::Rgb(r, g, b) => 0x0200_0000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32),
        }
    }

    #[must_use]
    pub fn resolve_rgb(self, default_rgb: [u8; 3]) -> [u8; 3] {
        match self {
            Self::Default => default_rgb,
            Self::Rgb(r, g, b) => [r, g, b],
            Self::Indexed(idx) => xterm_256_to_rgb(idx),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub fg: TermColor,
    pub bg: TermColor,
    pub attrs: u16,
    pub width: u8,
    pub hyperlink_id: u32,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg: TermColor::Default,
            bg: TermColor::Default,
            attrs: 0,
            width: 1,
            hyperlink_id: 0,
        }
    }
}

const fn cube_step(v: u8) -> u8 {
    if v == 0 {
        0
    } else {
        55 + v * 40
    }
}

/// Convert standard Xterm 256-color index into `[r, g, b]` cleanly.
#[must_use]
pub const fn xterm_256_to_rgb(idx: u8) -> [u8; 3] {
    const ANSI16: [[u8; 3]; 16] = [
        [28, 33, 40],    // 0 black
        [244, 112, 103], // 1 red
        [87, 171, 90],   // 2 green
        [198, 144, 38],  // 3 yellow
        [83, 155, 245],  // 4 blue
        [176, 131, 240], // 5 magenta
        [63, 184, 175],  // 6 cyan (Operquay teal-aligned!)
        [173, 186, 199], // 7 white
        [118, 131, 144], // 8 bright black
        [255, 147, 138], // 9 bright red
        [107, 196, 109], // 10 bright green
        [218, 170, 63],  // 11 bright yellow
        [108, 182, 255], // 12 bright blue
        [220, 189, 251], // 13 bright magenta
        [118, 228, 247], // 14 bright cyan
        [230, 234, 240], // 15 bright white
    ];
    if idx < 16 {
        return ANSI16[idx as usize];
    }
    if idx < 232 {
        let c = idx - 16;
        let r = c / 36;
        let g = (c % 36) / 6;
        let b = c % 6;
        return [cube_step(r), cube_step(g), cube_step(b)];
    }
    let gray = 8 + (idx - 232) * 10;
    [gray, gray, gray]
}
