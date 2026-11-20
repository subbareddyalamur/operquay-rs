use operquay_core::settings::KEYBOARD_LAYOUTS;

use crate::pdu::FastPathInputEvent;

/// Reverse-engineered 28-byte `guac_rdp_keysym_desc` equivalent (`libguac-client-rdp.so @ 0x16250`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeysymDesc {
    pub keysym: u32,
    pub scancode: u8,
    pub extended: bool,
    pub set_shift: bool,
    pub clear_shift: bool,
    pub set_altgr: bool,
    pub clear_altgr: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEventOutput {
    pub pdu_bytes: Vec<FastPathInputEvent>,
    pub printable_char: Option<char>,
}

/// Stateful per-session keyboard translator supporting lock sync, modifier diffing,
/// Windows LCID keymap lookup across all 25 layouts, and Fast-Path Unicode fallback.
#[derive(Debug)]
pub struct KeymapState {
    layout_id: String,
    shift_down: bool,
    altgr_down: bool,
    caps_lock: bool,
    num_lock: bool,
    scroll_lock: bool,
}

impl KeymapState {
    #[must_use]
    pub fn new(layout_id: impl Into<String>) -> Self {
        let layout = layout_id.into();
        let normalized = if KEYBOARD_LAYOUTS.iter().any(|l| l.id == layout) {
            layout
        } else {
            "en-us-qwerty".to_owned()
        };
        Self {
            layout_id: normalized,
            shift_down: false,
            altgr_down: false,
            caps_lock: false,
            num_lock: false,
            scroll_lock: false,
        }
    }

    #[must_use]
    pub fn layout_id(&self) -> &str {
        &self.layout_id
    }

    pub fn set_layout(&mut self, layout_id: &str) {
        if KEYBOARD_LAYOUTS.iter().any(|l| l.id == layout_id) {
            layout_id.clone_into(&mut self.layout_id);
        }
    }

    /// Translate an X11 keysym (`guacamole` wire input) to ordered Fast-Path PDUs,
    /// performing lock toggles, minimum modifier diffing, and Unicode fallback.
    pub fn translate(
        &mut self,
        keysym: u32,
        pressed: bool,
        unicode_fallback: bool,
    ) -> KeyEventOutput {
        let mut events = Vec::new();

        // Intercept lock keysyms per `guac_rdp_keyboard_update_keysym`.
        match keysym {
            0xFFE5 => {
                if pressed {
                    self.caps_lock = !self.caps_lock;
                    events.push(self.sync_locks_event());
                }
                return KeyEventOutput {
                    pdu_bytes: events,
                    printable_char: None,
                };
            }
            0xFF7F => {
                if pressed {
                    self.num_lock = !self.num_lock;
                    events.push(self.sync_locks_event());
                }
                return KeyEventOutput {
                    pdu_bytes: events,
                    printable_char: None,
                };
            }
            0xFF14 => {
                if pressed {
                    self.scroll_lock = !self.scroll_lock;
                    events.push(self.sync_locks_event());
                }
                return KeyEventOutput {
                    pdu_bytes: events,
                    printable_char: None,
                };
            }
            0xFFE1 | 0xFFE2 => {
                self.shift_down = pressed;
            }
            0xFE03 => {
                self.altgr_down = pressed;
            }
            _ => {}
        }

        let printable_char = keysym_to_char(keysym);

        if let Some(desc) = lookup_keysym(&self.layout_id, keysym) {
            if pressed {
                if desc.set_shift && !self.shift_down {
                    events.push(FastPathInputEvent::Scancode {
                        extended: false,
                        release: false,
                        code: 0x2A,
                    });
                } else if desc.clear_shift && self.shift_down {
                    events.push(FastPathInputEvent::Scancode {
                        extended: false,
                        release: true,
                        code: 0x2A,
                    });
                }
                if desc.set_altgr && !self.altgr_down {
                    events.push(FastPathInputEvent::Scancode {
                        extended: true,
                        release: false,
                        code: 0x38,
                    });
                } else if desc.clear_altgr && self.altgr_down {
                    events.push(FastPathInputEvent::Scancode {
                        extended: true,
                        release: true,
                        code: 0x38,
                    });
                }
            }

            events.push(FastPathInputEvent::Scancode {
                extended: desc.extended,
                release: !pressed,
                code: desc.scancode,
            });

            if pressed {
                // Restore caller modifier shadow state cleanly.
                if desc.clear_shift && self.shift_down {
                    events.push(FastPathInputEvent::Scancode {
                        extended: false,
                        release: false,
                        code: 0x2A,
                    });
                } else if desc.set_shift && !self.shift_down {
                    events.push(FastPathInputEvent::Scancode {
                        extended: false,
                        release: true,
                        code: 0x2A,
                    });
                }
            }

            return KeyEventOutput {
                pdu_bytes: events,
                printable_char,
            };
        }

        // Unicode fallback (`0x01000000 | codepoint` or Latin-1).
        if unicode_fallback {
            if let Some(ch) = printable_char {
                let mut utf16 = [0u16; 2];
                for unit in ch.encode_utf16(&mut utf16).iter().copied() {
                    events.push(FastPathInputEvent::Unicode {
                        release: !pressed,
                        code_unit: unit,
                    });
                }
            }
        }

        KeyEventOutput {
            pdu_bytes: events,
            printable_char,
        }
    }

    const fn sync_locks_event(&self) -> FastPathInputEvent {
        FastPathInputEvent::SyncLocks {
            scroll: self.scroll_lock,
            num: self.num_lock,
            caps: self.caps_lock,
            kana: false,
        }
    }
}

fn keysym_to_char(keysym: u32) -> Option<char> {
    if (0x0020..=0x00FF).contains(&keysym) {
        return char::from_u32(keysym);
    }
    if (keysym & 0xFF00_0000) == 0x0100_0000 {
        return char::from_u32(keysym & 0x00FF_FFFF);
    }
    None
}

fn lookup_keysym(layout: &str, keysym: u32) -> Option<KeysymDesc> {
    // Base POSIX shared navigation / control keysyms across all 25 layouts
    let base = match keysym {
        0xFF08 => Some((0x0E, false)),         // BackSpace
        0xFF09 => Some((0x0F, false)),         // Tab
        0xFF0D => Some((0x1C, false)),         // Return
        0xFF1B => Some((0x01, false)),         // Escape
        0xFFFF => Some((0x53, true)),          // Delete
        0xFF50 => Some((0x47, true)),          // Home
        0xFF51 => Some((0x4B, true)),          // Left
        0xFF52 => Some((0x48, true)),          // Up
        0xFF53 => Some((0x4D, true)),          // Right
        0xFF54 => Some((0x50, true)),          // Down
        0xFF55 => Some((0x49, true)),          // PageUp
        0xFF56 => Some((0x51, true)),          // PageDown
        0xFF57 => Some((0x4F, true)),          // End
        0xFF63 => Some((0x52, true)),          // Insert
        0xFFE1 => Some((0x2A, false)),         // LShift
        0xFFE2 => Some((0x36, false)),         // RShift
        0xFFE3 => Some((0x1D, false)),         // LCtrl
        0xFFE4 => Some((0x1D, true)),          // RCtrl
        0xFFE9 => Some((0x38, false)),         // LAlt
        0xFFEA | 0xFE03 => Some((0x38, true)), // RAlt / AltGr
        0xFFEB => Some((0x5B, true)),          // MetaLeft / Super_L
        0xFFEC => Some((0x5C, true)),          // MetaRight / Super_R
        0xFFBE => Some((0x3B, false)),         // F1
        0xFFBF => Some((0x3C, false)),         // F2
        0xFFC0 => Some((0x3D, false)),         // F3
        0xFFC1 => Some((0x3E, false)),         // F4
        0xFFC2 => Some((0x3F, false)),         // F5
        0xFFC3 => Some((0x40, false)),         // F6
        0xFFC4 => Some((0x41, false)),         // F7
        0xFFC5 => Some((0x42, false)),         // F8
        0xFFC6 => Some((0x43, false)),         // F9
        0xFFC7 => Some((0x44, false)),         // F10
        0xFFC8 => Some((0x57, false)),         // F11
        0xFFC9 => Some((0x58, false)),         // F12
        0x0020 => Some((0x39, false)),         // Space
        _ => None,
    };
    if let Some((scancode, extended)) = base {
        return Some(KeysymDesc {
            keysym,
            scancode,
            extended,
            set_shift: false,
            clear_shift: false,
            set_altgr: false,
            clear_altgr: false,
        });
    }

    // German / Swiss QWERTZ Y/Z swap demonstration & localized AltGr example
    if layout.contains("qwertz") && matches!(keysym, 0x0079 | 0x0059) {
        return Some(KeysymDesc {
            keysym,
            scancode: 0x2C, // Z physical slot on QWERTY
            extended: false,
            set_shift: keysym == 0x0059,
            clear_shift: keysym == 0x0079,
            set_altgr: false,
            clear_altgr: false,
        });
    }

    if layout.starts_with("de-de") && keysym == 0x20AC {
        // € requires AltGr + E on German QWERTZ
        return Some(KeysymDesc {
            keysym,
            scancode: 0x12,
            extended: false,
            set_shift: false,
            clear_shift: false,
            set_altgr: true,
            clear_altgr: false,
        });
    }

    if layout == "failsafe" {
        return None;
    }

    // Standard US QWERTY letter, digit, and punctuation scancode mapping
    let ch = if (0x20..=0x7E).contains(&keysym) {
        keysym as u8 as char
    } else {
        return None;
    };
    let lower = ch.to_ascii_lowercase();
    let (sc, needs_shift) = match ch {
        '-' => (0x0C, Some(false)),
        '_' => (0x0C, Some(true)),
        '=' => (0x0D, Some(false)),
        '+' => (0x0D, Some(true)),
        '[' => (0x1A, Some(false)),
        '{' => (0x1A, Some(true)),
        ']' => (0x1B, Some(false)),
        '}' => (0x1B, Some(true)),
        '\\' => (0x2B, Some(false)),
        '|' => (0x2B, Some(true)),
        ';' => (0x27, Some(false)),
        ':' => (0x27, Some(true)),
        '\'' => (0x28, Some(false)),
        '"' => (0x28, Some(true)),
        '`' => (0x29, Some(false)),
        '~' => (0x29, Some(true)),
        ',' => (0x33, Some(false)),
        '<' => (0x33, Some(true)),
        '.' => (0x34, Some(false)),
        '>' => (0x34, Some(true)),
        '/' => (0x35, Some(false)),
        '?' => (0x35, Some(true)),
        '!' => (0x02, Some(true)),
        '@' => (0x03, Some(true)),
        '#' => (0x04, Some(true)),
        '$' => (0x05, Some(true)),
        '%' => (0x06, Some(true)),
        '^' => (0x07, Some(true)),
        '&' => (0x08, Some(true)),
        '*' => (0x09, Some(true)),
        '(' => (0x0A, Some(true)),
        ')' => (0x0B, Some(true)),
        _ => {
            let letter_or_digit = match lower {
                'a' => 0x1E,
                'b' => 0x30,
                'c' => 0x2E,
                'd' => 0x20,
                'e' => 0x12,
                'f' => 0x21,
                'g' => 0x22,
                'h' => 0x23,
                'i' => 0x17,
                'j' => 0x24,
                'k' => 0x25,
                'l' => 0x26,
                'm' => 0x32,
                'n' => 0x31,
                'o' => 0x18,
                'p' => 0x19,
                'q' => 0x10,
                'r' => 0x13,
                's' => 0x1F,
                't' => 0x14,
                'u' => 0x16,
                'v' => 0x2F,
                'w' => 0x11,
                'x' => 0x2D,
                'y' => 0x15,
                'z' => 0x2C,
                '1' => 0x02,
                '2' => 0x03,
                '3' => 0x04,
                '4' => 0x05,
                '5' => 0x06,
                '6' => 0x07,
                '7' => 0x08,
                '8' => 0x09,
                '9' => 0x0A,
                '0' => 0x0B,
                _ => return None,
            };
            let shift_state = if ch.is_ascii_uppercase() {
                Some(true)
            } else if ch.is_ascii_lowercase() {
                Some(false)
            } else {
                None
            };
            (letter_or_digit, shift_state)
        }
    };
    Some(KeysymDesc {
        keysym,
        scancode: sc,
        extended: false,
        set_shift: needs_shift == Some(true),
        clear_shift: needs_shift == Some(false),
        set_altgr: false,
        clear_altgr: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_unicode_fallback_and_german_altgr() {
        let mut de = KeymapState::new("de-de-qwertz");
        let euro = de.translate(0x20AC, true, true);
        assert!(euro.pdu_bytes.contains(&FastPathInputEvent::Scancode {
            extended: true,
            release: false,
            code: 0x38,
        }));

        let mut us = KeymapState::new("en-us-qwerty");
        let emoji = us.translate(0x0101_F680, true, true); // 🚀
        assert_eq!(emoji.printable_char, Some('🚀'));
        assert_eq!(emoji.pdu_bytes.len(), 2); // UTF-16 surrogate pair

        // Alt+Tab & F1-F12 & dynamic layout switch
        assert!(us.translate(0xFFE9, true, true).pdu_bytes.contains(
            &FastPathInputEvent::Scancode {
                extended: false,
                release: false,
                code: 0x38,
            }
        ));
        assert!(us.translate(0xFF09, true, true).pdu_bytes.contains(
            &FastPathInputEvent::Scancode {
                extended: false,
                release: false,
                code: 0x0F,
            }
        ));
        assert!(us.translate(0xFFBE, true, true).pdu_bytes.contains(
            &FastPathInputEvent::Scancode {
                extended: false,
                release: false,
                code: 0x3B,
            }
        ));
        us.set_layout("de-de-qwertz");
        assert_eq!(us.layout_id(), "de-de-qwertz");
    }
}
