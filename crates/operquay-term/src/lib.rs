#![forbid(unsafe_code)]

//! Clean-room `#![forbid(unsafe_code)]` ANSI/VT100/VT220/Xterm terminal engine
//! unifying `@xterm/xterm` and `@wterm/dom` features for both browser WebAssembly
//! (`operquay-term-wasm`) and server-side TrueType `.cast`/MP4 frame rasterization.

pub mod cell;

use std::collections::VecDeque;
use std::fmt::Write as _;

use cell::{attr, Cell, TermColor};
use serde::{Deserialize, Serialize};
use unicode_width::UnicodeWidthChar;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ParserState {
    #[default]
    Ground,
    Esc,
    EscCharset,
    CsiEntry,
    OscString,
    OscEsc,
    DcsIgnore,
    DcsEsc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum CursorStyle {
    Block = 0,
    Underline = 1,
    #[default]
    Bar = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchMatch {
    /// Absolute row index across scrollback + active screen.
    pub abs_row: usize,
    pub col_start: usize,
    pub col_end: usize,
}

#[derive(Debug, Clone)]
struct CursorState {
    col: u16,
    row: u16,
    fg: TermColor,
    bg: TermColor,
    attrs: u16,
    origin_mode: bool,
    wrap_next: bool,
}

impl Default for CursorState {
    fn default() -> Self {
        Self {
            col: 0,
            row: 0,
            fg: TermColor::Default,
            bg: TermColor::Default,
            attrs: 0,
            origin_mode: false,
            wrap_next: false,
        }
    }
}

/// Complete virtual terminal screen buffer + ANSI/VT state machine.
pub struct TerminalEngine {
    cols: u16,
    rows: u16,
    scrollback_limit: usize,
    scrollback: VecDeque<Vec<Cell>>,
    viewport_scroll: usize,
    grid: Vec<Vec<Cell>>,
    alt_grid: Vec<Vec<Cell>>,
    using_alt: bool,

    cursor: CursorState,
    saved_cursor: CursorState,
    alt_saved_cursor: CursorState,

    scroll_top: u16,
    scroll_bottom: u16,
    tab_stops: Vec<bool>,

    auto_wrap: bool,
    cursor_visible: bool,
    cursor_style: CursorStyle,
    app_cursor_keys: bool,
    bracketed_paste: bool,
    mouse_mode: u8,
    mouse_sgr: bool,
    g0_dec_graphics: bool,
    esc_charset_is_g0: bool,
    insert_mode: bool,
    last_graphic_char: Option<char>,

    title: String,
    cwd: String,
    hyperlinks: Vec<String>,
    active_hyperlink: u32,
    pending_clipboard: Option<String>,
    pending_replies: Vec<u8>,
    shell_prompts: Vec<usize>,

    parser_state: ParserState,
    utf8_buf: Vec<u8>,
    csi_buf: Vec<u8>,
    osc_buf: Vec<u8>,
}

impl TerminalEngine {
    #[must_use]
    pub fn new(cols: u16, rows: u16, scrollback_limit: usize) -> Self {
        let cols = cols.max(2);
        let rows = rows.max(1);
        let make_grid =
            |c: u16, r: u16| vec![vec![Cell::default(); usize::from(c)]; usize::from(r)];
        let tab_stops = (0..usize::from(cols))
            .map(|i| i % 8 == 0 && i > 0)
            .collect();

        Self {
            cols,
            rows,
            scrollback_limit: scrollback_limit.min(50_000),
            scrollback: VecDeque::with_capacity(scrollback_limit.min(1024)),
            viewport_scroll: 0,
            grid: make_grid(cols, rows),
            alt_grid: make_grid(cols, rows),
            using_alt: false,
            cursor: CursorState::default(),
            saved_cursor: CursorState::default(),
            alt_saved_cursor: CursorState::default(),
            scroll_top: 0,
            scroll_bottom: rows - 1,
            tab_stops,
            auto_wrap: true,
            cursor_visible: true,
            cursor_style: CursorStyle::Bar,
            app_cursor_keys: false,
            bracketed_paste: false,
            mouse_mode: 0,
            mouse_sgr: false,
            g0_dec_graphics: false,
            esc_charset_is_g0: true,
            insert_mode: false,
            last_graphic_char: None,
            title: String::new(),
            cwd: String::new(),
            hyperlinks: vec![String::new()],
            active_hyperlink: 0,
            pending_clipboard: None,
            pending_replies: Vec::new(),
            shell_prompts: Vec::new(),
            parser_state: ParserState::Ground,
            utf8_buf: Vec::with_capacity(4),
            csi_buf: Vec::with_capacity(64),
            osc_buf: Vec::with_capacity(256),
        }
    }

    #[must_use]
    pub const fn cols(&self) -> u16 {
        self.cols
    }

    #[must_use]
    pub const fn rows(&self) -> u16 {
        self.rows
    }

    #[must_use]
    pub const fn cursor_pos(&self) -> (u16, u16) {
        (self.cursor.col, self.cursor.row)
    }

    #[must_use]
    pub const fn bracketed_paste_enabled(&self) -> bool {
        self.bracketed_paste
    }

    #[must_use]
    pub const fn app_cursor_enabled(&self) -> bool {
        self.app_cursor_keys
    }

    #[must_use]
    pub const fn is_alt_screen(&self) -> bool {
        self.using_alt
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    #[must_use]
    pub fn hyperlink_url(&self, id: u32) -> Option<&str> {
        self.hyperlinks
            .get(id as usize)
            .filter(|s| !s.is_empty())
            .map(String::as_str)
    }

    pub fn take_replies(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending_replies)
    }

    pub fn take_clipboard(&mut self) -> Option<String> {
        self.pending_clipboard.take()
    }

    #[must_use]
    pub fn scrollback_len(&self) -> usize {
        if self.using_alt {
            0
        } else {
            self.scrollback.len()
        }
    }

    #[must_use]
    pub fn viewport_scroll(&self) -> usize {
        if self.using_alt {
            0
        } else {
            self.viewport_scroll.min(self.scrollback.len())
        }
    }

    /// Scroll viewport offset relative to bottom (`+` scrolls up into history, `-` down toward live).
    pub fn scroll_viewport(&mut self, delta_lines: isize) -> usize {
        if self.using_alt {
            self.viewport_scroll = 0;
            return 0;
        }
        let max = self.scrollback.len() as i128;
        let next = (self.viewport_scroll as i128 + delta_lines as i128).clamp(0, max);
        self.viewport_scroll = next as usize;
        self.viewport_scroll
    }

    /// Jump viewport to an exact number of lines above the live bottom.
    pub fn set_viewport_scroll(&mut self, offset: usize) -> usize {
        if self.using_alt {
            self.viewport_scroll = 0;
            return 0;
        }
        self.viewport_scroll = offset.min(self.scrollback.len());
        self.viewport_scroll
    }

    /// Update the scrollback capacity dynamically and trim oldest history if needed.
    pub fn set_scrollback_limit(&mut self, limit: usize) {
        let clamped = limit.min(50_000);
        self.scrollback_limit = clamped;
        while self.scrollback.len() > clamped {
            self.scrollback.pop_front();
        }
        self.viewport_scroll = self.viewport_scroll.min(self.scrollback.len());
    }

    /// Extract plain text across an inclusive cell coordinate range `(row, col)` across scrollback + grid.
    #[must_use]
    pub fn extract_range(
        &self,
        start_abs_row: usize,
        start_col: usize,
        end_abs_row: usize,
        end_col: usize,
    ) -> String {
        let total = self.scrollback_len() + usize::from(self.rows);
        if total == 0 {
            return String::new();
        }
        let ((sr, sc), (er, ec)) = if (start_abs_row, start_col) <= (end_abs_row, end_col) {
            ((start_abs_row, start_col), (end_abs_row, end_col))
        } else {
            ((end_abs_row, end_col), (start_abs_row, start_col))
        };
        if sr >= total {
            return String::new();
        }
        let er = er.min(total - 1);
        let mut lines = Vec::with_capacity(er - sr + 1);
        for r in sr..=er {
            let Some(row) = self.row_cells(r) else {
                lines.push(String::new());
                continue;
            };
            if row.is_empty() {
                lines.push(String::new());
                continue;
            }
            let mut c_start = if r == sr { sc } else { 0 };
            if c_start < row.len()
                && (row[c_start].attrs & attr::WIDE_CONTINUATION) != 0
                && c_start > 0
            {
                c_start -= 1;
            }
            let c_end_excl = if r == er {
                ec.saturating_add(1).min(row.len())
            } else {
                row.len()
            };
            if c_start >= c_end_excl {
                lines.push(String::new());
                continue;
            }
            let mut line: String = row[c_start..c_end_excl]
                .iter()
                .filter(|c| (c.attrs & attr::WIDE_CONTINUATION) == 0)
                .map(|c| c.ch)
                .collect();
            while line.ends_with(' ') {
                line.pop();
            }
            lines.push(line);
        }
        lines.join("\n")
    }

    #[must_use]
    pub fn row_cells(&self, abs_row: usize) -> Option<&[Cell]> {
        if self.using_alt {
            return self.grid.get(abs_row).map(Vec::as_slice);
        }
        if abs_row < self.scrollback.len() {
            return self.scrollback.get(abs_row).map(Vec::as_slice);
        }
        self.grid
            .get(abs_row - self.scrollback.len())
            .map(Vec::as_slice)
    }

    #[must_use]
    pub fn viewport_cells(&self) -> &[Vec<Cell>] {
        &self.grid
    }

    /// Feed raw PTY UTF-8/VT bytes incrementally into the terminal state machine.
    pub fn feed(&mut self, data: &[u8]) {
        for &byte in data {
            self.process_byte(byte);
        }
    }

    pub fn feed_str(&mut self, s: &str) {
        self.feed(s.as_bytes());
    }

    pub fn resize(&mut self, new_cols: u16, new_rows: u16) {
        let nc = new_cols.max(2);
        let nr = new_rows.max(1);
        if nc == self.cols && nr == self.rows {
            return;
        }
        self.grid = resize_grid(&self.grid, nc, nr);
        self.alt_grid = resize_grid(&self.alt_grid, nc, nr);
        self.cols = nc;
        self.rows = nr;
        self.cursor.col = self.cursor.col.min(nc - 1);
        self.cursor.row = self.cursor.row.min(nr - 1);
        self.cursor.wrap_next = false;
        self.scroll_top = 0;
        self.scroll_bottom = nr - 1;
        self.viewport_scroll = self.viewport_scroll.min(self.scrollback.len());
        self.tab_stops = (0..usize::from(nc)).map(|i| i % 8 == 0 && i > 0).collect();
    }

    /// Encode keyboard key events accurately respecting Application Cursor Mode (`DECCKM`).
    #[must_use]
    pub fn encode_key_input(&self, key: &str, ctrl: bool, alt: bool, _shift: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let ss3_or_csi = if self.app_cursor_keys {
            "\x1bO"
        } else {
            "\x1b["
        };

        let seq: Option<&[u8]> = match key {
            "Enter" => Some(b"\r"),
            "Backspace" => Some(b"\x7f"),
            "Tab" => Some(b"\t"),
            "Escape" => Some(b"\x1b"),
            "ArrowUp" => {
                out.extend_from_slice(ss3_or_csi.as_bytes());
                out.push(b'A');
                return out;
            }
            "ArrowDown" => {
                out.extend_from_slice(ss3_or_csi.as_bytes());
                out.push(b'B');
                return out;
            }
            "ArrowRight" => {
                out.extend_from_slice(ss3_or_csi.as_bytes());
                out.push(b'C');
                return out;
            }
            "ArrowLeft" => {
                out.extend_from_slice(ss3_or_csi.as_bytes());
                out.push(b'D');
                return out;
            }
            "Home" => Some(if self.app_cursor_keys {
                b"\x1bOH"
            } else {
                b"\x1b[H"
            }),
            "End" => Some(if self.app_cursor_keys {
                b"\x1bOF"
            } else {
                b"\x1b[F"
            }),
            "Insert" => Some(b"\x1b[2~"),
            "Delete" => Some(b"\x1b[3~"),
            "PageUp" => Some(b"\x1b[5~"),
            "PageDown" => Some(b"\x1b[6~"),
            "F1" => Some(b"\x1bOP"),
            "F2" => Some(b"\x1bOQ"),
            "F3" => Some(b"\x1bOR"),
            "F4" => Some(b"\x1bOS"),
            "F5" => Some(b"\x1b[15~"),
            "F6" => Some(b"\x1b[17~"),
            "F7" => Some(b"\x1b[18~"),
            "F8" => Some(b"\x1b[19~"),
            "F9" => Some(b"\x1b[20~"),
            "F10" => Some(b"\x1b[21~"),
            "F11" => Some(b"\x1b[23~"),
            "F12" => Some(b"\x1b[24~"),
            _ => None,
        };

        if let Some(bytes) = seq {
            out.extend_from_slice(bytes);
            return out;
        }

        let mut chars = key.chars();
        if let (Some(ch), None) = (chars.next(), chars.next()) {
            if ctrl {
                let lower = ch.to_ascii_lowercase();
                if lower.is_ascii_lowercase() {
                    if alt {
                        out.push(0x1B);
                    }
                    out.push((lower as u8) - b'a' + 1);
                    return out;
                }
                if ch == '[' {
                    out.push(0x1B);
                    return out;
                }
            }
            if alt {
                out.push(0x1B);
            }
            let mut tmp = [0u8; 4];
            let s = ch.encode_utf8(&mut tmp);
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    /// Encode clipboard paste honoring active `?2004` Bracketed Paste mode with ESC neutralization.
    #[must_use]
    pub fn encode_paste(&self, text: &str) -> Vec<u8> {
        if !self.bracketed_paste {
            return text.as_bytes().to_vec();
        }
        let sanitized = text.replace('\x1b', "");
        let mut out = Vec::with_capacity(sanitized.len() + 12);
        out.extend_from_slice(b"\x1b[200~");
        out.extend_from_slice(sanitized.as_bytes());
        out.extend_from_slice(b"\x1b[201~");
        out
    }

    /// Extract plain trimmed lines (`wterm.readText()` parity).
    #[must_use]
    pub fn plain_text(&self) -> String {
        let total = self.scrollback_len() + usize::from(self.rows);
        let mut lines = Vec::with_capacity(total);
        for r in 0..total {
            if let Some(cells) = self.row_cells(r) {
                lines.push(row_to_trimmed_string(cells));
            }
        }
        while lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        if lines.is_empty() {
            String::new()
        } else {
            let mut joined = lines.join("\r\n");
            joined.push_str("\r\n");
            joined
        }
    }

    /// Search across scrollback + viewport (`@xterm/addon-search` & `wterm.search` parity).
    #[must_use]
    pub fn search(&self, query: &str, case_sensitive: bool) -> Vec<SearchMatch> {
        if query.is_empty() {
            return Vec::new();
        }
        let needle = if case_sensitive {
            query.to_owned()
        } else {
            query.to_lowercase()
        };
        let total = self.scrollback_len() + usize::from(self.rows);
        let mut matches = Vec::new();
        for abs_row in 0..total {
            let Some(cells) = self.row_cells(abs_row) else {
                continue;
            };
            let line: String = cells
                .iter()
                .filter(|c| (c.attrs & attr::WIDE_CONTINUATION) == 0)
                .map(|c| c.ch)
                .collect();
            let hay = if case_sensitive {
                line
            } else {
                line.to_lowercase()
            };
            let mut offset = 0usize;
            while let Some(pos) = hay[offset..].find(&needle) {
                let start_byte = offset + pos;
                let char_start = hay[..start_byte].chars().count();
                let char_len = needle.chars().count();
                matches.push(SearchMatch {
                    abs_row,
                    col_start: char_start,
                    col_end: char_start + char_len,
                });
                offset = start_byte + needle.len().max(1);
            }
        }
        matches
    }

    /// Serialize complete visible + styled ANSI stream (`@xterm/addon-serialize` parity for split/swap).
    #[must_use]
    pub fn serialize_vt(&self) -> String {
        let mut out = String::with_capacity(usize::from(self.cols) * usize::from(self.rows) + 128);
        let total = self.scrollback_len() + usize::from(self.rows);
        let mut last_non_empty = 0usize;
        for r in 0..total {
            if let Some(row) = self.row_cells(r) {
                if !row_to_trimmed_string(row).is_empty() {
                    last_non_empty = r + 1;
                }
            }
        }

        let mut fg_state = TermColor::Default;
        let mut bg_state = TermColor::Default;
        let mut cur_attrs = 0u16;

        for r in 0..last_non_empty {
            let Some(row) = self.row_cells(r) else {
                continue;
            };
            let trimmed_cols = row
                .iter()
                .rposition(|c| {
                    c.ch != ' '
                        || c.bg != TermColor::Default
                        || (c.attrs & !attr::WIDE_CONTINUATION) != 0
                })
                .map_or(0, |i| i + 1);
            for cell in &row[..trimmed_cols] {
                if (cell.attrs & attr::WIDE_CONTINUATION) != 0 {
                    continue;
                }
                let cell_attrs = cell.attrs & !attr::WIDE_CONTINUATION;
                if cell.fg != fg_state || cell.bg != bg_state || cell_attrs != cur_attrs {
                    write_sgr_diff(&mut out, cell.fg, cell.bg, cell_attrs);
                    fg_state = cell.fg;
                    bg_state = cell.bg;
                    cur_attrs = cell_attrs;
                }
                out.push(cell.ch);
            }
            if r + 1 < last_non_empty {
                if bg_state != TermColor::Default
                    || cur_attrs != 0
                    || fg_state != TermColor::Default
                {
                    out.push_str("\x1b[0m");
                    fg_state = TermColor::Default;
                    bg_state = TermColor::Default;
                    cur_attrs = 0;
                }
                out.push_str("\r\n");
            }
        }
        if fg_state != TermColor::Default || bg_state != TermColor::Default || cur_attrs != 0 {
            out.push_str("\x1b[0m");
        }
        out
    }

    /// Encode zero-copy compact binary snapshot (`"OQTM"` header + active viewport grid).
    #[must_use]
    pub fn render_binary_snapshot(&self) -> Vec<u8> {
        let cell_count = usize::from(self.cols) * usize::from(self.rows);
        let mut out = Vec::with_capacity(24 + cell_count * 14);
        out.extend_from_slice(b"OQTM");
        out.extend_from_slice(&self.cols.to_le_bytes());
        out.extend_from_slice(&self.rows.to_le_bytes());
        out.extend_from_slice(&self.cursor.col.to_le_bytes());
        out.extend_from_slice(&self.cursor.row.to_le_bytes());
        let mut flags = 0u8;
        if self.cursor_visible {
            flags |= 1 << 0;
        }
        if self.bracketed_paste {
            flags |= 1 << 1;
        }
        if self.app_cursor_keys {
            flags |= 1 << 2;
        }
        if self.using_alt {
            flags |= 1 << 3;
        }
        out.push(flags);
        out.push(self.cursor_style as u8);
        out.extend_from_slice(&[0u8; 2]);
        out.extend_from_slice(&(self.scrollback_len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.viewport_scroll() as u32).to_le_bytes());

        let sb_len = self.scrollback_len();
        let vp_scroll = self.viewport_scroll();
        let start_abs = sb_len.saturating_sub(vp_scroll);
        let cols = usize::from(self.cols);
        let default_cell = Cell::default();
        for r in 0..usize::from(self.rows) {
            let row = self.row_cells(start_abs + r).unwrap_or(&[]);
            for c in 0..cols {
                let cell = row.get(c).unwrap_or(&default_cell);
                out.extend_from_slice(&(cell.ch as u32).to_le_bytes());
                out.extend_from_slice(&cell.fg.to_packed_u32().to_le_bytes());
                out.extend_from_slice(&cell.bg.to_packed_u32().to_le_bytes());
                out.extend_from_slice(&cell.attrs.to_le_bytes());
            }
        }
        out
    }

    fn process_byte(&mut self, byte: u8) {
        match self.parser_state {
            ParserState::Ground => self.process_ground_byte(byte),
            ParserState::Esc => self.process_esc_byte(byte),
            ParserState::EscCharset => {
                if self.esc_charset_is_g0 {
                    self.g0_dec_graphics = byte == b'0';
                }
                self.parser_state = ParserState::Ground;
            }
            ParserState::CsiEntry => self.process_csi_byte(byte),
            ParserState::OscString => {
                if byte == 0x07 {
                    self.dispatch_osc();
                    self.parser_state = ParserState::Ground;
                } else if byte == 0x1B {
                    self.parser_state = ParserState::OscEsc;
                } else if self.osc_buf.len() < 8192 {
                    self.osc_buf.push(byte);
                }
            }
            ParserState::OscEsc => {
                if byte == b'\\' {
                    self.dispatch_osc();
                    self.parser_state = ParserState::Ground;
                } else {
                    self.osc_buf.clear();
                    self.parser_state = ParserState::Ground;
                    self.process_esc_byte(byte);
                }
            }
            ParserState::DcsIgnore => {
                if byte == 0x1B {
                    self.parser_state = ParserState::DcsEsc;
                } else if byte == 0x07 {
                    self.parser_state = ParserState::Ground;
                }
            }
            ParserState::DcsEsc => {
                if byte == b'\\' {
                    self.parser_state = ParserState::Ground;
                } else {
                    self.parser_state = ParserState::DcsIgnore;
                }
            }
        }
    }

    fn process_ground_byte(&mut self, byte: u8) {
        if !self.utf8_buf.is_empty() && byte < 0x80 {
            self.utf8_buf.clear();
        }
        match byte {
            0x1B => {
                self.utf8_buf.clear();
                self.parser_state = ParserState::Esc;
            }
            b'\r' => {
                self.cursor.col = 0;
                self.cursor.wrap_next = false;
            }
            b'\n' | 0x0B | 0x0C => self.line_feed(),
            0x08 => {
                if self.cursor.wrap_next {
                    self.cursor.wrap_next = false;
                } else {
                    self.cursor.col = self.cursor.col.saturating_sub(1);
                }
            }
            b'\t' => {
                self.cursor.wrap_next = false;
                let cur = usize::from(self.cursor.col) + 1;
                let next_stop = self.tab_stops[cur.min(usize::from(self.cols))..]
                    .iter()
                    .position(|&s| s)
                    .map_or(usize::from(self.cols - 1), |p| cur + p);
                self.cursor.col = (next_stop as u16).min(self.cols - 1);
            }
            0x00..=0x1F | 0x7F => {}
            0x20..=0x7E => {
                let mut ch = byte as char;
                if self.g0_dec_graphics {
                    ch = map_dec_special_graphics(ch);
                }
                self.put_char(ch);
            }
            _ => {
                self.utf8_buf.push(byte);
                if let Ok(s) = std::str::from_utf8(&self.utf8_buf) {
                    if let Some(ch) = s.chars().next() {
                        self.put_char(ch);
                    }
                    self.utf8_buf.clear();
                } else if self.utf8_buf.len() >= 4 {
                    self.utf8_buf.clear();
                    self.put_char('\u{FFFD}');
                }
            }
        }
    }

    fn process_esc_byte(&mut self, byte: u8) {
        match byte {
            b'[' => {
                self.csi_buf.clear();
                self.parser_state = ParserState::CsiEntry;
            }
            b']' => {
                self.osc_buf.clear();
                self.parser_state = ParserState::OscString;
            }
            b'P' | b'_' | b'^' | b'X' => {
                self.parser_state = ParserState::DcsIgnore;
            }
            b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/' | b'#' | b'%' | b' ' => {
                self.esc_charset_is_g0 = byte == b'(';
                self.parser_state = ParserState::EscCharset;
            }
            b'7' => {
                self.saved_cursor = self.cursor.clone();
                self.parser_state = ParserState::Ground;
            }
            b'8' => {
                self.cursor = self.saved_cursor.clone();
                self.cursor.col = self.cursor.col.min(self.cols - 1);
                self.cursor.row = self.cursor.row.min(self.rows - 1);
                self.parser_state = ParserState::Ground;
            }
            b'D' => {
                self.line_feed();
                self.parser_state = ParserState::Ground;
            }
            b'M' => {
                self.reverse_index();
                self.parser_state = ParserState::Ground;
            }
            b'E' => {
                self.cursor.col = 0;
                self.line_feed();
                self.parser_state = ParserState::Ground;
            }
            b'H' => {
                if let Some(slot) = self.tab_stops.get_mut(usize::from(self.cursor.col)) {
                    *slot = true;
                }
                self.parser_state = ParserState::Ground;
            }
            b'c' => {
                let (c, r, lim) = (self.cols, self.rows, self.scrollback_limit);
                *self = Self::new(c, r, lim);
            }
            _ => {
                self.parser_state = ParserState::Ground;
            }
        }
    }

    fn process_csi_byte(&mut self, byte: u8) {
        if (0x40..=0x7E).contains(&byte) {
            let final_ch = byte as char;
            let raw = String::from_utf8_lossy(&self.csi_buf).into_owned();
            self.parser_state = ParserState::Ground;
            self.dispatch_csi(&raw, final_ch);
        } else if byte == 0x1B {
            self.parser_state = ParserState::Esc;
        } else if byte == 0x18 || byte == 0x1A {
            self.csi_buf.clear();
            self.parser_state = ParserState::Ground;
        } else if (0x00..=0x1F).contains(&byte) {
            self.process_ground_byte(byte);
        } else if byte != 0x7F && self.csi_buf.len() < 256 {
            self.csi_buf.push(byte);
        }
    }

    fn dispatch_csi(&mut self, raw: &str, final_ch: char) {
        let is_private = raw.starts_with('?');
        let stripped = raw.trim_start_matches('?').trim_start_matches('>');
        let params: Vec<u16> = if stripped.is_empty() {
            Vec::new()
        } else {
            stripped
                .split(';')
                .map(|p| p.parse::<u16>().unwrap_or(0))
                .collect()
        };
        let p = |idx: usize, default: u16| -> u16 {
            params
                .get(idx)
                .copied()
                .filter(|&v| v != 0)
                .unwrap_or(default)
        };

        if raw.starts_with('>')
            || raw.starts_with('<')
            || raw.starts_with('=')
            || raw.starts_with('!')
        {
            if raw == "!" && final_ch == 'p' {
                self.insert_mode = false;
                self.app_cursor_keys = false;
                self.cursor_visible = true;
                self.cursor.origin_mode = false;
                self.auto_wrap = true;
                self.scroll_top = 0;
                self.scroll_bottom = self.rows - 1;
                self.reset_sgr();
            }
            return;
        }

        if is_private {
            match final_ch {
                'h' | 'l' => {
                    let enable = final_ch == 'h';
                    for &mode in &params {
                        self.set_dec_mode(mode, enable);
                    }
                }
                _ => {}
            }
            return;
        }

        match final_ch {
            'A' => {
                let n = p(0, 1);
                self.cursor.row = self.cursor.row.saturating_sub(n).max(self.scroll_top);
                self.cursor.wrap_next = false;
            }
            'B' | 'e' => {
                let n = p(0, 1);
                self.cursor.row = (self.cursor.row + n).min(self.scroll_bottom);
                self.cursor.wrap_next = false;
            }
            'C' | 'a' => {
                let n = p(0, 1);
                self.cursor.col = (self.cursor.col + n).min(self.cols - 1);
                self.cursor.wrap_next = false;
            }
            'D' => {
                let n = p(0, 1);
                self.cursor.col = self.cursor.col.saturating_sub(n);
                self.cursor.wrap_next = false;
            }
            'E' => {
                let n = p(0, 1);
                self.cursor.row = (self.cursor.row + n).min(self.rows - 1);
                self.cursor.col = 0;
                self.cursor.wrap_next = false;
            }
            'F' => {
                let n = p(0, 1);
                self.cursor.row = self.cursor.row.saturating_sub(n);
                self.cursor.col = 0;
                self.cursor.wrap_next = false;
            }
            'G' | '`' => {
                self.cursor.col = p(0, 1).saturating_sub(1).min(self.cols - 1);
                self.cursor.wrap_next = false;
            }
            'd' => {
                self.cursor.row = p(0, 1).saturating_sub(1).min(self.rows - 1);
                self.cursor.wrap_next = false;
            }
            'H' | 'f' => {
                let row = p(0, 1).saturating_sub(1);
                let col = p(1, 1).saturating_sub(1).min(self.cols - 1);
                let abs_row = if self.cursor.origin_mode {
                    (self.scroll_top + row).min(self.scroll_bottom)
                } else {
                    row.min(self.rows - 1)
                };
                self.cursor.row = abs_row;
                self.cursor.col = col;
                self.cursor.wrap_next = false;
            }
            'J' => {
                let mode = params.first().copied().unwrap_or(0);
                self.erase_in_display(mode);
            }
            'K' => {
                let mode = params.first().copied().unwrap_or(0);
                self.erase_in_line(mode);
            }
            'L' => {
                let n = p(0, 1);
                self.insert_lines(n);
            }
            'M' => {
                let n = p(0, 1);
                self.delete_lines(n);
            }
            '@' => {
                let n = p(0, 1) as usize;
                let blank = self.blank_cell();
                let row = &mut self.grid[usize::from(self.cursor.row)];
                let col = usize::from(self.cursor.col);
                let count = n.min(row.len().saturating_sub(col));
                row[col..].rotate_right(count);
                for cell in &mut row[col..col + count] {
                    *cell = blank.clone();
                }
            }
            'P' => {
                let n = p(0, 1) as usize;
                let blank = self.blank_cell();
                let row = &mut self.grid[usize::from(self.cursor.row)];
                let col = usize::from(self.cursor.col);
                let count = n.min(row.len().saturating_sub(col));
                row[col..].rotate_left(count);
                let start = row.len().saturating_sub(count);
                for cell in &mut row[start..] {
                    *cell = blank.clone();
                }
            }
            'X' => {
                let n = p(0, 1) as usize;
                let col = usize::from(self.cursor.col);
                let end = (col + n).min(usize::from(self.cols));
                let blank = self.blank_cell();
                for cell in &mut self.grid[usize::from(self.cursor.row)][col..end] {
                    *cell = blank.clone();
                }
            }
            'S' => {
                let n = p(0, 1);
                self.scroll_up_region(self.scroll_top, self.scroll_bottom, n);
            }
            'T' => {
                let n = p(0, 1);
                self.scroll_down_region(self.scroll_top, self.scroll_bottom, n);
            }
            'r' => {
                let top = p(0, 1).saturating_sub(1).min(self.rows - 1);
                let bot = p(1, self.rows).saturating_sub(1).min(self.rows - 1);
                if top < bot {
                    self.scroll_top = top;
                    self.scroll_bottom = bot;
                } else {
                    self.scroll_top = 0;
                    self.scroll_bottom = self.rows - 1;
                }
                self.cursor.row = if self.cursor.origin_mode {
                    self.scroll_top
                } else {
                    0
                };
                self.cursor.col = 0;
                self.cursor.wrap_next = false;
            }
            'h' | 'l' => {
                let enable = final_ch == 'h';
                for &m in &params {
                    if m == 4 {
                        self.insert_mode = enable;
                    }
                }
            }
            'b' => {
                if let Some(ch) = self.last_graphic_char {
                    let n = p(0, 1).min(self.cols);
                    for _ in 0..n {
                        self.put_char(ch);
                    }
                }
            }
            'I' => {
                self.cursor.wrap_next = false;
                let mut col = usize::from(self.cursor.col);
                let max_c = usize::from(self.cols - 1);
                for _ in 0..p(0, 1) {
                    col = ((col + 1)..=max_c)
                        .find(|&i| self.tab_stops.get(i).copied().unwrap_or(false))
                        .unwrap_or(max_c);
                }
                self.cursor.col = col as u16;
            }
            'Z' => {
                self.cursor.wrap_next = false;
                let mut col = usize::from(self.cursor.col);
                for _ in 0..p(0, 1) {
                    col = (0..col)
                        .rev()
                        .find(|&i| self.tab_stops.get(i).copied().unwrap_or(false))
                        .unwrap_or(0);
                }
                self.cursor.col = col as u16;
            }
            's' if raw.is_empty() => {
                self.saved_cursor = self.cursor.clone();
            }
            'u' if raw.is_empty() => {
                self.cursor = self.saved_cursor.clone();
                self.cursor.col = self.cursor.col.min(self.cols - 1);
                self.cursor.row = self.cursor.row.min(self.rows - 1);
            }
            'm' => {
                if raw.starts_with('>') {
                    return;
                }
                self.apply_sgr(stripped);
            }
            'n' => {
                let code = params.first().copied().unwrap_or(0);
                if code == 5 {
                    self.pending_replies.extend_from_slice(b"\x1b[0n");
                } else if code == 6 {
                    let reply = format!("\x1b[{};{}R", self.cursor.row + 1, self.cursor.col + 1);
                    self.pending_replies.extend_from_slice(reply.as_bytes());
                }
            }
            'c' => {
                if raw.is_empty() || raw == "0" {
                    self.pending_replies.extend_from_slice(b"\x1b[?62;c");
                }
            }
            'q' if raw.ends_with(' ') => {
                let style_num = raw.trim_end_matches(' ').parse::<u16>().unwrap_or(0);
                self.cursor_style = match style_num {
                    1 | 2 => CursorStyle::Block,
                    3 | 4 => CursorStyle::Underline,
                    _ => CursorStyle::Bar,
                };
            }
            _ => {}
        }
    }

    fn set_dec_mode(&mut self, mode: u16, enable: bool) {
        match mode {
            1 => self.app_cursor_keys = enable,
            6 => {
                self.cursor.origin_mode = enable;
                self.cursor.col = 0;
                self.cursor.row = if enable { self.scroll_top } else { 0 };
            }
            7 => self.auto_wrap = enable,
            25 => self.cursor_visible = enable,
            47 | 1047 => self.switch_alt_screen(enable, false),
            1048 => {
                if enable {
                    self.saved_cursor = self.cursor.clone();
                } else {
                    self.cursor = self.saved_cursor.clone();
                    self.cursor.col = self.cursor.col.min(self.cols - 1);
                    self.cursor.row = self.cursor.row.min(self.rows - 1);
                }
            }
            1049 => self.switch_alt_screen(enable, true),
            1000 => self.mouse_mode = u8::from(enable),
            1002 => self.mouse_mode = if enable { 2 } else { 0 },
            1003 => self.mouse_mode = if enable { 3 } else { 0 },
            1006 => self.mouse_sgr = enable,
            2004 => self.bracketed_paste = enable,
            _ => {}
        }
    }

    fn switch_alt_screen(&mut self, enable: bool, save_restore: bool) {
        if enable == self.using_alt {
            return;
        }
        if enable {
            if save_restore {
                self.alt_saved_cursor = self.cursor.clone();
            }
            self.viewport_scroll = 0;
            std::mem::swap(&mut self.grid, &mut self.alt_grid);
            self.using_alt = true;
            self.clear_active_grid();
            self.cursor.col = 0;
            self.cursor.row = 0;
            self.cursor.wrap_next = false;
        } else {
            std::mem::swap(&mut self.grid, &mut self.alt_grid);
            self.using_alt = false;
            if save_restore {
                self.cursor = self.alt_saved_cursor.clone();
                self.cursor.col = self.cursor.col.min(self.cols - 1);
                self.cursor.row = self.cursor.row.min(self.rows - 1);
            }
        }
    }

    fn clear_active_grid(&mut self) {
        for row in &mut self.grid {
            for cell in row {
                *cell = Cell::default();
            }
        }
    }

    fn dispatch_osc(&mut self) {
        let s = String::from_utf8_lossy(&self.osc_buf).into_owned();
        self.osc_buf.clear();
        let Some((code_str, body)) = s.split_once(';') else {
            return;
        };
        match code_str {
            "0" | "2" => body.clone_into(&mut self.title),
            "7" => body.clone_into(&mut self.cwd),
            "8" => {
                if let Some((_params, uri)) = body.split_once(';') {
                    if uri.is_empty() {
                        self.active_hyperlink = 0;
                    } else {
                        let id = self.hyperlinks.len() as u32;
                        self.hyperlinks.push(uri.to_owned());
                        self.active_hyperlink = id;
                    }
                }
            }
            "52" => {
                if let Some((_sel, b64)) = body.split_once(';') {
                    if !b64.is_empty() && b64 != "?" {
                        self.pending_clipboard = Some(b64.to_owned());
                    }
                }
            }
            "133" if body.starts_with('A') => {
                self.shell_prompts
                    .push(self.scrollback_len() + usize::from(self.cursor.row));
            }
            _ => {}
        }
    }

    fn apply_sgr(&mut self, param_str: &str) {
        if param_str.is_empty() {
            self.reset_sgr();
            return;
        }
        // Normalize colon-delimited subparameters (`38:2::r:g:b`) seamlessly cleanly
        let normalized = param_str.replace(':', ";");
        let nums: Vec<u16> = normalized
            .split(';')
            .map(|p| p.parse::<u16>().unwrap_or(0))
            .collect();
        let mut i = 0usize;
        while i < nums.len() {
            match nums[i] {
                0 => self.reset_sgr(),
                1 => self.cursor.attrs |= attr::BOLD,
                2 => self.cursor.attrs |= attr::DIM,
                3 => self.cursor.attrs |= attr::ITALIC,
                4 => self.cursor.attrs |= attr::UNDERLINE,
                5 | 6 => self.cursor.attrs |= attr::BLINK,
                7 => self.cursor.attrs |= attr::INVERSE,
                8 => self.cursor.attrs |= attr::HIDDEN,
                9 => self.cursor.attrs |= attr::STRIKETHROUGH,
                22 => self.cursor.attrs &= !(attr::BOLD | attr::DIM),
                23 => self.cursor.attrs &= !attr::ITALIC,
                24 => self.cursor.attrs &= !attr::UNDERLINE,
                25 => self.cursor.attrs &= !attr::BLINK,
                27 => self.cursor.attrs &= !attr::INVERSE,
                28 => self.cursor.attrs &= !attr::HIDDEN,
                29 => self.cursor.attrs &= !attr::STRIKETHROUGH,
                30..=37 => self.cursor.fg = TermColor::Indexed((nums[i] - 30) as u8),
                39 => self.cursor.fg = TermColor::Default,
                40..=47 => self.cursor.bg = TermColor::Indexed((nums[i] - 40) as u8),
                49 => self.cursor.bg = TermColor::Default,
                90..=97 => self.cursor.fg = TermColor::Indexed((nums[i] - 90 + 8) as u8),
                100..=107 => self.cursor.bg = TermColor::Indexed((nums[i] - 100 + 8) as u8),
                38 | 48 => {
                    let is_fg = nums[i] == 38;
                    if let Some(&kind) = nums.get(i + 1) {
                        if kind == 5 {
                            if let Some(&idx) = nums.get(i + 2) {
                                let col = TermColor::Indexed(idx.min(255) as u8);
                                if is_fg {
                                    self.cursor.fg = col;
                                } else {
                                    self.cursor.bg = col;
                                }
                                i += 2;
                            }
                        } else if kind == 2 {
                            // Support both `38;2;r;g;b` and ITU `38:2::r:g:b`
                            let offset = if nums.len() > i + 5 && nums[i + 2] == 0 {
                                3
                            } else {
                                2
                            };
                            if let (Some(&r), Some(&g), Some(&b)) = (
                                nums.get(i + offset),
                                nums.get(i + offset + 1),
                                nums.get(i + offset + 2),
                            ) {
                                let col = TermColor::Rgb(
                                    r.min(255) as u8,
                                    g.min(255) as u8,
                                    b.min(255) as u8,
                                );
                                if is_fg {
                                    self.cursor.fg = col;
                                } else {
                                    self.cursor.bg = col;
                                }
                                i += offset + 2;
                            }
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn reset_sgr(&mut self) {
        self.cursor.fg = TermColor::Default;
        self.cursor.bg = TermColor::Default;
        self.cursor.attrs = 0;
    }

    fn blank_cell(&self) -> Cell {
        Cell {
            ch: ' ',
            fg: TermColor::Default,
            bg: self.cursor.bg,
            attrs: 0,
            width: 1,
            hyperlink_id: 0,
        }
    }

    fn put_char(&mut self, ch: char) {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0) as u8;
        if w == 0 {
            return;
        }
        self.last_graphic_char = Some(ch);
        if self.cursor.wrap_next {
            if self.auto_wrap {
                self.cursor.col = 0;
                self.line_feed();
            }
            self.cursor.wrap_next = false;
        }

        if w == 2 && self.cursor.col + 1 >= self.cols {
            if self.auto_wrap {
                let col = usize::from(self.cursor.col);
                self.grid[usize::from(self.cursor.row)][col] = self.blank_cell();
                self.cursor.col = 0;
                self.line_feed();
            } else {
                return;
            }
        }

        let r = usize::from(self.cursor.row);
        let c = usize::from(self.cursor.col);
        let cols_len = usize::from(self.cols);
        let blank = self.blank_cell();

        if self.insert_mode {
            if (self.grid[r][c].attrs & attr::WIDE_CONTINUATION) != 0 && c > 0 {
                self.grid[r][c - 1] = blank.clone();
            }
            let shift = usize::from(w).min(cols_len.saturating_sub(c));
            self.grid[r][c..].rotate_right(shift);
            for slot in &mut self.grid[r][c..c + shift] {
                *slot = blank.clone();
            }
            if cols_len > 0 && self.grid[r][cols_len - 1].width == 2 {
                self.grid[r][cols_len - 1] = blank.clone();
            }
        } else {
            if (self.grid[r][c].attrs & attr::WIDE_CONTINUATION) != 0 && c > 0 {
                self.grid[r][c - 1] = blank.clone();
            } else if self.grid[r][c].width == 2 && c + 1 < cols_len {
                self.grid[r][c + 1] = blank.clone();
            }
            if w == 2 && c + 1 < cols_len && self.grid[r][c + 1].width == 2 && c + 2 < cols_len {
                self.grid[r][c + 2] = blank.clone();
            }
        }

        self.grid[r][c] = Cell {
            ch,
            fg: self.cursor.fg,
            bg: self.cursor.bg,
            attrs: self.cursor.attrs,
            width: w,
            hyperlink_id: self.active_hyperlink,
        };
        if w == 2 && c + 1 < cols_len {
            self.grid[r][c + 1] = Cell {
                ch: ' ',
                fg: self.cursor.fg,
                bg: self.cursor.bg,
                attrs: attr::WIDE_CONTINUATION,
                width: 0,
                hyperlink_id: self.active_hyperlink,
            };
        }

        let advance = u16::from(w);
        if self.cursor.col + advance >= self.cols {
            if self.auto_wrap {
                self.cursor.wrap_next = true;
            }
            self.cursor.col = self.cols - 1;
        } else {
            self.cursor.col += advance;
        }
    }

    fn line_feed(&mut self) {
        self.cursor.wrap_next = false;
        if self.cursor.row == self.scroll_bottom {
            self.scroll_up_region(self.scroll_top, self.scroll_bottom, 1);
        } else if self.cursor.row + 1 < self.rows {
            self.cursor.row += 1;
        }
    }

    fn reverse_index(&mut self) {
        self.cursor.wrap_next = false;
        if self.cursor.row == self.scroll_top {
            self.scroll_down_region(self.scroll_top, self.scroll_bottom, 1);
        } else {
            self.cursor.row = self.cursor.row.saturating_sub(1);
        }
    }

    fn scroll_up_region(&mut self, top: u16, bottom: u16, count: u16) {
        let t = usize::from(top);
        let b = usize::from(bottom).min(self.grid.len().saturating_sub(1));
        if t > b {
            return;
        }
        let n = usize::from(count).min(b - t + 1);
        for _ in 0..n {
            let removed = self.grid.remove(t);
            if !self.using_alt && t == 0 && self.scrollback_limit > 0 {
                self.scrollback.push_back(removed);
                while self.scrollback.len() > self.scrollback_limit {
                    self.scrollback.pop_front();
                }
                if self.viewport_scroll > 0 {
                    self.viewport_scroll = (self.viewport_scroll + 1).min(self.scrollback.len());
                }
            }
            self.grid
                .insert(b, vec![self.blank_cell(); usize::from(self.cols)]);
        }
    }

    fn scroll_down_region(&mut self, top: u16, bottom: u16, count: u16) {
        let t = usize::from(top);
        let b = usize::from(bottom).min(self.grid.len().saturating_sub(1));
        if t > b {
            return;
        }
        let n = usize::from(count).min(b - t + 1);
        for _ in 0..n {
            let _ = self.grid.remove(b);
            self.grid
                .insert(t, vec![self.blank_cell(); usize::from(self.cols)]);
        }
    }

    fn insert_lines(&mut self, count: u16) {
        if self.cursor.row < self.scroll_top || self.cursor.row > self.scroll_bottom {
            return;
        }
        self.scroll_down_region(self.cursor.row, self.scroll_bottom, count);
    }

    fn delete_lines(&mut self, count: u16) {
        if self.cursor.row < self.scroll_top || self.cursor.row > self.scroll_bottom {
            return;
        }
        self.scroll_up_region(self.cursor.row, self.scroll_bottom, count);
    }

    fn erase_in_display(&mut self, mode: u16) {
        let r = usize::from(self.cursor.row);
        let c = usize::from(self.cursor.col);
        let blank = self.blank_cell();
        match mode {
            0 => {
                for cell in &mut self.grid[r][c..] {
                    *cell = blank.clone();
                }
                for row in &mut self.grid[r + 1..] {
                    row.fill(blank.clone());
                }
            }
            1 => {
                for row in &mut self.grid[..r] {
                    row.fill(blank.clone());
                }
                let end = (c + 1).min(usize::from(self.cols));
                for cell in &mut self.grid[r][..end] {
                    *cell = blank.clone();
                }
            }
            2 | 3 => {
                for row in &mut self.grid {
                    row.fill(blank.clone());
                }
                if mode == 3 && !self.using_alt {
                    self.scrollback.clear();
                    self.viewport_scroll = 0;
                }
            }
            _ => {}
        }
    }

    fn erase_in_line(&mut self, mode: u16) {
        let r = usize::from(self.cursor.row);
        let c = usize::from(self.cursor.col);
        let blank = self.blank_cell();
        match mode {
            0 => self.grid[r][c..].fill(blank),
            1 => {
                let end = (c + 1).min(usize::from(self.cols));
                self.grid[r][..end].fill(blank);
            }
            2 => self.grid[r].fill(blank),
            _ => {}
        }
    }
}

fn resize_grid(old: &[Vec<Cell>], new_cols: u16, new_rows: u16) -> Vec<Vec<Cell>> {
    let nc = usize::from(new_cols);
    let nr = usize::from(new_rows);
    let mut out = Vec::with_capacity(nr);
    for r in 0..nr {
        let mut row = vec![Cell::default(); nc];
        if let Some(src) = old.get(r) {
            let copy_n = src.len().min(nc);
            row[..copy_n].clone_from_slice(&src[..copy_n]);
        }
        out.push(row);
    }
    out
}

fn row_to_trimmed_string(row: &[Cell]) -> String {
    let mut s: String = row
        .iter()
        .filter(|c| (c.attrs & attr::WIDE_CONTINUATION) == 0)
        .map(|c| c.ch)
        .collect();
    while s.ends_with(' ') {
        s.pop();
    }
    s
}

fn write_sgr_diff(out: &mut String, fg: TermColor, bg: TermColor, attrs: u16) {
    out.push_str("\x1b[0");
    if (attrs & attr::BOLD) != 0 {
        out.push_str(";1");
    }
    if (attrs & attr::DIM) != 0 {
        out.push_str(";2");
    }
    if (attrs & attr::ITALIC) != 0 {
        out.push_str(";3");
    }
    if (attrs & attr::UNDERLINE) != 0 {
        out.push_str(";4");
    }
    if (attrs & attr::INVERSE) != 0 {
        out.push_str(";7");
    }
    if (attrs & attr::STRIKETHROUGH) != 0 {
        out.push_str(";9");
    }
    match fg {
        TermColor::Default => {}
        TermColor::Indexed(i) if i < 8 => {
            let _ = write!(out, ";{}", 30 + i);
        }
        TermColor::Indexed(i) if i < 16 => {
            let _ = write!(out, ";{}", 90 + (i - 8));
        }
        TermColor::Indexed(i) => {
            let _ = write!(out, ";38;5;{i}");
        }
        TermColor::Rgb(r, g, b) => {
            let _ = write!(out, ";38;2;{r};{g};{b}");
        }
    }
    match bg {
        TermColor::Default => {}
        TermColor::Indexed(i) if i < 8 => {
            let _ = write!(out, ";{}", 40 + i);
        }
        TermColor::Indexed(i) if i < 16 => {
            let _ = write!(out, ";{}", 100 + (i - 8));
        }
        TermColor::Indexed(i) => {
            let _ = write!(out, ";48;5;{i}");
        }
        TermColor::Rgb(r, g, b) => {
            let _ = write!(out, ";48;2;{r};{g};{b}");
        }
    }
    out.push('m');
}

const fn map_dec_special_graphics(ch: char) -> char {
    match ch {
        'j' => '┘',
        'k' => '┐',
        'l' => '┌',
        'm' => '└',
        'n' => '┼',
        'q' => '─',
        't' => '├',
        'u' => '┤',
        'v' => '┴',
        'w' => '┬',
        'x' => '│',
        _ => ch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sgr_truecolor_alt_screen_scrollback_and_search() {
        let mut term = TerminalEngine::new(20, 4, 100);
        term.feed_str("\x1b[38;2;63;184;175mhello\x1b[0m world\r\n");
        term.feed_str("line two kubectl\r\nline three\r\nline four\r\nline five\r\n");

        // Primary scrollback captured shifted top lines cleanly
        assert!(term.scrollback_len() >= 1);
        let hits = term.search("kubectl", false);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].col_start, 9);
        assert_eq!(hits[0].col_end, 16);

        // Alternate screen switches cleanly and restores primary text on exit
        term.feed_str("\x1b[?1049h\x1b[2;3HALT MODE");
        assert!(term.is_alt_screen());
        assert!(term.plain_text().contains("ALT MODE"));
        assert!(!term.plain_text().contains("kubectl"));

        term.feed_str("\x1b[?1049l");
        assert!(!term.is_alt_screen());
        assert!(term.plain_text().contains("kubectl"));
    }

    #[test]
    fn encodes_decckm_bracketed_paste_osc8_and_serialize_roundtrip() {
        let mut term = TerminalEngine::new(40, 6, 50);
        term.feed_str("\x1b[?1h\x1b[?2004h\x1b]8;;https://operquay.io\x07docs\x1b]8;;\x07\x1b[1;32m ok\x1b[0m");
        assert_eq!(
            term.encode_key_input("ArrowUp", false, false, false),
            b"\x1bOA"
        );
        assert_eq!(term.encode_paste("rm \x1bfoo"), b"\x1b[200~rm foo\x1b[201~");
        let row0 = term.row_cells(0).unwrap();
        assert_eq!(
            term.hyperlink_url(row0[0].hyperlink_id),
            Some("https://operquay.io")
        );

        let vt = term.serialize_vt();
        let mut cloned = TerminalEngine::new(40, 6, 50);
        cloned.feed_str(&vt);
        assert!(cloned.plain_text().contains("docs ok"));

        let snap = term.render_binary_snapshot();
        assert_eq!(&snap[0..4], b"OQTM");
        assert_eq!(snap.len(), 24 + 40 * 6 * 14);
    }

    #[test]
    fn responds_to_cpr_device_status_and_handles_cjk_wide_chars() {
        let mut term = TerminalEngine::new(10, 4, 20);
        term.feed_str("日本語\x1b[6n");
        assert_eq!(term.take_replies(), b"\x1b[1;7R");
    }

    #[test]
    fn supports_viewport_scroll_pinning_snapshot_offset_and_range_extract() {
        let mut term = TerminalEngine::new(20, 4, 10);
        for i in 1..=8 {
            term.feed_str(&format!("line-{i:02} alpha\r\n"));
        }
        assert!(term.scrollback_len() >= 4);
        assert_eq!(term.viewport_scroll(), 0);

        let scrolled = term.scroll_viewport(3);
        assert_eq!(scrolled, 3);
        let snap = term.render_binary_snapshot();
        let vp_scroll = u32::from_le_bytes(snap[20..24].try_into().unwrap());
        assert_eq!(vp_scroll, 3);

        // First visible row in snapshot should show older history rather than live bottom
        let mut first_row_chars = String::new();
        for c in 0..7 {
            let off = 24 + c * 14;
            let code = u32::from_le_bytes(snap[off..off + 4].try_into().unwrap());
            first_row_chars.push(char::from_u32(code).unwrap_or(' '));
        }
        assert_eq!(first_row_chars, "line-03");

        // New output pins scrolled-up viewport to the same history line
        term.feed_str("line-09 omega\r\n");
        assert!(term.viewport_scroll() >= 3);

        // Extract inclusive single-line and multi-line range (including reversed selection)
        let r0 = term.extract_range(0, 0, 0, 12);
        assert!(r0.starts_with("line-"));
        let reversed = term.extract_range(1, 7, 0, 0);
        let forward = term.extract_range(0, 0, 1, 7);
        assert_eq!(reversed, forward);
        assert!(forward.contains('\n'));

        // Alt screen disables scrollback & resets viewport scroll
        term.feed_str("\x1b[?1049hALT");
        assert_eq!(term.viewport_scroll(), 0);
        term.feed_str("\x1b[?1049l");

        // Dynamic scrollback limit trims and clamps viewport scroll cleanly
        term.set_viewport_scroll(99);
        term.set_scrollback_limit(2);
        assert_eq!(term.scrollback_len(), 2);
        assert!(term.viewport_scroll() <= 2);
    }

    #[test]
    fn handles_irm_insert_wrap_bs_kitty_csi_esc_charset_c0_rep_and_dec1048() {
        // 1. IRM insert mode (\x1b[4h ... \x1b[4l) shifts existing text instead of overwriting
        let mut term = TerminalEngine::new(20, 4, 20);
        term.feed_str("hello world\x1b[5D\x1b[4hS\x1b[4l");
        assert!(term.plain_text().contains("hello Sworld"));

        // 2. Backspace after pending right-margin wrap clears wrap_next cleanly
        let mut wrap_term = TerminalEngine::new(4, 2, 10);
        wrap_term.feed_str("abcd\x08Z");
        assert_eq!(wrap_term.cursor_pos(), (3, 0));
        assert!(wrap_term.plain_text().contains("abcZ"));

        // 3. Kitty keyboard protocol CSI = 0 u and CSI > c / CSI = c must be ignored (no cursor jump / DA reply)
        let mut kitty = TerminalEngine::new(20, 4, 10);
        kitty.feed_str("\x1b[shello\x1b[=0u!");
        assert!(kitty.plain_text().contains("hello!"));
        kitty.feed_str("\x1b[=c\x1b[>c");
        assert_eq!(kitty.take_replies(), Vec::<u8>::new());

        // 4. ESC # 8 (DECALN) must not leak '8' to the screen
        let mut esc2 = TerminalEngine::new(10, 2, 10);
        esc2.feed_str("\x1b#8OK");
        assert_eq!(esc2.plain_text().trim(), "OK");

        // 5. Embedded C0 BS inside CSI and REP (CSI b) + DEC ?1048h/l cursor save/restore
        let mut c0 = TerminalEngine::new(20, 3, 10);
        c0.feed_str("X\x1b[3b");
        assert!(c0.plain_text().contains("XXXX"));
        c0.feed_str("\x1b[?1048h\x1b[2;5H@\x1b[?1048l!");
        assert!(c0.plain_text().contains("XXXX!"));
    }
}
