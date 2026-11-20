#![allow(unsafe_code)]

//! WebAssembly (`wasm32-unknown-unknown`) C-ABI bridge for `operquay-term`.
//! Contains zero `unsafe { ... }` blocks; uses plain 32-bit integer register-packed
//! calls (no `BigInt` overhead) and safe slice pointers for zero-copy JS linear memory reads.

use std::cell::RefCell;

use operquay_term::TerminalEngine;

struct InstanceSlot {
    engine: TerminalEngine,
    out_buf: Vec<u8>,
}

thread_local! {
    static SLOTS: RefCell<Vec<Option<InstanceSlot>>> = const { RefCell::new(Vec::new()) };
}

#[no_mangle]
pub extern "C" fn oqr_term_new(cols: u32, rows: u32, scrollback: u32) -> u32 {
    let slot = InstanceSlot {
        engine: TerminalEngine::new(cols as u16, rows as u16, scrollback as usize),
        out_buf: Vec::with_capacity(64 * 1024),
    };
    SLOTS.with(|cell| {
        let mut list = cell.borrow_mut();
        if let Some((idx, empty)) = list.iter_mut().enumerate().find(|(_, item)| item.is_none()) {
            *empty = Some(slot);
            (idx + 1) as u32
        } else {
            list.push(Some(slot));
            list.len() as u32
        }
    })
}

#[no_mangle]
pub extern "C" fn oqr_term_free(handle: u32) {
    if handle == 0 {
        return;
    }
    SLOTS.with(|cell| {
        let mut list = cell.borrow_mut();
        if let Some(slot) = list.get_mut((handle - 1) as usize) {
            *slot = None;
        }
    });
}

/// Feed up to 16 UTF-8/VT bytes packed little-endian into four `u32` words (`len <= 16`).
#[no_mangle]
pub extern "C" fn oqr_term_feed16(handle: u32, w0: u32, w1: u32, w2: u32, w3: u32, len: u32) {
    let take = (len as usize).min(16);
    let mut chunk = [0u8; 16];
    chunk[0..4].copy_from_slice(&w0.to_le_bytes());
    chunk[4..8].copy_from_slice(&w1.to_le_bytes());
    chunk[8..12].copy_from_slice(&w2.to_le_bytes());
    chunk[12..16].copy_from_slice(&w3.to_le_bytes());

    with_slot_mut(handle, |slot| {
        slot.engine.feed(&chunk[..take]);
    });
}

#[no_mangle]
pub extern "C" fn oqr_term_resize(handle: u32, cols: u32, rows: u32) {
    with_slot_mut(handle, |slot| {
        slot.engine.resize(cols as u16, rows as u16);
    });
}

#[no_mangle]
pub extern "C" fn oqr_term_render_snapshot(handle: u32) -> u32 {
    with_slot_mut(handle, |slot| {
        slot.out_buf = slot.engine.render_binary_snapshot();
        slot.out_buf.len() as u32
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_serialize_vt(handle: u32) -> u32 {
    with_slot_mut(handle, |slot| {
        slot.out_buf = slot.engine.serialize_vt().into_bytes();
        slot.out_buf.len() as u32
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_plain_text(handle: u32) -> u32 {
    with_slot_mut(handle, |slot| {
        slot.out_buf = slot.engine.plain_text().into_bytes();
        slot.out_buf.len() as u32
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_search16(
    handle: u32,
    w0: u32,
    w1: u32,
    w2: u32,
    w3: u32,
    len: u32,
    case_sensitive: u32,
) -> u32 {
    let take = (len as usize).min(16);
    let mut chunk = [0u8; 16];
    chunk[0..4].copy_from_slice(&w0.to_le_bytes());
    chunk[4..8].copy_from_slice(&w1.to_le_bytes());
    chunk[8..12].copy_from_slice(&w2.to_le_bytes());
    chunk[12..16].copy_from_slice(&w3.to_le_bytes());
    let query = String::from_utf8_lossy(&chunk[..take]).into_owned();

    with_slot_mut(handle, |slot| {
        let hits = slot.engine.search(&query, case_sensitive != 0);
        let mut buf = Vec::with_capacity(4 + hits.len() * 8);
        buf.extend_from_slice(&(hits.len() as u32).to_le_bytes());
        for hit in hits {
            buf.extend_from_slice(&(hit.abs_row as u32).to_le_bytes());
            buf.extend_from_slice(&(hit.col_start as u16).to_le_bytes());
            buf.extend_from_slice(&(hit.col_end as u16).to_le_bytes());
        }
        slot.out_buf = buf;
        slot.out_buf.len() as u32
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_take_replies(handle: u32) -> u32 {
    with_slot_mut(handle, |slot| {
        slot.out_buf = slot.engine.take_replies();
        slot.out_buf.len() as u32
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_out_ptr(handle: u32) -> u32 {
    with_slot_ref(handle, |slot| slot.out_buf.as_ptr() as usize as u32).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_out_len(handle: u32) -> u32 {
    with_slot_ref(handle, |slot| slot.out_buf.len() as u32).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_bracketed_paste(handle: u32) -> u32 {
    with_slot_ref(handle, |slot| {
        u32::from(slot.engine.bracketed_paste_enabled())
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_app_cursor(handle: u32) -> u32 {
    with_slot_ref(handle, |slot| u32::from(slot.engine.app_cursor_enabled())).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_scroll_viewport(handle: u32, delta_lines: i32) -> u32 {
    with_slot_mut(handle, |slot| {
        slot.engine.scroll_viewport(delta_lines as isize) as u32
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_set_scroll(handle: u32, offset: u32) -> u32 {
    with_slot_mut(handle, |slot| {
        slot.engine.set_viewport_scroll(offset as usize) as u32
    })
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn oqr_term_set_scrollback_limit(handle: u32, limit: u32) {
    with_slot_mut(handle, |slot| {
        slot.engine.set_scrollback_limit(limit as usize);
    });
}

#[no_mangle]
pub extern "C" fn oqr_term_extract_range(
    handle: u32,
    start_row: u32,
    start_col: u32,
    end_row: u32,
    end_col: u32,
) -> u32 {
    with_slot_mut(handle, |slot| {
        slot.out_buf = slot
            .engine
            .extract_range(
                start_row as usize,
                start_col as usize,
                end_row as usize,
                end_col as usize,
            )
            .into_bytes();
        slot.out_buf.len() as u32
    })
    .unwrap_or(0)
}

fn with_slot_mut<R>(handle: u32, f: impl FnOnce(&mut InstanceSlot) -> R) -> Option<R> {
    if handle == 0 {
        return None;
    }
    SLOTS.with(|cell| {
        let mut list = cell.borrow_mut();
        list.get_mut((handle - 1) as usize)
            .and_then(Option::as_mut)
            .map(f)
    })
}

fn with_slot_ref<R>(handle: u32, f: impl FnOnce(&InstanceSlot) -> R) -> Option<R> {
    if handle == 0 {
        return None;
    }
    SLOTS.with(|cell| {
        let list = cell.borrow();
        list.get((handle - 1) as usize)
            .and_then(Option::as_ref)
            .map(f)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack16(slice: &[u8]) -> [u32; 4] {
        let mut bytes = [0u8; 16];
        let n = slice.len().min(16);
        bytes[..n].copy_from_slice(&slice[..n]);
        [
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        ]
    }

    #[test]
    fn wasm_abi_executes_feed_snapshot_search_and_serialize_zero_unsafe() {
        let h = oqr_term_new(30, 5, 100);
        assert!(h > 0);
        let msg = b"\x1b[32mrust-wasm-term\x1b[0m ready";
        for chunk in msg.chunks(16) {
            let w = pack16(chunk);
            oqr_term_feed16(h, w[0], w[1], w[2], w[3], chunk.len() as u32);
        }
        let snap_len = oqr_term_render_snapshot(h);
        assert_eq!(snap_len, 24 + 30 * 5 * 14);
        assert!(oqr_term_out_ptr(h) != 0);
        assert_eq!(oqr_term_out_len(h), snap_len);

        let qw = pack16(b"wasm");
        let search_len = oqr_term_search16(h, qw[0], qw[1], qw[2], qw[3], 4, 0);
        assert_eq!(search_len, 4 + 8);

        let vt_len = oqr_term_serialize_vt(h);
        assert!(vt_len > 10);

        // Exercise scrollback + viewport scroll + range extraction ABI
        let more = b"\r\nl2\r\nl3\r\nl4\r\nl5\r\nl6\r\n";
        for chunk in more.chunks(16) {
            let w = pack16(chunk);
            oqr_term_feed16(h, w[0], w[1], w[2], w[3], chunk.len() as u32);
        }
        assert!(oqr_term_scroll_viewport(h, 2) >= 1);
        assert_eq!(oqr_term_set_scroll(h, 1), 1);
        let ext_len = oqr_term_extract_range(h, 0, 0, 0, 15);
        assert!(ext_len > 0);
        oqr_term_set_scrollback_limit(h, 1);
        oqr_term_free(h);
    }
}
