use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp_core::impl_as_any;
use operquay_core::ClipboardNormalization;
use tokio::sync::mpsc;

/// Events emitted by [`OperquayCliprdrBackend`] into the active `IronRDP` session loop.
#[derive(Debug, Clone)]
pub enum RdpClipboardEvent {
    RequestFormatList,
    RemoteCopy(ClipboardFormatId),
    FormatDataRequest(ClipboardFormatId),
    RemoteText(String),
}

/// Object-oriented `[MS-RDPECLIP]` backend bridging `ironrdp-cliprdr` callbacks with Operquay's
/// `DisplaySink` and browser WebSocket clipboard normalization rules.
#[derive(Debug)]
pub struct OperquayCliprdrBackend {
    tx: mpsc::Sender<RdpClipboardEvent>,
    normalization: ClipboardNormalization,
    pending_paste_format: Option<ClipboardFormatId>,
}

impl_as_any!(OperquayCliprdrBackend);

impl OperquayCliprdrBackend {
    #[must_use]
    pub const fn new(
        tx: mpsc::Sender<RdpClipboardEvent>,
        normalization: ClipboardNormalization,
    ) -> Self {
        Self {
            tx,
            normalization,
            pending_paste_format: None,
        }
    }
}

/// Encodes UTF-8 text into null-terminated UTF-16LE bytes for Windows `CF_UNICODETEXT`,
/// applying the configured line-ending policy.
#[must_use]
pub fn encode_clipboard_text_utf16le(text: &str, policy: ClipboardNormalization) -> Vec<u8> {
    let normalized = normalize_clipboard_text(text, policy);
    let mut out = Vec::with_capacity((normalized.len() + 1) * 2);
    for unit in normalized.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Decodes Windows `CF_UNICODETEXT` or `CF_TEXT` payload bytes into normalized UTF-8 text.
#[must_use]
pub fn decode_clipboard_bytes(
    data: &[u8],
    format: ClipboardFormatId,
    policy: ClipboardNormalization,
) -> String {
    let raw = if format == ClipboardFormatId::CF_UNICODETEXT {
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        let nul_pos = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..nul_pos]).into_owned()
    };
    normalize_clipboard_text(&raw, policy)
}

#[must_use]
pub fn normalize_clipboard_text(text: &str, policy: ClipboardNormalization) -> String {
    match policy {
        ClipboardNormalization::Preserve => text.to_owned(),
        ClipboardNormalization::WindowsCrlf => text.replace("\r\n", "\n").replace('\n', "\r\n"),
        ClipboardNormalization::UnixLf => text.replace("\r\n", "\n"),
    }
}

impl CliprdrBackend for OperquayCliprdrBackend {
    #[allow(clippy::unnecessary_literal_bound)]
    fn temporary_directory(&self) -> &str {
        "/tmp"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {
        let _ = self.tx.try_send(RdpClipboardEvent::RequestFormatList);
    }

    fn on_request_format_list(&mut self) {
        let _ = self.tx.try_send(RdpClipboardEvent::RequestFormatList);
    }

    fn on_process_negotiated_capabilities(
        &mut self,
        _capabilities: ClipboardGeneralCapabilityFlags,
    ) {
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        let chosen = if available_formats
            .iter()
            .any(|f| f.id == ClipboardFormatId::CF_UNICODETEXT)
        {
            Some(ClipboardFormatId::CF_UNICODETEXT)
        } else if available_formats
            .iter()
            .any(|f| f.id == ClipboardFormatId::CF_TEXT)
        {
            Some(ClipboardFormatId::CF_TEXT)
        } else {
            None
        };
        if let Some(fmt_id) = chosen {
            self.pending_paste_format = Some(fmt_id);
            let _ = self.tx.try_send(RdpClipboardEvent::RemoteCopy(fmt_id));
        }
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let _ = self
            .tx
            .try_send(RdpClipboardEvent::FormatDataRequest(request.format));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() {
            return;
        }
        let fmt = self
            .pending_paste_format
            .take()
            .unwrap_or(ClipboardFormatId::CF_UNICODETEXT);
        let text = decode_clipboard_bytes(response.data(), fmt, self.normalization);
        if !text.is_empty() {
            let _ = self.tx.try_send(RdpClipboardEvent::RemoteText(text));
        }
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_utf16_clipboard_with_normalization() {
        let utf16 =
            encode_clipboard_text_utf16le("line1\nline2", ClipboardNormalization::WindowsCrlf);
        assert!(utf16.ends_with(&[0, 0]));
        let decoded = decode_clipboard_bytes(
            &utf16,
            ClipboardFormatId::CF_UNICODETEXT,
            ClipboardNormalization::UnixLf,
        );
        assert_eq!(decoded, "line1\nline2");
    }
}
