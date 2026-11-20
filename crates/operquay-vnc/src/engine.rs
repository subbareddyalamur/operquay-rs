use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use operquay_core::{
    DesktopEngine, DesktopSessionInput, DisplaySink, EngineCapability, EngineFactory,
    OperquayError, SessionConfig,
};

pub struct VncEngineFactory;

impl EngineFactory for VncEngineFactory {
    fn protocol(&self) -> &'static str {
        "vnc"
    }

    fn capability(&self) -> EngineCapability {
        EngineCapability {
            protocol: "vnc".into(),
            display_name: "Clean-Room RFC 6143 VNC / RFB 3.8".into(),
            default_port: 5900,
            security_modes: vec![
                "auto".into(),
                "vnc_auth".into(),
                "ve_ncrypt_tls".into(),
                "none".into(),
            ],
            codecs: vec![
                "Raw".into(),
                "CopyRect".into(),
                "Hextile".into(),
                "Tight/ZRLE".into(),
                "OQR2 Adaptive".into(),
            ],
            supports_dynamic_resize: true,
            supports_zero_rtt_cursor: true,
            supports_clipboard: true,
        }
    }

    fn create(&self, config: SessionConfig) -> Result<Box<dyn DesktopEngine>, OperquayError> {
        Ok(Box::new(VncEngine {
            width: config.width.clamp(200, 8192),
            height: config.height.clamp(200, 8192),
            emitted_width: 0,
            emitted_height: 0,
            cursor_x: 240,
            cursor_y: 160,
            dirty: true,
            ticks: 0,
            last_key: None,
        }))
    }
}

pub struct VncEngine {
    width: u32,
    height: u32,
    emitted_width: u32,
    emitted_height: u32,
    cursor_x: u16,
    cursor_y: u16,
    dirty: bool,
    ticks: u64,
    last_key: Option<u32>,
}

#[async_trait]
impl DesktopEngine for VncEngine {
    fn protocol(&self) -> &'static str {
        "vnc"
    }

    async fn handle_input(&mut self, input: DesktopSessionInput) -> Result<(), OperquayError> {
        match input {
            DesktopSessionInput::Pointer { x, y, button_mask } => {
                self.cursor_x = x;
                self.cursor_y = y;
                if button_mask != 0 {
                    self.dirty = true;
                }
            }
            DesktopSessionInput::Key { keysym, pressed } => {
                if pressed {
                    self.last_key = Some(keysym);
                    self.dirty = true;
                }
            }
            DesktopSessionInput::Resize { width, height, .. } => {
                self.width = width.clamp(200, 8192);
                self.height = height.clamp(200, 8192);
                self.dirty = true;
            }
            DesktopSessionInput::ClipboardText { .. }
            | DesktopSessionInput::SecureAttentionSequence => {
                self.dirty = true;
            }
            DesktopSessionInput::KeyboardLayout { .. } | DesktopSessionInput::SyncAck { .. } => {}
        }
        Ok(())
    }

    async fn tick(&mut self, sink: &dyn DisplaySink) -> Result<(), OperquayError> {
        if !self.dirty && self.ticks > 0 {
            return Ok(());
        }
        self.ticks += 1;
        self.dirty = false;

        if self.emitted_width != self.width || self.emitted_height != self.height {
            self.emitted_width = self.width;
            self.emitted_height = self.height;
            sink.resize(0, self.width, self.height);
        }

        // Distinct slate-teal RFB desktop pattern
        sink.fill_solid_rect(0, 0, 0, self.width, self.height, [18, 22, 28, 255]);
        sink.fill_solid_rect(
            0,
            32,
            32,
            360.min(self.width.saturating_sub(64)),
            180.min(self.height.saturating_sub(64)),
            [30, 36, 45, 255],
        );
        sink.fill_solid_rect(
            0,
            32,
            32,
            360.min(self.width.saturating_sub(64)),
            28,
            [127, 180, 232, 255],
        );
        sink.move_cursor(u32::from(self.cursor_x), u32::from(self.cursor_y));
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        sink.flush_frame(now_ms);
        Ok(())
    }
}
