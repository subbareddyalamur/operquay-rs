use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::OperquayError;
use crate::secret::SecretString;
use crate::settings::{RemoteDesktopSettings, SettingsStoreError};

/// Protocol-agnostic rendered display sink consumed by `operquay-rdp` and `operquay-vnc`.
pub trait DisplaySink: Send + Sync {
    fn resize(&self, layer_id: i32, width: u32, height: u32);
    fn draw_rgba_rect(
        &self,
        layer_id: i32,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        rgba: &[u8],
        stride: usize,
    );
    fn fill_solid_rect(&self, layer_id: i32, x: u32, y: u32, w: u32, h: u32, rgba: [u8; 4]);
    fn copy_rect(
        &self,
        src_layer: i32,
        sx: u32,
        sy: u32,
        w: u32,
        h: u32,
        dst_layer: i32,
        dx: u32,
        dy: u32,
    );
    fn set_cursor(&self, hot_x: u32, hot_y: u32, w: u32, h: u32, rgba: &[u8]);
    fn move_cursor(&self, x: u32, y: u32);
    fn flush_frame(&self, timestamp_ms: u64);
    /// Optional raw H.264 Annex-B NALU region emitted by `MS-RDPEGFX` `AVC420` for `WebCodecs` pass-through.
    fn draw_h264_nalu(&self, _layer_id: i32, _x: u32, _y: u32, _w: u32, _h: u32, _annex_b: &[u8]) {}
    /// Optional raw JPEG rectangle emitted by VNC `Tight` (`0x09`) encoding for direct browser tile delivery.
    fn draw_jpeg_rect(&self, _layer_id: i32, _x: u32, _y: u32, _w: u32, _h: u32, _jpeg: &[u8]) {}
    /// Optional remote-to-local UTF-8 clipboard update received from `cliprdr` or RFB `ServerCutText`.
    fn on_clipboard_text(&self, _text: &str) {}
}

/// Interactive input events sent from browser / WS handler down to the active protocol engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopSessionInput {
    Pointer { x: u16, y: u16, button_mask: u8 },
    Key { keysym: u32, pressed: bool },
    Resize { width: u32, height: u32, dpi: u16 },
    KeyboardLayout { layout: String },
    ClipboardText { text: String },
    SecureAttentionSequence,
    SyncAck { server_ts_ms: u64 },
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_id: String,
    pub tenant_id: String,
    pub protocol: String,
    pub target_host: String,
    pub target_port: u16,
    pub width: u32,
    pub height: u32,
    pub dpi: u16,
    pub username: String,
    pub password: SecretString,
    pub settings: RemoteDesktopSettings,
}

/// Unified asynchronous desktop session contract implemented cleanly per protocol.
#[async_trait]
pub trait DesktopEngine: Send + Sync {
    fn protocol(&self) -> &'static str;
    async fn handle_input(&mut self, input: DesktopSessionInput) -> Result<(), OperquayError>;
    async fn tick(&mut self, sink: &dyn DisplaySink) -> Result<(), OperquayError>;
}

/// Machine-readable capability metadata advertised via `/api/v1/protocols` so the UI
/// dynamically stays in sync with compiled backend engines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCapability {
    pub protocol: String,
    pub display_name: String,
    pub default_port: u16,
    pub security_modes: Vec<String>,
    pub codecs: Vec<String>,
    pub supports_dynamic_resize: bool,
    pub supports_zero_rtt_cursor: bool,
    pub supports_clipboard: bool,
}

pub trait EngineFactory: Send + Sync {
    fn protocol(&self) -> &'static str;
    fn capability(&self) -> EngineCapability;
    fn create(&self, config: SessionConfig) -> Result<Box<dyn DesktopEngine>, OperquayError>;
}

/// Extensible runtime registry decoupling HTTP/WS server routes from concrete protocols.
#[derive(Default)]
pub struct EngineRegistry {
    factories: HashMap<String, Arc<dyn EngineFactory>>,
}

impl EngineRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, factory: Arc<dyn EngineFactory>) {
        self.factories
            .insert(factory.protocol().to_owned(), factory);
    }

    #[must_use]
    pub fn capabilities(&self) -> Vec<EngineCapability> {
        let mut list: Vec<_> = self.factories.values().map(|f| f.capability()).collect();
        list.sort_by(|a, b| a.protocol.cmp(&b.protocol));
        list
    }

    pub fn create_engine(
        &self,
        protocol: &str,
        config: SessionConfig,
    ) -> Result<Box<dyn DesktopEngine>, OperquayError> {
        let factory = self
            .factories
            .get(protocol)
            .ok_or_else(|| OperquayError::UnsupportedProtocol(protocol.to_owned()))?;
        factory.create(config)
    }
}

/// Persistent settings store seam supporting both in-memory dev/test state and PostgreSQL RLS.
#[async_trait]
pub trait SettingsStore: Send + Sync {
    async fn get(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError>;
    async fn put(
        &self,
        tenant_id: &str,
        settings: RemoteDesktopSettings,
    ) -> Result<RemoteDesktopSettings, SettingsStoreError>;
    async fn reset(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError>;
}

/// Default thread-safe in-memory settings store keyed by `tenant_id`.
#[derive(Debug, Default)]
pub struct InMemorySettingsStore {
    tenants: RwLock<HashMap<String, RemoteDesktopSettings>>,
}

impl InMemorySettingsStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SettingsStore for InMemorySettingsStore {
    async fn get(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        let guard = self.tenants.read().await;
        Ok(guard.get(tenant_id).cloned().unwrap_or_default())
    }

    async fn put(
        &self,
        tenant_id: &str,
        settings: RemoteDesktopSettings,
    ) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        settings.validate()?;
        let mut guard = self.tenants.write().await;
        guard.insert(tenant_id.to_owned(), settings.clone());
        Ok(settings)
    }

    async fn reset(&self, tenant_id: &str) -> Result<RemoteDesktopSettings, SettingsStoreError> {
        let defaults = RemoteDesktopSettings::default();
        let mut guard = self.tenants.write().await;
        guard.insert(tenant_id.to_owned(), defaults.clone());
        Ok(defaults)
    }
}
