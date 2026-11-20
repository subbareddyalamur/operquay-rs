#![forbid(unsafe_code)]

//! Core domain types, redacted secret wrappers, extensible protocol/engine traits,
//! and enterprise remote desktop settings validation for Operquay-Rust.

pub mod error;
pub mod secret;
pub mod settings;
pub mod traits;

pub use error::{OperquayError, Result};
pub use secret::SecretString;
pub use settings::{
    compliance_mode_enabled, CertPolicy, ClipboardNormalization, CodecMode,
    KeyboardLayoutDescriptor, NetworkPreset, NetworkSimulationCondition, NetworkSimulationResult,
    ProtocolPreference, RdpSecurityMode, RemoteDesktopSettings, SettingsError, SettingsStoreError,
    TransportMode, VncSecurityMode, KEYBOARD_LAYOUTS,
};
pub use traits::{
    DesktopEngine, DesktopSessionInput, DisplaySink, EngineCapability, EngineFactory,
    EngineRegistry, InMemorySettingsStore, SessionConfig, SettingsStore,
};
