use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Metadata for each of the 25 reverse-engineered Windows LCID keyboard layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyboardLayoutDescriptor {
    pub id: &'static str,
    pub label: &'static str,
    pub lcid_hex: &'static str,
    pub lcid: u32,
}

/// Complete registry of 25 keyboard layouts preserved from Guacamole 1.6.0-r3 (`GUAC_KEYMAPS`).
pub const KEYBOARD_LAYOUTS: &[KeyboardLayoutDescriptor] = &[
    KeyboardLayoutDescriptor {
        id: "en-us-qwerty",
        label: "English (US QWERTY)",
        lcid_hex: "0x0409",
        lcid: 0x0409,
    },
    KeyboardLayoutDescriptor {
        id: "en-gb-qwerty",
        label: "English (UK QWERTY)",
        lcid_hex: "0x0809",
        lcid: 0x0809,
    },
    KeyboardLayoutDescriptor {
        id: "de-de-qwertz",
        label: "German (Germany QWERTZ)",
        lcid_hex: "0x0407",
        lcid: 0x0407,
    },
    KeyboardLayoutDescriptor {
        id: "de-ch-qwertz",
        label: "German (Swiss QWERTZ)",
        lcid_hex: "0x0807",
        lcid: 0x0807,
    },
    KeyboardLayoutDescriptor {
        id: "fr-fr-azerty",
        label: "French (France AZERTY)",
        lcid_hex: "0x040C",
        lcid: 0x040c,
    },
    KeyboardLayoutDescriptor {
        id: "fr-be-azerty",
        label: "French (Belgium AZERTY)",
        lcid_hex: "0x080C",
        lcid: 0x080c,
    },
    KeyboardLayoutDescriptor {
        id: "fr-ca-qwerty",
        label: "French (Canada QWERTY)",
        lcid_hex: "0x1009",
        lcid: 0x1009,
    },
    KeyboardLayoutDescriptor {
        id: "fr-ch-qwertz",
        label: "French (Swiss QWERTZ)",
        lcid_hex: "0x100C",
        lcid: 0x100c,
    },
    KeyboardLayoutDescriptor {
        id: "es-es-qwerty",
        label: "Spanish (Spain QWERTY)",
        lcid_hex: "0x040A",
        lcid: 0x040a,
    },
    KeyboardLayoutDescriptor {
        id: "es-latam-qwerty",
        label: "Spanish (Latin America)",
        lcid_hex: "0x080A",
        lcid: 0x080a,
    },
    KeyboardLayoutDescriptor {
        id: "cs-cz-qwertz",
        label: "Czech (QWERTZ)",
        lcid_hex: "0x0405",
        lcid: 0x0405,
    },
    KeyboardLayoutDescriptor {
        id: "hu-hu-qwertz",
        label: "Hungarian (QWERTZ)",
        lcid_hex: "0x040E",
        lcid: 0x040e,
    },
    KeyboardLayoutDescriptor {
        id: "it-it-qwerty",
        label: "Italian (QWERTY)",
        lcid_hex: "0x0410",
        lcid: 0x0410,
    },
    KeyboardLayoutDescriptor {
        id: "ja-jp-qwerty",
        label: "Japanese (QWERTY)",
        lcid_hex: "0x0411",
        lcid: 0x0411,
    },
    KeyboardLayoutDescriptor {
        id: "no-no-qwerty",
        label: "Norwegian (QWERTY)",
        lcid_hex: "0x0414",
        lcid: 0x0414,
    },
    KeyboardLayoutDescriptor {
        id: "pl-pl-qwerty",
        label: "Polish (Programmers QWERTY)",
        lcid_hex: "0x0415",
        lcid: 0x0415,
    },
    KeyboardLayoutDescriptor {
        id: "pt-br-qwerty",
        label: "Portuguese (Brazil ABNT2)",
        lcid_hex: "0x10416",
        lcid: 0x10416,
    },
    KeyboardLayoutDescriptor {
        id: "pt-pt-qwerty",
        label: "Portuguese (Portugal QWERTY)",
        lcid_hex: "0x0816",
        lcid: 0x0816,
    },
    KeyboardLayoutDescriptor {
        id: "ro-ro-qwerty",
        label: "Romanian (Standard)",
        lcid_hex: "0x0418",
        lcid: 0x0418,
    },
    KeyboardLayoutDescriptor {
        id: "sv-se-qwerty",
        label: "Swedish (QWERTY)",
        lcid_hex: "0x041D",
        lcid: 0x041d,
    },
    KeyboardLayoutDescriptor {
        id: "da-dk-qwerty",
        label: "Danish (QWERTY)",
        lcid_hex: "0x0406",
        lcid: 0x0406,
    },
    KeyboardLayoutDescriptor {
        id: "tr-tr-qwerty",
        label: "Turkish (QWERTY)",
        lcid_hex: "0x041F",
        lcid: 0x041f,
    },
    KeyboardLayoutDescriptor {
        id: "failsafe",
        label: "Unicode Failsafe Fallback",
        lcid_hex: "0x0409",
        lcid: 0x0409,
    },
    KeyboardLayoutDescriptor {
        id: "base",
        label: "Base POSIX Shared Keymap",
        lcid_hex: "0x0409",
        lcid: 0x0409,
    },
    KeyboardLayoutDescriptor {
        id: "base-altgr",
        label: "Base AltGr Extension",
        lcid_hex: "0x0409",
        lcid: 0x0409,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPreset {
    AutoAdaptive,
    UltraLowLatency,
    BalancedWan,
    ConstrainedWan,
    Custom,
}

impl NetworkPreset {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoAdaptive => "auto_adaptive",
            Self::UltraLowLatency => "ultra_low_latency",
            Self::BalancedWan => "balanced_wan",
            Self::ConstrainedWan => "constrained_wan",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolPreference {
    Auto,
    Rdp,
    Vnc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Oqr2Binary,
    GuacamoleCompat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodecMode {
    AdaptiveHybrid,
    LosslessCrisp,
    MotionPriority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpSecurityMode {
    Any,
    Nla,
    NlaExt,
    Tls,
    ClassicRdp,
    Vmconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VncSecurityMode {
    Auto,
    VncAuth,
    VeNCryptTls,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertPolicy {
    StrictCa,
    TofuPinned,
    SsmLoopbackIgnore,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardNormalization {
    #[default]
    Preserve,
    WindowsCrlf,
    UnixLf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteDesktopSettings {
    pub network_preset: NetworkPreset,
    pub protocol_preference: ProtocolPreference,
    pub transport_mode: TransportMode,
    pub codec_mode: CodecMode,
    pub target_fps: u8,
    pub jpeg_quality_floor: u8,
    pub enable_copy_rect: bool,
    pub enable_dynamic_resize: bool,
    pub enable_local_cursor_prediction: bool,
    pub enable_mouse_coalescing: bool,
    pub keyboard_layout: String,
    pub unicode_fallback: bool,
    pub rdp_security_mode: RdpSecurityMode,
    pub vnc_security_mode: VncSecurityMode,
    pub cert_policy: CertPolicy,
    pub clipboard_normalization: ClipboardNormalization,
    pub fail_closed_recording: bool,
    pub enable_drive_redirection: bool,
    pub otel_sample_ratio: f64,
    pub show_live_telemetry_hud: bool,
    #[serde(default)]
    pub allow_legacy_crypto_over_ssm: bool,
}

/// Returns `true` when Compliance Mode (`OPERQUAY_COMPLIANCE_MODE=1|true`) is enabled.
#[must_use]
pub fn compliance_mode_enabled() -> bool {
    std::env::var("OPERQUAY_COMPLIANCE_MODE")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

impl Default for RemoteDesktopSettings {
    fn default() -> Self {
        Self {
            network_preset: NetworkPreset::AutoAdaptive,
            protocol_preference: ProtocolPreference::Auto,
            transport_mode: TransportMode::Oqr2Binary,
            codec_mode: CodecMode::AdaptiveHybrid,
            target_fps: 30,
            jpeg_quality_floor: 55,
            enable_copy_rect: true,
            enable_dynamic_resize: true,
            enable_local_cursor_prediction: true,
            enable_mouse_coalescing: true,
            keyboard_layout: "en-us-qwerty".to_owned(),
            unicode_fallback: true,
            rdp_security_mode: RdpSecurityMode::Any,
            vnc_security_mode: VncSecurityMode::Auto,
            cert_policy: CertPolicy::TofuPinned,
            clipboard_normalization: ClipboardNormalization::Preserve,
            fail_closed_recording: true,
            enable_drive_redirection: false,
            otel_sample_ratio: 1.0,
            show_live_telemetry_hud: true,
            allow_legacy_crypto_over_ssm: false,
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum SettingsError {
    #[error("target_fps must be between 10 and 60 (got {0})")]
    InvalidFps(u8),
    #[error("jpeg_quality_floor must be between 20 and 95 (got {0})")]
    InvalidQualityFloor(u8),
    #[error("otel_sample_ratio must be finite and between 0.0 and 1.0 (got {0})")]
    InvalidSampleRatio(f64),
    #[error("unknown keyboard layout '{0}'")]
    UnknownKeyboardLayout(String),
}

#[derive(Debug, Error)]
pub enum SettingsStoreError {
    #[error("validation failed: {0}")]
    Validation(#[from] SettingsError),
    #[error("storage backend failed: {0}")]
    Backend(String),
}

impl RemoteDesktopSettings {
    /// Apply canonical tuned values for a goal-based network preset while preserving
    /// identity/security/keyboard choices that belong to the target host policy.
    pub fn apply_preset(&mut self, preset: NetworkPreset) {
        self.network_preset = preset;
        match preset {
            NetworkPreset::AutoAdaptive => {
                self.transport_mode = TransportMode::Oqr2Binary;
                self.codec_mode = CodecMode::AdaptiveHybrid;
                self.target_fps = 30;
                self.jpeg_quality_floor = 55;
                self.enable_copy_rect = true;
                self.enable_local_cursor_prediction = true;
                self.enable_mouse_coalescing = true;
            }
            NetworkPreset::UltraLowLatency => {
                self.transport_mode = TransportMode::Oqr2Binary;
                self.codec_mode = CodecMode::LosslessCrisp;
                self.target_fps = 60;
                self.jpeg_quality_floor = 85;
                self.enable_copy_rect = true;
                self.enable_local_cursor_prediction = true;
                self.enable_mouse_coalescing = false;
            }
            NetworkPreset::BalancedWan => {
                self.transport_mode = TransportMode::Oqr2Binary;
                self.codec_mode = CodecMode::AdaptiveHybrid;
                self.target_fps = 30;
                self.jpeg_quality_floor = 50;
                self.enable_copy_rect = true;
                self.enable_local_cursor_prediction = true;
                self.enable_mouse_coalescing = true;
            }
            NetworkPreset::ConstrainedWan => {
                self.transport_mode = TransportMode::Oqr2Binary;
                self.codec_mode = CodecMode::MotionPriority;
                self.target_fps = 20;
                self.jpeg_quality_floor = 30;
                self.enable_copy_rect = true;
                self.enable_local_cursor_prediction = true;
                self.enable_mouse_coalescing = true;
            }
            NetworkPreset::Custom => {}
        }
    }

    pub fn validate(&self) -> Result<(), SettingsError> {
        if !(10..=60).contains(&self.target_fps) {
            return Err(SettingsError::InvalidFps(self.target_fps));
        }
        if !(20..=95).contains(&self.jpeg_quality_floor) {
            return Err(SettingsError::InvalidQualityFloor(self.jpeg_quality_floor));
        }
        if !self.otel_sample_ratio.is_finite() || !(0.0..=1.0).contains(&self.otel_sample_ratio) {
            return Err(SettingsError::InvalidSampleRatio(self.otel_sample_ratio));
        }
        if !KEYBOARD_LAYOUTS
            .iter()
            .any(|k| k.id == self.keyboard_layout)
        {
            return Err(SettingsError::UnknownKeyboardLayout(
                self.keyboard_layout.clone(),
            ));
        }
        Ok(())
    }

    /// Compute the effective JPEG quality at a measured lag (`ms`), combining
    /// Guacamole's reverse-engineered curve (`lag <= 19 ? 90 : max(30, 110 - lag)`)
    /// with the operator's configured quality floor.
    #[must_use]
    pub fn effective_jpeg_quality(&self, lag_ms: u32) -> u8 {
        if self.codec_mode == CodecMode::LosslessCrisp {
            return 95;
        }
        let guac_curve: u8 = if lag_ms <= 19 {
            90
        } else {
            let scaled = 110_i32.saturating_sub(lag_ms as i32).max(30);
            scaled as u8
        };
        guac_curve.max(self.jpeg_quality_floor)
    }

    /// Simulate effective pipeline behavior across synthetic LAN / WAN / SSM network profiles
    /// for both observability telemetry and the settings UI live preview.
    #[must_use]
    pub fn simulate_network(
        &self,
        condition: NetworkSimulationCondition,
    ) -> NetworkSimulationResult {
        let quality = self.effective_jpeg_quality(condition.rtt_ms);
        let max_in_flight_sync = match self.network_preset {
            NetworkPreset::UltraLowLatency => 1,
            _ => 2,
        };
        let active_codec_summary = match (self.transport_mode, self.codec_mode) {
            (TransportMode::Oqr2Binary, CodecMode::AdaptiveHybrid) => {
                "OQR2 Binary: PNG text + Adaptive JPEG + AVC420 pass-through"
            }
            (TransportMode::Oqr2Binary, CodecMode::LosslessCrisp) => {
                "OQR2 Binary: Lossless PNG + ClearCodec Crisp UI"
            }
            (TransportMode::Oqr2Binary, CodecMode::MotionPriority) => {
                "OQR2 Binary: Coalesced JPEG/AVC420 Motion Priority"
            }
            (TransportMode::GuacamoleCompat, _) => "Guacamole UTF-8: PNG/JPEG Base64 Compat",
        };

        let estimated_glass_latency_ms = if self.enable_local_cursor_prediction {
            (condition.rtt_ms / 2).saturating_add(match self.transport_mode {
                TransportMode::Oqr2Binary => 4,
                TransportMode::GuacamoleCompat => 11,
            })
        } else {
            condition.rtt_ms.saturating_add(12)
        };

        let drops_stale_frames = condition.rtt_ms > 90 || condition.packet_loss_pct >= 1.5;

        NetworkSimulationResult {
            rtt_ms: condition.rtt_ms,
            effective_jpeg_quality: quality,
            effective_fps_cap: if condition.rtt_ms > 200 {
                self.target_fps.min(20)
            } else {
                self.target_fps
            },
            cursor_mode: if self.enable_local_cursor_prediction {
                "zero_rtt_local"
            } else {
                "server_roundtrip"
            },
            active_codec_summary,
            max_in_flight_sync,
            drops_stale_frames,
            estimated_glass_latency_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NetworkSimulationCondition {
    pub rtt_ms: u32,
    pub packet_loss_pct: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkSimulationResult {
    pub rtt_ms: u32,
    pub effective_jpeg_quality: u8,
    pub effective_fps_cap: u8,
    pub cursor_mode: &'static str,
    pub active_codec_summary: &'static str,
    pub max_in_flight_sync: u8,
    pub drops_stale_frames: bool,
    pub estimated_glass_latency_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_all_25_extracted_keymaps() {
        assert_eq!(KEYBOARD_LAYOUTS.len(), 25);
        assert!(KEYBOARD_LAYOUTS
            .iter()
            .any(|k| k.id == "ja-jp-qwerty" && k.lcid == 0x0411));
        assert!(KEYBOARD_LAYOUTS
            .iter()
            .any(|k| k.id == "pt-br-qwerty" && k.lcid == 0x10416));
    }

    #[test]
    fn validates_bounds_and_rejects_invalid_layouts() {
        let mut s = RemoteDesktopSettings::default();
        assert!(s.validate().is_ok());

        s.target_fps = 5;
        assert_eq!(s.validate(), Err(SettingsError::InvalidFps(5)));

        s.target_fps = 30;
        s.jpeg_quality_floor = 99;
        assert_eq!(s.validate(), Err(SettingsError::InvalidQualityFloor(99)));

        s.jpeg_quality_floor = 55;
        s.otel_sample_ratio = 1.5;
        assert_eq!(s.validate(), Err(SettingsError::InvalidSampleRatio(1.5)));

        s.otel_sample_ratio = 1.0;
        s.keyboard_layout = "klingon-qwerty".to_owned();
        assert_eq!(
            s.validate(),
            Err(SettingsError::UnknownKeyboardLayout(
                "klingon-qwerty".to_owned()
            ))
        );
    }

    #[test]
    fn lag_adaptive_quality_respects_guacamole_curve_and_floor() {
        let mut s = RemoteDesktopSettings::default();
        s.apply_preset(NetworkPreset::ConstrainedWan);
        assert_eq!(s.effective_jpeg_quality(15), 90);
        assert_eq!(s.effective_jpeg_quality(50), 60);
        assert_eq!(s.effective_jpeg_quality(250), 30);

        s.apply_preset(NetworkPreset::UltraLowLatency);
        assert_eq!(s.effective_jpeg_quality(250), 95);
    }
}
