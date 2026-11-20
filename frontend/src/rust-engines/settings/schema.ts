import { z } from 'zod';

export const NetworkPresetSchema = z.enum([
  'auto_adaptive',
  'ultra_low_latency',
  'balanced_wan',
  'constrained_wan',
  'custom',
]);
export type NetworkPreset = z.infer<typeof NetworkPresetSchema>;

export const ProtocolPreferenceSchema = z.enum(['auto', 'rdp', 'vnc']);
export type ProtocolPreference = z.infer<typeof ProtocolPreferenceSchema>;

export const TransportModeSchema = z.enum(['oqr2_binary', 'guacamole_compat']);
export type TransportMode = z.infer<typeof TransportModeSchema>;

export const CodecModeSchema = z.enum(['adaptive_hybrid', 'lossless_crisp', 'motion_priority']);
export type CodecMode = z.infer<typeof CodecModeSchema>;

export const RdpSecurityModeSchema = z.enum(['any', 'nla', 'nla_ext', 'tls', 'classic_rdp', 'vmconnect']);
export type RdpSecurityMode = z.infer<typeof RdpSecurityModeSchema>;

export const VncSecurityModeSchema = z.enum(['auto', 'vnc_auth', 've_ncrypt_tls', 'none']);
export type VncSecurityMode = z.infer<typeof VncSecurityModeSchema>;

export const CertPolicySchema = z.enum(['strict_ca', 'tofu_pinned', 'ssm_loopback_ignore']);
export type CertPolicy = z.infer<typeof CertPolicySchema>;

export const ClipboardNormalizationSchema = z.enum(['preserve', 'windows_crlf', 'unix_lf']);
export type ClipboardNormalization = z.infer<typeof ClipboardNormalizationSchema>;

export const RemoteDesktopSettingsSchema = z.object({
  network_preset: NetworkPresetSchema,
  protocol_preference: ProtocolPreferenceSchema,
  transport_mode: TransportModeSchema,
  codec_mode: CodecModeSchema,
  target_fps: z.number().int().min(10).max(60),
  jpeg_quality_floor: z.number().int().min(20).max(95),
  enable_copy_rect: z.boolean(),
  enable_dynamic_resize: z.boolean(),
  enable_local_cursor_prediction: z.boolean(),
  enable_mouse_coalescing: z.boolean(),
  keyboard_layout: z.string().min(1),
  unicode_fallback: z.boolean(),
  rdp_security_mode: RdpSecurityModeSchema,
  vnc_security_mode: VncSecurityModeSchema,
  cert_policy: CertPolicySchema,
  clipboard_normalization: ClipboardNormalizationSchema,
  fail_closed_recording: z.boolean(),
  enable_drive_redirection: z.boolean(),
  otel_sample_ratio: z.number().min(0).max(1),
  show_live_telemetry_hud: z.boolean(),
});

export type RemoteDesktopSettings = z.infer<typeof RemoteDesktopSettingsSchema>;

export interface KeyboardLayoutDescriptor {
  id: string;
  label: string;
  lcid_hex: string;
  lcid: number;
}

export const DEFAULT_KEYBOARD_LAYOUTS: readonly KeyboardLayoutDescriptor[] = [
  { id: 'en-us-qwerty', label: 'English (US QWERTY)', lcid_hex: '0x0409', lcid: 0x0409 },
  { id: 'en-gb-qwerty', label: 'English (UK QWERTY)', lcid_hex: '0x0809', lcid: 0x0809 },
  { id: 'de-de-qwertz', label: 'German (Germany QWERTZ)', lcid_hex: '0x0407', lcid: 0x0407 },
  { id: 'de-ch-qwertz', label: 'German (Swiss QWERTZ)', lcid_hex: '0x0807', lcid: 0x0807 },
  { id: 'fr-fr-azerty', label: 'French (France AZERTY)', lcid_hex: '0x040C', lcid: 0x040c },
  { id: 'fr-be-azerty', label: 'French (Belgium AZERTY)', lcid_hex: '0x080C', lcid: 0x080c },
  { id: 'fr-ca-qwerty', label: 'French (Canada QWERTY)', lcid_hex: '0x1009', lcid: 0x1009 },
  { id: 'fr-ch-qwertz', label: 'French (Swiss QWERTZ)', lcid_hex: '0x100C', lcid: 0x100c },
  { id: 'es-es-qwerty', label: 'Spanish (Spain QWERTY)', lcid_hex: '0x040A', lcid: 0x040a },
  { id: 'es-latam-qwerty', label: 'Spanish (Latin America)', lcid_hex: '0x080A', lcid: 0x080a },
  { id: 'cs-cz-qwertz', label: 'Czech (QWERTZ)', lcid_hex: '0x0405', lcid: 0x0405 },
  { id: 'hu-hu-qwertz', label: 'Hungarian (QWERTZ)', lcid_hex: '0x040E', lcid: 0x040e },
  { id: 'it-it-qwerty', label: 'Italian (QWERTY)', lcid_hex: '0x0410', lcid: 0x0410 },
  { id: 'ja-jp-qwerty', label: 'Japanese (QWERTY)', lcid_hex: '0x0411', lcid: 0x0411 },
  { id: 'no-no-qwerty', label: 'Norwegian (QWERTY)', lcid_hex: '0x0414', lcid: 0x0414 },
  { id: 'pl-pl-qwerty', label: 'Polish (Programmers QWERTY)', lcid_hex: '0x0415', lcid: 0x0415 },
  { id: 'pt-br-qwerty', label: 'Portuguese (Brazil ABNT2)', lcid_hex: '0x10416', lcid: 0x10416 },
  { id: 'pt-pt-qwerty', label: 'Portuguese (Portugal QWERTY)', lcid_hex: '0x0816', lcid: 0x0816 },
  { id: 'ro-ro-qwerty', label: 'Romanian (Standard)', lcid_hex: '0x0418', lcid: 0x0418 },
  { id: 'sv-se-qwerty', label: 'Swedish (QWERTY)', lcid_hex: '0x041D', lcid: 0x041d },
  { id: 'da-dk-qwerty', label: 'Danish (QWERTY)', lcid_hex: '0x0406', lcid: 0x0406 },
  { id: 'tr-tr-qwerty', label: 'Turkish (QWERTY)', lcid_hex: '0x041F', lcid: 0x041f },
  { id: 'failsafe', label: 'Unicode Failsafe Fallback', lcid_hex: '0x0409', lcid: 0x0409 },
  { id: 'base', label: 'Base POSIX Shared Keymap', lcid_hex: '0x0409', lcid: 0x0409 },
  { id: 'base-altgr', label: 'Base AltGr Extension', lcid_hex: '0x0409', lcid: 0x0409 },
];

export interface EngineCapability {
  protocol: string;
  display_name: string;
  default_port: number;
  security_modes: string[];
  codecs: string[];
  supports_dynamic_resize: boolean;
  supports_zero_rtt_cursor: boolean;
  supports_clipboard: boolean;
}

export interface NetworkSimulationResult {
  rtt_ms: number;
  effective_jpeg_quality: number;
  effective_fps_cap: number;
  cursor_mode: string;
  active_codec_summary: string;
  max_in_flight_sync: number;
  drops_stale_frames: boolean;
  estimated_glass_latency_ms: number;
}

export interface TelemetrySummary {
  service_name: string;
  otlp_configured: boolean;
  sessions_started_total: number;
  active_sessions: number;
  frames_encoded_total: number;
  frames_dropped_total: number;
  settings_updates_total: number;
  last_frame_encode_ms: number;
  last_input_rtt_ms: number;
}

export const DEFAULT_SETTINGS: RemoteDesktopSettings = {
  network_preset: 'auto_adaptive',
  protocol_preference: 'auto',
  transport_mode: 'oqr2_binary',
  codec_mode: 'adaptive_hybrid',
  target_fps: 30,
  jpeg_quality_floor: 55,
  enable_copy_rect: true,
  enable_dynamic_resize: true,
  enable_local_cursor_prediction: true,
  enable_mouse_coalescing: true,
  keyboard_layout: 'en-us-qwerty',
  unicode_fallback: true,
  rdp_security_mode: 'any',
  vnc_security_mode: 'auto',
  cert_policy: 'tofu_pinned',
  clipboard_normalization: 'preserve',
  fail_closed_recording: true,
  enable_drive_redirection: false,
  otel_sample_ratio: 1.0,
  show_live_telemetry_hud: true,
};

export interface PresetCardDescriptor {
  id: Exclude<NetworkPreset, 'custom'>;
  title: string;
  recommended?: boolean;
  summary: string;
  latencyTag: string;
  bandwidthTag: string;
  patch: Partial<RemoteDesktopSettings>;
}

export const NETWORK_PRESET_CARDS: readonly PresetCardDescriptor[] = [
  {
    id: 'auto_adaptive',
    title: 'Auto Adaptive',
    recommended: true,
    summary: 'Balances crisp PNG UI text with lag-scaled JPEG/AVC420 motion over any link.',
    latencyTag: 'Low lag',
    bandwidthTag: 'Adaptive',
    patch: {
      network_preset: 'auto_adaptive',
      transport_mode: 'oqr2_binary',
      codec_mode: 'adaptive_hybrid',
      target_fps: 30,
      jpeg_quality_floor: 55,
      enable_copy_rect: true,
      enable_local_cursor_prediction: true,
      enable_mouse_coalescing: true,
    },
  },
  {
    id: 'ultra_low_latency',
    title: 'Ultra-Low Latency LAN',
    summary: 'Native mstsc-grade clarity at 60 FPS with zero pointer coalescing for nearby VPC/LAN targets.',
    latencyTag: 'Lowest glass delay',
    bandwidthTag: 'High bitrate',
    patch: {
      network_preset: 'ultra_low_latency',
      transport_mode: 'oqr2_binary',
      codec_mode: 'lossless_crisp',
      target_fps: 60,
      jpeg_quality_floor: 85,
      enable_copy_rect: true,
      enable_local_cursor_prediction: true,
      enable_mouse_coalescing: false,
    },
  },
  {
    id: 'balanced_wan',
    title: 'Balanced Cloud / SSM',
    summary: 'Optimized for AWS SSM WebSocket DataChannels across regions with aggressive scroll CopyRect.',
    latencyTag: 'Smooth SSM',
    bandwidthTag: 'Moderate',
    patch: {
      network_preset: 'balanced_wan',
      transport_mode: 'oqr2_binary',
      codec_mode: 'adaptive_hybrid',
      target_fps: 30,
      jpeg_quality_floor: 50,
      enable_copy_rect: true,
      enable_local_cursor_prediction: true,
      enable_mouse_coalescing: true,
    },
  },
  {
    id: 'constrained_wan',
    title: 'Constrained / High-RTT WAN',
    summary: 'Coalesces intermediate frames under 200+ ms RTT to keep typing and mouse crisp.',
    latencyTag: 'Anti-bufferbloat',
    bandwidthTag: 'Lowest bitrate',
    patch: {
      network_preset: 'constrained_wan',
      transport_mode: 'oqr2_binary',
      codec_mode: 'motion_priority',
      target_fps: 20,
      jpeg_quality_floor: 30,
      enable_copy_rect: true,
      enable_local_cursor_prediction: true,
      enable_mouse_coalescing: true,
    },
  },
];

export function computeLocalSimulation(s: RemoteDesktopSettings, rttMs: number): NetworkSimulationResult {
  const guacQuality = s.codec_mode === 'lossless_crisp' ? 95 : rttMs <= 19 ? 90 : Math.max(30, 110 - rttMs);
  const quality = Math.max(guacQuality, s.codec_mode === 'lossless_crisp' ? 95 : s.jpeg_quality_floor);
  const codecSummary =
    s.transport_mode === 'guacamole_compat'
      ? 'Guacamole UTF-8: PNG/JPEG Base64 Compat'
      : s.codec_mode === 'lossless_crisp'
        ? 'OQR2 Binary: Lossless PNG + ClearCodec Crisp UI'
        : s.codec_mode === 'motion_priority'
          ? 'OQR2 Binary: Coalesced JPEG/AVC420 Motion Priority'
          : 'OQR2 Binary: PNG text + Adaptive JPEG + AVC420 pass-through';

  return {
    rtt_ms: rttMs,
    effective_jpeg_quality: quality,
    effective_fps_cap: rttMs > 200 ? Math.min(s.target_fps, 20) : s.target_fps,
    cursor_mode: s.enable_local_cursor_prediction ? 'zero_rtt_local' : 'server_roundtrip',
    active_codec_summary: codecSummary,
    max_in_flight_sync: s.network_preset === 'ultra_low_latency' ? 1 : 2,
    drops_stale_frames: rttMs > 90,
    estimated_glass_latency_ms: s.enable_local_cursor_prediction
      ? Math.floor(rttMs / 2) + (s.transport_mode === 'oqr2_binary' ? 4 : 11)
      : rttMs + 12,
  };
}

export function diffSettingsCount(a: RemoteDesktopSettings, b: RemoteDesktopSettings): number {
  const keys = Object.keys(a) as Array<keyof RemoteDesktopSettings>;
  return keys.filter((k) => a[k] !== b[k]).length;
}

