export type ProtocolScope = 'all' | 'rdp' | 'vnc';

export type SettingsSectionId =
  | 'profiles'
  | 'display'
  | 'input'
  | 'security'
  | 'recording'
  | 'telemetry';

export interface SettingsSectionDescriptor {
  id: SettingsSectionId;
  title: string;
  subtitle: string;
  group: 'Performance' | 'Protocols & Security' | 'Observability';
  protocolScope: ProtocolScope;
  keywords: readonly string[];
  defaultExpanded: boolean;
}

/**
 * Declarative Settings Registry (RULES.md §2.2).
 * Adding a new remote protocol or enterprise policy section is one entry here.
 */
export const SETTINGS_SECTIONS: readonly SettingsSectionDescriptor[] = [
  {
    id: 'profiles',
    title: 'Connection Profiles & Network Simulator',
    subtitle: 'Goal-based presets tuned for LAN, Cloud/SSM, and high-RTT WAN links',
    group: 'Performance',
    protocolScope: 'all',
    keywords: ['preset', 'latency', 'wan', 'lan', 'ssm', 'fps', 'quality', 'oqr2', 'mstsc'],
    defaultExpanded: true,
  },
  {
    id: 'display',
    title: 'Display Pipeline & Adaptive Codecs',
    subtitle: 'Subprotocol framing, 64x64 CopyRect scroll acceleration, and dynamic MS-RDPEDISP resize',
    group: 'Performance',
    protocolScope: 'all',
    keywords: ['codec', 'png', 'jpeg', 'copyrect', 'resize', 'hidpi', 'fps', 'clearcodec', 'avc420'],
    defaultExpanded: true,
  },
  {
    id: 'input',
    title: 'Input Prediction & 25-LCID Keyboard Engine',
    subtitle: 'Zero-RTT local cursor overlay, pointer coalescing, and Windows LCID / Unicode fallback maps',
    group: 'Protocols & Security',
    protocolScope: 'rdp',
    keywords: ['cursor', 'keyboard', 'layout', 'lcid', 'unicode', 'ime', 'mouse', 'scancode'],
    defaultExpanded: false,
  },
  {
    id: 'security',
    title: 'Authentication & Certificate Verification',
    subtitle: 'Clean-room RDP NLA / HYBRID_EX, VNC DES Auth / VeNCrypt TLS, and TOFU host pinning',
    group: 'Protocols & Security',
    protocolScope: 'all',
    keywords: ['nla', 'hybrid', 'tls', 'vncauth', 'vencrypt', 'tofu', 'certificate', 'zeroize', 'ironrdp'],
    defaultExpanded: false,
  },
  {
    id: 'recording',
    title: 'Clipboard, Fail-Closed Recording & Compliance',
    subtitle: 'Line-ending normalization, mandatory audit capture, and disabled host drive policy',
    group: 'Protocols & Security',
    protocolScope: 'all',
    keywords: ['clipboard', 'recording', 'audit', 'crlf', 'drive', 'rdpdr', 'compliance'],
    defaultExpanded: false,
  },
  {
    id: 'telemetry',
    title: 'OpenTelemetry & Transport Diagnostics',
    subtitle: 'W3C trace sampling, Prometheus /metrics counters, and live HUD inspection',
    group: 'Observability',
    protocolScope: 'all',
    keywords: ['opentelemetry', 'otel', 'prometheus', 'trace', 'metrics', 'hud', 'latency'],
    defaultExpanded: false,
  },
];

export function filterSections(
  query: string,
  scope: ProtocolScope,
): readonly SettingsSectionDescriptor[] {
  const q = query.trim().toLowerCase();
  return SETTINGS_SECTIONS.filter((sec) => {
    const scopeMatch = scope === 'all' || sec.protocolScope === 'all' || sec.protocolScope === scope;
    if (!scopeMatch) return false;
    if (!q) return true;
    const haystack = `${sec.title} ${sec.subtitle} ${sec.keywords.join(' ')}`.toLowerCase();
    return haystack.includes(q);
  });
}

