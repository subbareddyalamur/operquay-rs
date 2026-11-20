import { create } from 'zustand';
import {
  DEFAULT_SETTINGS,
  NETWORK_PRESET_CARDS,
  RemoteDesktopSettingsSchema,
  type EngineCapability,
  type KeyboardLayoutDescriptor,
  type NetworkPreset,
  type RemoteDesktopSettings,
  type TelemetrySummary,
} from './schema';

interface ToastState {
  id: string;
  tone: 'success' | 'danger' | 'info';
  message: string;
}

interface SettingsStoreState {
  saved: RemoteDesktopSettings;
  draft: RemoteDesktopSettings;
  capabilities: EngineCapability[];
  keyboardLayouts: KeyboardLayoutDescriptor[];
  telemetrySummary: TelemetrySummary | null;
  lastTraceId: string;
  loading: boolean;
  saving: boolean;
  simulatedRttMs: 15 | 120 | 280;
  toast: ToastState | null;
  loadAll: () => Promise<void>;
  refreshTelemetry: () => Promise<void>;
  updateField: <K extends keyof RemoteDesktopSettings>(key: K, value: RemoteDesktopSettings[K]) => void;
  applyPreset: (presetId: Exclude<NetworkPreset, 'custom'>) => void;
  discardDraft: () => void;
  saveDraft: () => Promise<boolean>;
  resetServerDefaults: () => Promise<void>;
  setSimulatedRtt: (rtt: 15 | 120 | 280) => void;
  dismissToast: () => void;
}

export const useSettingsStore = create<SettingsStoreState>((set, get) => ({
  saved: DEFAULT_SETTINGS,
  draft: DEFAULT_SETTINGS,
  capabilities: [],
  keyboardLayouts: [],
  telemetrySummary: null,
  lastTraceId: '00000000000000000000000000000000',
  loading: false,
  saving: false,
  simulatedRttMs: 120,
  toast: null,

  loadAll: async () => {
    set({ loading: true });
    try {
      const [settingsRes, protoRes, telRes] = await Promise.all([
        fetch('/api/v1/settings/remote-desktop'),
        fetch('/api/v1/protocols'),
        fetch('/api/v1/telemetry/summary'),
      ]);

      if (settingsRes.ok) {
        const data = (await settingsRes.json()) as {
          settings: RemoteDesktopSettings;
          trace_id: string;
        };
        const parsed = RemoteDesktopSettingsSchema.safeParse(data.settings);
        if (parsed.success) {
          set({ saved: parsed.data, draft: parsed.data, lastTraceId: data.trace_id });
        }
      }
      if (protoRes.ok) {
        const p = (await protoRes.json()) as {
          capabilities: EngineCapability[];
          keyboard_layouts: KeyboardLayoutDescriptor[];
        };
        set({ capabilities: p.capabilities, keyboardLayouts: p.keyboard_layouts });
      }
      if (telRes.ok) {
        const t = (await telRes.json()) as { summary: TelemetrySummary; trace_id: string };
        set({ telemetrySummary: t.summary, lastTraceId: t.trace_id });
      }
    } catch {
      set({
        toast: {
          id: String(Date.now()),
          tone: 'danger',
          message: 'Unable to reach Operquay-Rust API; using local defaults.',
        },
      });
    } finally {
      set({ loading: false });
    }
  },

  refreshTelemetry: async () => {
    try {
      const res = await fetch('/api/v1/telemetry/summary');
      if (res.ok) {
        const data = (await res.json()) as { summary: TelemetrySummary; trace_id: string };
        set({ telemetrySummary: data.summary, lastTraceId: data.trace_id });
      }
    } catch {
      // Ignore background telemetry refresh transient error
    }
  },

  updateField: (key, value) => {
    set((state) => {
      const next: RemoteDesktopSettings = {
        ...state.draft,
        [key]: value,
      };
      if (key !== 'network_preset') {
        next.network_preset = 'custom';
      }
      return { draft: next };
    });
  },

  applyPreset: (presetId) => {
    const preset = NETWORK_PRESET_CARDS.find((c) => c.id === presetId);
    if (!preset) return;
    set((state) => ({
      draft: {
        ...state.draft,
        ...preset.patch,
      },
    }));
  },

  discardDraft: () => {
    set((state) => ({ draft: state.saved }));
  },

  saveDraft: async () => {
    const { draft } = get();
    const checked = RemoteDesktopSettingsSchema.safeParse(draft);
    if (!checked.success) {
      set({
        toast: {
          id: String(Date.now()),
          tone: 'danger',
          message: checked.error.issues[0]?.message ?? 'Invalid settings values',
        },
      });
      return false;
    }

    set({ saving: true });
    try {
      const res = await fetch('/api/v1/settings/remote-desktop', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(checked.data),
      });
      if (!res.ok) {
        const errBody = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(errBody.error ?? `HTTP ${res.status}`);
      }
      const data = (await res.json()) as {
        settings: RemoteDesktopSettings;
        trace_id: string;
      };
      set({
        saved: data.settings,
        draft: data.settings,
        lastTraceId: data.trace_id,
        toast: {
          id: String(Date.now()),
          tone: 'success',
          message: 'Remote desktop profile saved and applied.',
        },
      });
      void get().refreshTelemetry();
      return true;
    } catch (e) {
      set({
        toast: {
          id: String(Date.now()),
          tone: 'danger',
          message: e instanceof Error ? e.message : 'Save failed',
        },
      });
      return false;
    } finally {
      set({ saving: false });
    }
  },

  resetServerDefaults: async () => {
    set({ saving: true });
    try {
      const res = await fetch('/api/v1/settings/remote-desktop/reset', { method: 'POST' });
      if (res.ok) {
        const data = (await res.json()) as {
          settings: RemoteDesktopSettings;
          trace_id: string;
        };
        set({
          saved: data.settings,
          draft: data.settings,
          lastTraceId: data.trace_id,
          toast: {
            id: String(Date.now()),
            tone: 'info',
            message: 'Restored default adaptive remote desktop profile.',
          },
        });
        void get().refreshTelemetry();
      }
    } finally {
      set({ saving: false });
    }
  },

  setSimulatedRtt: (rtt) => set({ simulatedRttMs: rtt }),
  dismissToast: () => set({ toast: null }),
}));

