import { create } from 'zustand';
import { persist, createJSONStorage, devtools, subscribeWithSelector } from 'zustand/middleware';
import { canSendCredentials } from '@/lib/credentialTransport';
import { normalizeTerminalEngine, type TerminalEngineKind } from '@/lib/terminal-engine';
import {
  formatTerminalFontStack,
  normalizeTerminalFont,
  TERMINAL_FONTS,
} from '@/lib/xterm-themes';
import { useToastStore } from './toast';

export { formatTerminalFontStack, normalizeTerminalFont, TERMINAL_FONTS };

export interface EnvColorMapping {
  env: string;
  color: string;
  width: number;
}

interface SettingsState {
  fontSize: number;
  fontFamily: string;
  appZoom: number;
  theme: string;
  compactMode: boolean;
  enableEnvBorders: boolean;
  enableKubernetes: boolean;
  enableDatabases: boolean;
  scrollbackLines: number;
  terminalEngine: TerminalEngineKind;
  assistantName: string;
  aiProvider: string;
  aiModel: string;
  aiApiKey: string;
  aiBaseUrl: string;
  bedrockAuthMode: 'profile' | 'api_key' | 'inference_profile';
  bedrockRegion: string;
  bedrockProfile: string;
  bedrockAccessKeyId: string;
  bedrockSecretKey: string;
  bedrockSessionToken: string;
  bedrockInferenceProfileArn: string;
  s3Bucket: string;
  envColors: EnvColorMapping[];
  snippets: Array<{ name: string; command: string; category?: string }>;
  setFontSize: (n: number) => void;
  setAppZoom: (n: number) => void;
  zoomIn: () => void;
  zoomOut: () => void;
  resetZoom: () => void;
  setTheme: (t: string) => void;
  setCompactMode: (v: boolean) => void;
  setEnableEnvBorders: (v: boolean) => void;
  setEnableKubernetes: (v: boolean) => void;
  setEnableDatabases: (v: boolean) => void;
  setScrollbackLines: (n: number) => void;
  setTerminalEngine: (engine: TerminalEngineKind) => void;
  setS3Bucket: (b: string) => void;
  setAssistantName: (name: string) => void;
  addEnvColor: (m: EnvColorMapping) => void;
  removeEnvColor: (env: string) => void;
  loadFromServer: () => Promise<void>;
  saveToServer: () => Promise<boolean>;
}

const DEFAULT_ENV_COLORS: EnvColorMapping[] = [
  { env: 'prod', color: 'var(--env-preset-danger)', width: 4 },
  { env: 'staging', color: 'var(--warn)', width: 3 },
  { env: 'dev', color: 'var(--success)', width: 2 },
  { env: 'test', color: 'var(--info)', width: 2 },
];

export const DEFAULT_ASSISTANT_NAME = 'Oi';
/** Trimmed, at most 16 characters; empty falls back to the default. */
export const assistantName = (name: unknown) => (typeof name === 'string' ? name.trim().slice(0, 16) : '') || DEFAULT_ASSISTANT_NAME;

const MIN_FONT = 10;
const MAX_FONT = 22;
const DEFAULT_FONT = 13;

export const useSettingsStore = create<SettingsState>()(
  devtools(
    subscribeWithSelector(
      persist(
        (set, get) => ({
          fontSize: DEFAULT_FONT,
          fontFamily: 'JetBrains Mono',
          appZoom: 100,
          theme: 'warp',
          compactMode: false,
          enableEnvBorders: true,
          enableKubernetes: typeof window !== 'undefined' ? window.localStorage.getItem('enableKubernetes') !== 'false' : true,
          enableDatabases: typeof window !== 'undefined' ? window.localStorage.getItem('enableDatabases') !== 'false' : true,
          scrollbackLines: 10000,
          terminalEngine: 'xterm',
          assistantName: DEFAULT_ASSISTANT_NAME,
          aiProvider: 'bedrock',
          aiModel: 'claude-sonnet-4-5',
          aiApiKey: '',
          aiBaseUrl: '',
          bedrockAuthMode: 'profile' as const,
          bedrockRegion: 'us-east-1',
          bedrockProfile: 'default',
          bedrockAccessKeyId: '',
          bedrockSecretKey: '',
          bedrockSessionToken: '',
          bedrockInferenceProfileArn: '',
          s3Bucket: '',
          envColors: DEFAULT_ENV_COLORS,
          snippets: [],
          setFontSize: (n) => set({ fontSize: Math.max(MIN_FONT, Math.min(MAX_FONT, n)) }),
          setAppZoom: (n) => set({ appZoom: Math.max(50, Math.min(200, n)) }),
          zoomIn: () => get().setFontSize(get().fontSize + 1),
          zoomOut: () => get().setFontSize(get().fontSize - 1),
          resetZoom: () => set({ fontSize: DEFAULT_FONT, appZoom: 100 }),
          setTheme: (t) => set({ theme: t }),
          setCompactMode: (v) => set({ compactMode: v }),
          setEnableEnvBorders: (v) => set({ enableEnvBorders: v }),
          setEnableKubernetes: (v) => {
            if (typeof window !== 'undefined') window.localStorage.setItem('enableKubernetes', String(v));
            set({ enableKubernetes: v });
          },
          setEnableDatabases: (v) => {
            if (typeof window !== 'undefined') window.localStorage.setItem('enableDatabases', String(v));
            set({ enableDatabases: v });
          },
          setScrollbackLines: (n) => set({ scrollbackLines: Math.max(1000, Math.min(100000, n)) }),
          setTerminalEngine: (engine) => set({ terminalEngine: normalizeTerminalEngine(engine) }),
          setS3Bucket: (b) => set({ s3Bucket: b }),
          setAssistantName: (name) => set({ assistantName: name.slice(0, 16) }),
          addEnvColor: (m) => set((s) => ({
            envColors: [...s.envColors.filter((e) => e.env !== m.env), m],
          })),
          removeEnvColor: (env) => set((s) => ({
            envColors: s.envColors.filter((e) => e.env !== env),
          })),
          loadFromServer: async () => {
            if (!canSendCredentials('/preferences')) return;
            try {
              const res = await fetch('/preferences');
              if (!res.ok) return;
              const data = await res.json() as Record<string, unknown>;
              if (data && typeof data === 'object') {
                const patch: Partial<SettingsState> = {};
                if (typeof data.fontSize === 'number') patch.fontSize = data.fontSize as number;
                if (typeof data.fontFamily === 'string') patch.fontFamily = normalizeTerminalFont(data.fontFamily);
                if (typeof data.theme === 'string') patch.theme = data.theme as string;
                if (typeof data.assistantName === 'string') patch.assistantName = assistantName(data.assistantName);
                if (typeof data.aiProvider === 'string') patch.aiProvider = data.aiProvider as string;
                if (typeof data.aiModel === 'string') patch.aiModel = data.aiModel as string;
                if (typeof data.aiApiKey === 'string') patch.aiApiKey = data.aiApiKey as string;
                if (typeof data.aiBaseUrl === 'string') patch.aiBaseUrl = data.aiBaseUrl as string;
                if (typeof data.bedrockAuthMode === 'string') patch.bedrockAuthMode = data.bedrockAuthMode as SettingsState['bedrockAuthMode'];
                if (typeof data.bedrockRegion === 'string') patch.bedrockRegion = data.bedrockRegion as string;
                if (typeof data.bedrockProfile === 'string') patch.bedrockProfile = data.bedrockProfile as string;
                if (typeof data.bedrockAccessKeyId === 'string') patch.bedrockAccessKeyId = data.bedrockAccessKeyId as string;
                if (typeof data.bedrockSecretKey === 'string') patch.bedrockSecretKey = data.bedrockSecretKey as string;
                if (typeof data.bedrockSessionToken === 'string') patch.bedrockSessionToken = data.bedrockSessionToken as string;
                if (typeof data.bedrockInferenceProfileArn === 'string') patch.bedrockInferenceProfileArn = data.bedrockInferenceProfileArn as string;
                if (typeof data.s3Bucket === 'string') patch.s3Bucket = data.s3Bucket as string;
                if (typeof data.compactMode === 'boolean') patch.compactMode = data.compactMode as boolean;
                if (Array.isArray(data.envColors)) patch.envColors = data.envColors as EnvColorMapping[];
                if (Array.isArray(data.snippets)) patch.snippets = data.snippets as Array<{ name: string; command: string; category?: string }>;
                if (typeof data.enableEnvBorders === 'boolean') patch.enableEnvBorders = data.enableEnvBorders as boolean;
                if (typeof data.enableKubernetes === 'boolean') patch.enableKubernetes = data.enableKubernetes as boolean;
                if (typeof data.enableDatabases === 'boolean') patch.enableDatabases = data.enableDatabases as boolean;
                if (typeof data.scrollbackLines === 'number') patch.scrollbackLines = data.scrollbackLines as number;
                if (typeof data.terminalEngine === 'string') patch.terminalEngine = normalizeTerminalEngine(data.terminalEngine);
                set(patch);
              }
            } catch {
              // Server preferences unavailable — use localStorage
            }
          },
          saveToServer: async () => {
            if (!canSendCredentials('/preferences')) return false;
            const s = get();
            const payload = {
              fontSize: s.fontSize,
              fontFamily: s.fontFamily,
              theme: s.theme,
              assistantName: assistantName(s.assistantName),
              aiProvider: s.aiProvider,
              aiModel: s.aiModel,
              aiApiKey: s.aiApiKey,
              aiBaseUrl: s.aiBaseUrl,
              bedrockAuthMode: s.bedrockAuthMode,
              bedrockRegion: s.bedrockRegion,
              bedrockProfile: s.bedrockProfile,
              bedrockAccessKeyId: s.bedrockAccessKeyId,
              bedrockSecretKey: s.bedrockSecretKey,
              bedrockSessionToken: s.bedrockSessionToken,
              bedrockInferenceProfileArn: s.bedrockInferenceProfileArn,
              s3Bucket: s.s3Bucket,
              compactMode: s.compactMode,
              enableEnvBorders: s.enableEnvBorders,
              enableKubernetes: s.enableKubernetes,
              enableDatabases: s.enableDatabases,
              scrollbackLines: s.scrollbackLines,
              terminalEngine: normalizeTerminalEngine(s.terminalEngine),
              envColors: s.envColors,
            };
            try {
              const response = await fetch('/preferences', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
              });
              return response.ok;
            } catch {
              return false;
            }
          },
        }),
        {
          name: 'ct-settings',
          storage: createJSONStorage(() => localStorage),
          merge: (persistedState, currentState) => {
            const p = (persistedState as Partial<SettingsState> | undefined) ?? {};
            return {
              ...currentState,
              ...p,
              fontFamily: normalizeTerminalFont(p.fontFamily ?? currentState.fontFamily),
            };
          },
        },
      ),
    ),
    { name: 'settings' },
  ),
);

// Auto-save to server on any change (debounced 2s)
let saveTimer: ReturnType<typeof setTimeout> | null = null;
useSettingsStore.subscribe(
  (s) => ({
    fontSize: s.fontSize,
    fontFamily: s.fontFamily,
    theme: s.theme,
    assistantName: s.assistantName,
    aiProvider: s.aiProvider,
    aiModel: s.aiModel,
    aiApiKey: s.aiApiKey,
    aiBaseUrl: s.aiBaseUrl,
    bedrockAuthMode: s.bedrockAuthMode,
    bedrockRegion: s.bedrockRegion,
    bedrockProfile: s.bedrockProfile,
    bedrockAccessKeyId: s.bedrockAccessKeyId,
    bedrockSecretKey: s.bedrockSecretKey,
    bedrockInferenceProfileArn: s.bedrockInferenceProfileArn,
    s3Bucket: s.s3Bucket,
    compactMode: s.compactMode,
    enableEnvBorders: s.enableEnvBorders,
    enableKubernetes: s.enableKubernetes,
    enableDatabases: s.enableDatabases,
    scrollbackLines: s.scrollbackLines,
    terminalEngine: normalizeTerminalEngine(s.terminalEngine),
    envColors: s.envColors,
    snippets: s.snippets,
  }),
  () => {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      void useSettingsStore.getState().saveToServer().then((saved) => {
        if (!saved) useToastStore.getState().push({ variant: 'danger', title: 'Could not save settings', description: 'Check HTTPS and the server connection, then try again.', duration: 6000 });
      });
    }, 2000);
  },
  { equalityFn: (a, b) => JSON.stringify(a) === JSON.stringify(b) },
);

// Load from server on first import
if (typeof window !== 'undefined') {
  void useSettingsStore.getState().loadFromServer();
}
