import { useEffect } from 'react';
import { DesktopStage } from '@/rust-engines/DesktopStage';
import { useSessionsStore } from '@/stores/sessions';
import { useLayoutStore } from '@/stores/layout';
import { useSettingsStore as useRdpSettingsStore } from '@/rust-engines/settings/store';

export interface RdpDesktopClientProps {
  sessionId: string;
  token: string;
  userScoped?: boolean;
  protocol?: 'rdp' | 'vnc';
  targetHost?: string;
  onSessionEnded?: (reason: string) => void;
}

export function RdpDesktopClient({
  sessionId,
  token,
  userScoped = false,
  protocol = 'rdp',
  targetHost,
  onSessionEnded,
}: RdpDesktopClientProps) {
  const savedLayout = useRdpSettingsStore((s) => s.saved.keyboard_layout);

  useEffect(() => {
    useSessionsStore.getState().updateStatus(sessionId, 'connecting');
  }, [sessionId]);

  const wsUrl = `/api/v1/ws/rdp?ticket=${encodeURIComponent(token)}&transport=oqr2`;

  return (
    <div className="w-full h-full flex flex-col overflow-hidden bg-[var(--bg)]">
      <DesktopStage
        protocol={protocol}
        targetHost={targetHost}
        wsUrl={wsUrl}
        sessionId={sessionId}
        initialKeyboardLayout={savedLayout}
        embedded={Boolean(userScoped || !targetHost)}
        showHud
        onSessionEnded={onSessionEnded}
        onBackToSettings={() => useLayoutStore.getState().openSettings('remote-desktop')}
      />
    </div>
  );
}
