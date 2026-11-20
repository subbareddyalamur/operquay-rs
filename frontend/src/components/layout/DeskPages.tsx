import { SettingsModal } from '@/components/settings/SettingsModal';
import { useLayoutStore } from '@/stores/layout';

/** Full-page Settings, including Operations and Tools. Closing returns to the workspace that was open. */
export function DeskPage() {
  const settingsTab = useLayoutStore((s) => s.settingsTab);
  const closeSettings = useLayoutStore((s) => s.closeSettings);
  return (
    <div className="desk-page absolute inset-0 overflow-hidden bg-bg">
      <SettingsModal open asPage initialTab={settingsTab} onOpenChange={closeSettings} />
    </div>
  );
}
