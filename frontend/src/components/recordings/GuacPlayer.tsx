import { GuacRecordingPlayer } from '@/rust-engines/GuacRecordingPlayer';

export interface GuacPlayerProps {
  filename?: string;
  owner?: string;
  src?: string;
  className?: string;
  embedded?: boolean;
  onClose?: () => void;
}

export function GuacPlayer({ filename, src, className = '', embedded = false, onClose }: GuacPlayerProps) {
  const rawId = filename ?? (src ? (src.split('/').pop()?.split('?')[0] ?? src) : '');
  return (
    <div className={`w-full h-full flex flex-col overflow-hidden ${className}`}>
      <GuacRecordingPlayer
        recordingId={decodeURIComponent(rawId)}
        embedded={embedded}
        onClose={onClose ?? (() => undefined)}
      />
    </div>
  );
}
