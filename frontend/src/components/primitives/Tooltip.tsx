import './ui-sdk-compat';
import { useCallback, useRef, useState, type ReactElement, type ReactNode } from 'react';
import {
  Tooltip as UITooltip,
  TooltipContent as UITooltipContent,
  TooltipTrigger as UITooltipTrigger,
} from '@ui-sdk/react/tooltip';

export interface TooltipProps {
  label?: ReactNode;
  content?: ReactNode;
  children: ReactElement<Record<string, unknown>>;
  side?: 'top' | 'bottom' | 'left' | 'right';
  sideOffset?: number;
  disabled?: boolean;
  closeOnPress?: boolean;
  shortcut?: string;
  /** Milliseconds before tooltip opens on hover (defaults to @ui-sdk/core default). */
  delay?: number;
  /** When true, only opens if the trigger or any `[data-truncate]` descendant is overflowed/truncated. */
  onlyWhenTruncated?: boolean;
}

function hasTruncatedText(root: HTMLElement | null): boolean {
  if (!root) return false;
  const targets = root.querySelectorAll('[data-truncate]');
  const elements = targets.length > 0 ? Array.from(targets) : [root];
  return elements.some((el) => {
    const htmlEl = el as HTMLElement;
    return (
      htmlEl.dataset.truncated === 'true' ||
      htmlEl.scrollWidth > htmlEl.clientWidth + 1 ||
      htmlEl.scrollHeight > htmlEl.clientHeight + 1
    );
  });
}

export function Tooltip({
  label,
  content,
  children,
  side = 'top',
  sideOffset = 6,
  disabled = false,
  closeOnPress = true,
  shortcut,
  delay,
  onlyWhenTruncated = false,
}: TooltipProps) {
  const triggerRef = useRef<HTMLElement | null>(null);
  const [isOpen, setIsOpen] = useState(false);
  const resolvedLabel = label ?? content;

  const handleOpenChange = useCallback(
    (nextOpen: boolean, details: { cancel: () => void }) => {
      if (nextOpen && onlyWhenTruncated && !hasTruncatedText(triggerRef.current)) {
        details.cancel();
        return;
      }
      setIsOpen(nextOpen);
    },
    [onlyWhenTruncated],
  );

  if (disabled || !resolvedLabel) return children;
  return (
    <UITooltip
      closeOnPress={closeOnPress}
      delay={delay}
      onOpenChange={handleOpenChange}
    >
      <UITooltipTrigger ref={triggerRef as never} render={children} />
      {isOpen && (
        <UITooltipContent
          side={side}
          sideOffset={sideOffset}
          className="z-50 flex items-center gap-2 max-w-[340px] px-2.5 py-1.5 text-xs font-medium text-[var(--text-pri)] bg-[var(--elev)] border border-[var(--border-strong)] rounded-[var(--radius)] shadow-[var(--shadow-sm)] pointer-events-none select-none break-words"
        >
          <span className="min-w-0 break-words">{resolvedLabel}</span>
          {shortcut && (
            <kbd className="font-mono text-[11px] px-1 py-0.5 rounded bg-[var(--surface)] border border-[var(--border)] text-[var(--text-dim)] shrink-0">
              {shortcut}
            </kbd>
          )}
        </UITooltipContent>
      )}
    </UITooltip>
  );
}
