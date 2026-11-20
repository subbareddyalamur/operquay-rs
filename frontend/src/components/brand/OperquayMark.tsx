/** Same geometry as brand/operquay/mark.svg. The file is the artwork for external use. */
export function OperquayMark({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true" className="shrink-0 text-accent">
      <rect x="2.25" y="2.25" width="27.5" height="27.5" rx="7" stroke="currentColor" strokeWidth="2.25" />
      <path d="M12.2 10.4 L20.4 16 L12.2 21.6" stroke="currentColor" strokeWidth="2.25" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
