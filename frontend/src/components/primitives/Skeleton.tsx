export interface SkeletonProps {
  className?: string;
  width?: string | number;
  height?: string | number;
}

export function Skeleton({ className = '', width, height }: SkeletonProps) {
  return (
    <div
      aria-hidden="true"
      className={`oq-skeleton rounded-[var(--radius-sm)] ${className}`}
      style={{ width, height }}
    />
  );
}

export function SkeletonRow({ className = '' }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={`flex items-center gap-3 px-3 py-2.5 border-b border-[var(--border)]/60 ${className}`}
    >
      <Skeleton className="h-3.5 w-3.5 rounded-full shrink-0" />
      <Skeleton className="h-3.5 flex-1 max-w-[180px]" />
      <Skeleton className="h-3.5 w-24 hidden sm:block" />
      <Skeleton className="h-3.5 w-16 ml-auto" />
    </div>
  );
}

export function SkeletonCard({ className = '' }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={`bg-[var(--surface)] border border-[var(--border)] rounded-[var(--radius-lg)] p-4 space-y-2.5 ${className}`}
    >
      <Skeleton className="h-3 w-20" />
      <Skeleton className="h-7 w-24" />
      <Skeleton className="h-3 w-32" />
    </div>
  );
}

