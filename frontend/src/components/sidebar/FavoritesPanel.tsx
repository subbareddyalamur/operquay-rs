import { Star } from 'lucide-react';
import { useInstancesStore } from '@/stores/instances';
import type { AccountNode } from '@/lib/types';
import { InstanceRow } from './InstanceRow';

export function FavoritesPanel({ accounts }: { accounts?: AccountNode[] } = {}) {
  const storeAccounts = useInstancesStore((s) => s.accounts);
  const favorites = useInstancesStore((s) => s.favorites);
  const sourceAccounts = accounts ?? storeAccounts;

  const favInstances = sourceAccounts
    .flatMap((a) =>
      a.regions.flatMap((r) => r.groups.flatMap((g) => g.instances.map((instance) => ({ instance, provider: a.provider })))),
    )
    .filter(({ instance }) => favorites.includes(instance.instance_id));

  if (favInstances.length === 0) return null;

  return (
    <section className="rounded-xl border border-border/70 bg-surface/50 p-1.5 space-y-1" aria-label="Favorites">
      <header className="px-1.5 py-0.5 text-[10.5px] font-semibold text-text-dim uppercase tracking-wider flex items-center gap-1.5">
        <Star size={11} className="text-warn" aria-hidden />
        <span>Favorites</span>
        <span className="ml-auto font-mono font-normal text-text-mut">({favInstances.length})</span>
      </header>
      <div className="space-y-0.5">
        {favInstances.map(({ instance, provider }) => (
          <InstanceRow key={instance.instance_id} instance={instance} showAccount provider={provider} />
        ))}
      </div>
    </section>
  );
}
