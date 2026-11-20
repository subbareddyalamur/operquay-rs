import { useQuery, useQueryClient } from '@tanstack/react-query';
import { apiGet } from '@/lib/api';
import type { VPCTopology, ExposureResult, RuleConflict } from '@/lib/topology-types';

const STALE_MS = 5 * 60 * 1000;

function snakeToCamel(s: string): string {
  return s.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
}

function deepCamelCase(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(deepCamelCase);
  if (typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[snakeToCamel(key)] = deepCamelCase(value);
    }
    return result;
  }
  return obj;
}

export type UserTopologyScope = { roleID: string; region: string; cacheKey: string; peerIDs?: string[] };

export function useTopology(instanceId: string | null, scope?: UserTopologyScope) {
  return useQuery({
    queryKey: ['topology', instanceId, scope?.roleID, scope?.region, scope?.cacheKey, scope?.peerIDs ?? []],
    queryFn: async () => {
      if (!instanceId) throw new Error('No instance ID');
      const path = scope ? `/api/aws/topology?binding_id=${encodeURIComponent(scope.roleID)}&region=${encodeURIComponent(scope.region)}&instance_id=${encodeURIComponent(instanceId)}${(scope.peerIDs ?? []).map(id => `&peer_binding_id=${encodeURIComponent(id)}`).join('')}` : `/topology/${encodeURIComponent(instanceId)}`;
      const res = await apiGet<Record<string, unknown>>(path);
      if (!res.ok) throw new Error(res.error.message);
      return deepCamelCase(res.value) as VPCTopology;
    },
    enabled: instanceId != null && instanceId.length > 0,
    staleTime: scope ? 0 : STALE_MS,
    gcTime: scope ? 0 : undefined,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: 1,
  });
}

export function useTopologyExposure(instanceId: string | null) {
  return useQuery({
    queryKey: ['topology-exposure', instanceId],
    queryFn: async () => {
      if (!instanceId) throw new Error('No instance ID');
      const res = await apiGet<ExposureResult>(`/topology/exposure/${instanceId}`);
      if (!res.ok) throw new Error(res.error.message);
      return res.value;
    },
    enabled: instanceId != null && instanceId.length > 0,
    staleTime: STALE_MS,
  });
}

export function useTopologyConflicts(instanceId: string | null) {
  return useQuery({
    queryKey: ['topology-conflicts', instanceId],
    queryFn: async () => {
      if (!instanceId) throw new Error('No instance ID');
      const res = await apiGet<RuleConflict[]>(`/topology/conflicts/${instanceId}`);
      if (!res.ok) throw new Error(res.error.message);
      return res.value;
    },
    enabled: instanceId != null && instanceId.length > 0,
    staleTime: STALE_MS,
  });
}

export function useInvalidateTopology() {
  const qc = useQueryClient();
  return (instanceId: string) => {
    void qc.invalidateQueries({ queryKey: ['topology', instanceId] });
    void qc.invalidateQueries({ queryKey: ['topology-exposure', instanceId] });
    void qc.invalidateQueries({ queryKey: ['topology-conflicts', instanceId] });
  };
}
