import { useAuthStore } from '@/stores/auth';
import { useInstancesStore } from '@/stores/instances';
import { getAllInstances } from '@/lib/filter';
import type { EC2Instance } from '@/lib/types';

export const isUserAWSMode = () => useAuthStore.getState().config?.aws_access_mode === 'user';

/** In user mode, the connected role and the instance from its scan; null when either is missing. */
export function userScopedInstance(instanceId: string): { roleID: string; instance: EC2Instance } | null {
  const { instanceRoles, accounts } = useInstancesStore.getState();
  const roleID = instanceRoles[instanceId];
  if (!isUserAWSMode() || !roleID) return null;
  const instance = getAllInstances(accounts).find((i) => i.instance_id === instanceId);
  return instance ? { roleID, instance } : null;
}

export const instanceEnv = (i: EC2Instance) => i.tags?.Environment ?? i.tags?.environment ?? i.tag2_value ?? '';
