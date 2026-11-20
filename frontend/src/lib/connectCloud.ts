import { useAuthStore } from '@/stores/auth';
import { useLayoutStore } from '@/stores/layout';

/** Opens the place where this user connects cloud accounts: their own sign-in dialog, or the admin AWS accounts page. */
export function connectCloud() {
  if (useAuthStore.getState().config?.aws_access_mode === 'user') window.dispatchEvent(new CustomEvent('ct:open-aws-accounts'));
  else useLayoutStore.getState().openSettings('accounts');
}

