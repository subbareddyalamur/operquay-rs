import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useEffect, useCallback, useState, useMemo, useRef } from 'react';
import { AppShell } from '@/components/layout/AppShell';
import '@/stores/theme';
import { usePaletteStore } from '@/stores/palette';
import { shortcuts } from '@/lib/shortcuts';
import { CmdKPalette } from '@/components/palette/CmdKPalette';
import { FleetDashboard } from '@/components/dashboard/FleetDashboard';
import { DatabasesWorkspace } from '@/components/databases/DatabasesWorkspace';
import { KubernetesWorkspace } from '@/components/kubernetes/KubernetesWorkspace';
import { DeskPage } from '@/components/layout/DeskPages';
import { useLayoutStore } from '@/stores/layout';
import { useSettingsStore } from '@/stores/settings';
import { PortForwardModal } from '@/components/modals/PortForwardModal';
import { UploadModal } from '@/components/modals/UploadModal';
import { DownloadModal } from '@/components/modals/DownloadModal';
import { FileBrowserModal } from '@/components/modals/FileBrowserModal';
import { CloneModal } from '@/components/modals/CloneModal';
import { useSessionsStore } from '@/stores/sessions';
import { useInstancesStore } from '@/stores/instances';
import { useToastStore } from '@/stores/toast';
import { TerminalSession } from '@/components/terminal/TerminalSession';
import { RDPCredentialsModal } from '@/components/rdp/RDPCredentialsModal';
import type { RDPCredentials } from '@/components/rdp/RDPCredentialsModal';
import type { Instance } from '@/stores/instances';
import { api } from '@/lib/api';
import { useAuthStore, hasPermission } from '@/stores/auth';
import { UserAWSRDP } from '@/components/sidebar/UserAWSRDP';
import { TopologyRoute } from '@/components/topology/TopologyRoute';
import { UserAWSTransfer } from '@/components/sidebar/UserAWSTransfer';
import { UserAWSForward } from '@/components/sidebar/UserAWSForward';
import { UserAWSClone } from '@/components/sidebar/UserAWSClone';
import { Dialog } from '@/components/primitives/Dialog';
import { Button } from '@/components/primitives/Button';
import { connectCloud } from '@/lib/connectCloud';
import { isUserAWSMode, userScopedInstance, instanceEnv } from '@/lib/userScope';
import type { EC2Instance } from '@/lib/types';
import { nanoid } from 'nanoid';

type UserAction = { kind: 'upload' | 'download' | 'forward' | 'clone'; roleID: string; instance: EC2Instance };
const USER_ACTION_TITLE: Record<UserAction['kind'], string> = { upload: 'Upload file', download: 'Download file', forward: 'Port forwarding', clone: 'Clone instance' };

/** Opens a user-scoped session for the connected role; returns false outside user mode so the shared-profile path runs. */
function requireLiveAWS(roleID: string): boolean {
  const role = useInstancesStore.getState().userRoles.find((r) => r.id === roleID);
  if (!role || role.live !== false) return true;
  useToastStore.getState().push({ variant: 'info', title: 'Sign in to AWS to connect', description: `${role.name} is saved from the last discovery. Connect it again with AWS SSO or an IAM role.`, duration: 6000 });
  window.dispatchEvent(new CustomEvent('ct:open-aws-accounts'));
  return false;
}

function openUserSession(kind: 'ssh' | 'rdp' | 'topology', instanceId: string): boolean {
  if (!isUserAWSMode()) return false;
  const scoped = userScopedInstance(instanceId);
  const requiredPerm = kind === 'ssh' ? 'session:ssh' : kind === 'rdp' ? 'session:rdp' : 'instances:read';
  const me = useAuthStore.getState().me;
  if (!scoped || (me && !hasPermission(me, requiredPerm))) return true;
  if (!requireLiveAWS(scoped.roleID)) return true;
  const { roleID, instance } = scoped;
  const scope = { roleID, region: instance.aws_region };
  const base = { instanceId, instanceName: instance.name || instanceId, env: instanceEnv(instance) };
  const sessions = useSessionsStore.getState();
  if (kind === 'ssh') sessions.openSession({ ...base, id: `aws-${nanoid()}`, type: 'ssh', status: 'connecting', userSSH: scope });
  else if (kind === 'rdp') sessions.openSession({ ...base, id: `rdp-${nanoid()}`, type: 'rdp', status: 'connecting', userRDP: scope });
  else sessions.openSession({ ...base, id: `topo-${nanoid()}`, type: 'topology', status: 'connected', userTopology: scope });
  return true;
}

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 5 * 60 * 1000, retry: 1 } } });

interface InstanceModalState {
  open: boolean;
  instanceId: string;
  instanceName: string;
  awsProfile?: string;
  awsRegion?: string;
  platform?: string;
  initialPath?: string;
}

const CLOSED_MODAL: InstanceModalState = { open: false, instanceId: '', instanceName: '' };

export function App() {
  const togglePalette = usePaletteStore((s) => s.toggle);

  const view = useLayoutStore((s) => s.view);
  const authReady = useAuthStore((s) => s.ready);
  const authRequired = useAuthStore((s) => s.config?.required ?? false);
  const userId = useAuthStore((s) => s.me?.user_id);
  const userAWS = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const enableKubernetes = useSettingsStore((s) => s.enableKubernetes ?? true);
  const enableDatabases = useSettingsStore((s) => s.enableDatabases ?? true);
  const [kubernetesOpened, setKubernetesOpened] = useState(false);
  const kubernetesFrame = useRef<HTMLIFrameElement>(null);
  const [rdpModalOpen, setRdpModalOpen] = useState(false);
  const [rdpPendingInstance, setRdpPendingInstance] = useState<Instance | null>(null);

  const [portForwardModal, setPortForwardModal] = useState<InstanceModalState>(CLOSED_MODAL);
  const [uploadModal, setUploadModal] = useState<InstanceModalState>(CLOSED_MODAL);
  const [downloadModal, setDownloadModal] = useState<InstanceModalState>(CLOSED_MODAL);
  const [fileBrowserModal, setFileBrowserModal] = useState<InstanceModalState>(CLOSED_MODAL);
  const [cloneModal, setCloneModal] = useState<InstanceModalState>(CLOSED_MODAL);
  const [expressUploadModal, setExpressUploadModal] = useState<InstanceModalState>(CLOSED_MODAL);
  const [expressDownloadModal, setExpressDownloadModal] = useState<InstanceModalState>(CLOSED_MODAL);

  const [userAction, setUserAction] = useState<UserAction | null>(null);
  const [rdpTokens, setRdpTokens] = useState<Record<string, string>>({});
  const [rdpRecording, setRdpRecording] = useState<Record<string, string>>({});
  const [rdpStatus, setRdpStatus] = useState<Record<string, 'connecting' | 'error'>>({});

  const activeId = useSessionsStore((s) => s.activeId);
  const sessions = useSessionsStore((s) => s.sessions);
  const accounts = useInstancesStore((s) => s.accounts);
  const userRoles = useInstancesStore((s) => s.userRoles);
  const previousUser = useRef(userId);

  useEffect(() => {
    if (previousUser.current && previousUser.current !== userId) {
      for (const session of useSessionsStore.getState().sessions) if (session.userRDP || session.userSSH || session.userTopology) useSessionsStore.getState().closeSession(session.id);
    }
    previousUser.current = userId;
  }, [userId]);

  useEffect(() => {
    if (!userAWS) return;
    const isLive = (id: string) => userRoles.some(role => role.id === id && role.live !== false);
    if (userAction && !isLive(userAction.roleID)) setUserAction(null);
    const details = useLayoutStore.getState().detailsScope;
    if (details && !isLive(details.roleID)) useLayoutStore.getState().closeDetails();
  }, [userAWS, userRoles, userAction]);

  useEffect(() => {
    if (view === 'kubernetes' && !enableKubernetes) {
      useLayoutStore.getState().setView('session');
      return;
    }
    if (view === 'databases' && !enableDatabases) {
      useLayoutStore.getState().setView('session');
      return;
    }
    if (view === 'kubernetes') setKubernetesOpened(true);
  }, [view, enableKubernetes, enableDatabases]);

  useEffect(() => {
    if (kubernetesOpened || !authReady || (authRequired && !userId)) return;
    if (typeof window.requestIdleCallback === 'function') {
      const id = window.requestIdleCallback(() => setKubernetesOpened(true), { timeout: 1500 });
      return () => window.cancelIdleCallback(id);
    }
    const timer = window.setTimeout(() => setKubernetesOpened(true), 1000);
    return () => window.clearTimeout(timer);
  }, [kubernetesOpened, authReady, authRequired, userId]);

  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      if (event.origin === window.location.origin && event.data?.type === 'operquay:open-command-palette') {
        togglePalette();
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [togglePalette]);

  useEffect(() => {
    if (view !== 'kubernetes') return;
    kubernetesFrame.current?.contentWindow?.postMessage({ type: 'operquay-refresh-kube-clusters' }, window.location.origin);
    if (userAWS) kubernetesFrame.current?.contentWindow?.postMessage({ type: 'operquay-refresh-aws-roles' }, window.location.origin);
  }, [view, userAWS]);


  const flatInstances = useMemo(
    () =>
      accounts
        .flatMap((a) => a.regions)
        .flatMap((r) => r.groups)
        .flatMap((g) => g.instances),
    [accounts],
  );

  const findInstance = useCallback(
    (instanceId: string): Instance | null =>
      flatInstances.find((inst) => inst.instance_id === instanceId) ?? null,
    [flatInstances],
  );

  const getInstanceName = useCallback(
    (instanceId: string): string =>
      findInstance(instanceId)?.name ?? instanceId,
    [findInstance],
  );

  useEffect(() => {
    const handleSSH = (e: Event) => {
      const { instanceId, instanceName } = (e as CustomEvent<{
        instanceId: string;
        instanceName: string;
        accountId: string;
        region: string;
      }>).detail;
      if (openUserSession('ssh', instanceId)) return;
      const sessionId = `${instanceId}-ssh-${Date.now()}`;
      useSessionsStore.getState().openSession({
        id: sessionId,
        type: 'ssh',
        instanceId,
        instanceName,
        env: '',
        status: 'connecting',
      });
    };
    window.addEventListener('ct:open-ssh', handleSSH);
    return () => window.removeEventListener('ct:open-ssh', handleSSH);
  }, []);

  useEffect(() => {
    const handleRDP = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{
        instanceId: string;
        instanceName: string;
        accountId: string;
        region: string;
      }>).detail;
      if (openUserSession('rdp', instanceId)) return;
      const found = findInstance(instanceId);
      if (found) {
        setRdpPendingInstance(found);
        setRdpModalOpen(true);
      }
    };
    window.addEventListener('ct:open-rdp', handleRDP);
    return () => window.removeEventListener('ct:open-rdp', handleRDP);
  }, [findInstance]);

  const handleRDPSubmit = useCallback((creds: RDPCredentials) => {
    if (!rdpPendingInstance) return;

    // Open tab immediately and close modal — don't block the user
    const sessionId = `${rdpPendingInstance.instance_id}-rdp-${Date.now()}`;
    const inst = rdpPendingInstance;
    useSessionsStore.getState().openSession({
      id: sessionId,
      type: 'rdp',
      instanceId: inst.instance_id,
      instanceName: inst.name,
      env: inst.tag2_value ?? '',
      status: 'connecting',
    });
    setRdpStatus((prev) => ({ ...prev, [sessionId]: 'connecting' }));
    setRdpModalOpen(false);
    setRdpPendingInstance(null);

    // Fire API in background
    void (async () => {
      try {
        const width = Math.max(320, Math.min(4096, ((typeof window !== 'undefined' ? window.innerWidth : 1280) - 280))) & ~1;
        const height = Math.max(240, Math.min(4096, (typeof window !== 'undefined' ? window.innerHeight : 720) - 100));
        const result = await api.post<{ token: string; recording_name?: string; forward_id: string }>('/start-guacamole-rdp', {
          instance_id: inst.instance_id,
          instance_name: inst.name,
          aws_profile: inst.aws_profile,
          aws_region: inst.aws_region,
          username: creds.username,
          password: creds.password,
          security: creds.security,
          width,
          height,
        });
        if (result.ok && result.data) {
          if (!useSessionsStore.getState().sessions.some((session) => session.id === sessionId)) {
            await api.post('/stop-guacamole-rdp', { forward_id: result.data.forward_id });
            return;
          }
          setRdpTokens((prev) => ({ ...prev, [sessionId]: result.data!.token }));
          setRdpRecording((prev) => ({ ...prev, [sessionId]: result.data!.recording_name ?? '' }));
          setRdpStatus((prev) => { const next = { ...prev }; delete next[sessionId]; return next; });
        } else {
          setRdpStatus((prev) => ({ ...prev, [sessionId]: 'error' }));
          useSessionsStore.getState().updateStatus(sessionId, 'error');
          useToastStore.getState().push({ variant: 'danger', title: 'RDP Connection Failed', description: 'Could not start RDP session' });
        }
      } catch {
        setRdpStatus((prev) => ({ ...prev, [sessionId]: 'error' }));
        useSessionsStore.getState().updateStatus(sessionId, 'error');
        useToastStore.getState().push({ variant: 'danger', title: 'RDP Connection Failed', description: 'Network error' });
      }

    })();
  }, [rdpPendingInstance]);

  useEffect(() => {
    const handleDetails = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{ instanceId: string }>).detail;
      useLayoutStore.getState().showDetails(instanceId);
    };
    window.addEventListener('ct:show-details', handleDetails);
    return () => window.removeEventListener('ct:show-details', handleDetails);
  }, []);

  useEffect(() => {
    const handleCloseAll = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{ instanceId: string }>).detail;
      const { sessions: currentSessions, closeSession } = useSessionsStore.getState();
      currentSessions
        .filter((s) => s.instanceId === instanceId)
        .forEach((s) => closeSession(s.id));
    };
    window.addEventListener('ct:close-all', handleCloseAll);
    return () => window.removeEventListener('ct:close-all', handleCloseAll);
  }, []);

  useEffect(() => {
    const userActionFor = (kind: UserAction['kind'], instanceId: string): boolean => {
      if (!isUserAWSMode()) return false;
      const scoped = userScopedInstance(instanceId);
      if (scoped && !requireLiveAWS(scoped.roleID)) return true;
      const perm = kind === 'forward' ? 'session:forward' : kind === 'clone' ? 'instances:clone' : 'session:transfer';
      const me = useAuthStore.getState().me;
      if (scoped && (!me || hasPermission(me, perm))) setUserAction({ kind, ...scoped });
      return true;
    };
    const handleUpload = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{ instanceId: string }>).detail;
      if (userActionFor('upload', instanceId)) return;
      setUploadModal({ open: true, instanceId, instanceName: getInstanceName(instanceId) });
    };
    const handleDownload = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{ instanceId: string }>).detail;
      if (userActionFor('download', instanceId)) return;
      setDownloadModal({ open: true, instanceId, instanceName: getInstanceName(instanceId) });
    };
    const handleBrowseFiles = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{ instanceId: string }>).detail;
      if (isUserAWSMode()) return;
      const inst = findInstance(instanceId);
      setFileBrowserModal({
        open: true,
        instanceId,
        instanceName: inst?.name ?? instanceId,
        awsProfile: inst?.aws_profile,
        awsRegion: inst?.aws_region,
        platform: inst?.platform,
      });
    };
    const handlePortForward = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{ instanceId: string }>).detail;
      if (userActionFor('forward', instanceId)) return;
      setPortForwardModal({ open: true, instanceId, instanceName: getInstanceName(instanceId) });
    };
    const handleExpressUpload = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{ instanceId: string }>).detail;
      if (isUserAWSMode()) return;
      setExpressUploadModal({ open: true, instanceId, instanceName: getInstanceName(instanceId) });
    };
    const handleExpressDownload = (e: Event) => {
      const { instanceId } = (e as CustomEvent<{ instanceId: string }>).detail;
      if (isUserAWSMode()) return;
      setExpressDownloadModal({ open: true, instanceId, instanceName: getInstanceName(instanceId) });
    };
    const handleTopology = (e: Event) => {
      const { instanceId, instanceName } = (e as CustomEvent<{ instanceId: string; instanceName: string }>).detail;
      if (openUserSession('topology', instanceId)) return;
      const topoId = `topo-${instanceId}`;
      const { sessions, setActive } = useSessionsStore.getState();
      const existing = sessions.find((s) => s.id === topoId);
      if (existing) {
        setActive(topoId);
        return;
      }
      useSessionsStore.getState().openSession({
        id: topoId,
        type: 'topology',
        instanceId,
        instanceName: instanceName || getInstanceName(instanceId),
        env: '',
        status: 'connected',
      });
    };
    const handleClone = (e: Event) => {
      const { instanceId, instanceName } = (e as CustomEvent<{ instanceId: string; instanceName: string }>).detail;
      if (userActionFor('clone', instanceId)) return;
      const name = instanceName || getInstanceName(instanceId);
      setCloneModal({ open: true, instanceId, instanceName: name });
    };

    window.addEventListener('ct:upload', handleUpload);
    window.addEventListener('ct:download', handleDownload);
    window.addEventListener('ct:browse-files', handleBrowseFiles);
    window.addEventListener('ct:port-forward', handlePortForward);
    window.addEventListener('ct:express-upload', handleExpressUpload);
    window.addEventListener('ct:express-download', handleExpressDownload);
    window.addEventListener('ct:topology', handleTopology);
    window.addEventListener('ct:clone', handleClone);

    return () => {
      window.removeEventListener('ct:upload', handleUpload);
      window.removeEventListener('ct:download', handleDownload);
      window.removeEventListener('ct:browse-files', handleBrowseFiles);
      window.removeEventListener('ct:port-forward', handlePortForward);
      window.removeEventListener('ct:express-upload', handleExpressUpload);
      window.removeEventListener('ct:express-download', handleExpressDownload);
      window.removeEventListener('ct:topology', handleTopology);
      window.removeEventListener('ct:clone', handleClone);
    };
  }, [getInstanceName, findInstance]);

  const handleTogglePalette = useCallback(
    (e: KeyboardEvent) => {
      e.preventDefault();
      togglePalette();
    },
    [togglePalette],
  );

  const handleSettings = useCallback((e: KeyboardEvent) => {
    e.preventDefault();
    window.dispatchEvent(new CustomEvent('ct:open-settings'));
  }, []);

  const handleRecordings = useCallback((e: KeyboardEvent) => {
    if (!hasPermission(useAuthStore.getState().me, 'recordings:read')) return;
    e.preventDefault();
    useLayoutStore.getState().openSettings('recordings');
  }, []);

  const handleToggleList = useCallback((e: KeyboardEvent) => {
    if (useLayoutStore.getState().view !== 'session') return;
    e.preventDefault();
    useLayoutStore.getState().toggleSidebar();
  }, []);

  const handleCloseTab = useCallback((e: KeyboardEvent) => {
    e.preventDefault();
    if (activeId) useSessionsStore.getState().closeSession(activeId);
  }, [activeId]);

  const handleSwitchTab = useCallback((e: KeyboardEvent) => {
    e.preventDefault();
    const idx = parseInt(e.key) - 1;
    const tabIds = useSessionsStore.getState().sessions.map((s) => s.id);
    if (idx >= 0 && idx < tabIds.length) {
      const targetId = tabIds[idx];
      if (targetId) useSessionsStore.getState().setActive(targetId);
    }
  }, []);

  useEffect(() => {
    const unsubs = [
      shortcuts.register({ keys: 'cmd+k', handler: handleTogglePalette, description: 'Open Command Palette', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+k', handler: handleTogglePalette, description: 'Open Command Palette', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+,', handler: handleSettings, description: 'Open Settings', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+shift+r', handler: handleRecordings, description: 'Open Recordings', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+shift+r', handler: handleRecordings, description: 'Open Recordings', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+b', handler: handleToggleList, description: 'Show or hide the instance list', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+b', handler: handleToggleList, description: 'Show or hide the instance list', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+w', handler: handleCloseTab, description: 'Close active tab', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+w', handler: handleCloseTab, description: 'Close active tab', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+1', handler: handleSwitchTab, description: 'Switch to tab 1', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+2', handler: handleSwitchTab, description: 'Switch to tab 2', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+3', handler: handleSwitchTab, description: 'Switch to tab 3', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+4', handler: handleSwitchTab, description: 'Switch to tab 4', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+5', handler: handleSwitchTab, description: 'Switch to tab 5', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+6', handler: handleSwitchTab, description: 'Switch to tab 6', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+7', handler: handleSwitchTab, description: 'Switch to tab 7', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+8', handler: handleSwitchTab, description: 'Switch to tab 8', scope: 'global' }),
      shortcuts.register({ keys: 'cmd+9', handler: handleSwitchTab, description: 'Switch to tab 9', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+1', handler: handleSwitchTab, description: 'Switch to tab 1', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+2', handler: handleSwitchTab, description: 'Switch to tab 2', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+3', handler: handleSwitchTab, description: 'Switch to tab 3', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+4', handler: handleSwitchTab, description: 'Switch to tab 4', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+5', handler: handleSwitchTab, description: 'Switch to tab 5', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+6', handler: handleSwitchTab, description: 'Switch to tab 6', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+7', handler: handleSwitchTab, description: 'Switch to tab 7', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+8', handler: handleSwitchTab, description: 'Switch to tab 8', scope: 'global' }),
      shortcuts.register({ keys: 'ctrl+9', handler: handleSwitchTab, description: 'Switch to tab 9', scope: 'global' }),
    ];
    return () => unsubs.forEach((u) => u());
  }, [handleTogglePalette, handleSettings, handleRecordings, handleToggleList, handleCloseTab, handleSwitchTab]);

  const startCloneWithProgress = useCallback(async (instanceId: string, cloneName: string) => {
    const toastStore = useToastStore.getState();
    let poll: ReturnType<typeof setInterval> | null = null;
    const toastId = toastStore.push({
      variant: 'progress',
      title: 'Clone started',
      description: `Creating AMI for ${cloneName}…`,
      duration: null,
      progress: 0,
      onDismiss: () => { if (poll) clearInterval(poll); },
    });

    const r = await api.post<{ id: string }>('/clone/start', { instance_id: instanceId, clone_name: cloneName });
    if (!r.ok) {
      toastStore.update(toastId, { variant: 'danger', title: 'Clone Failed', description: 'Failed to start clone', duration: 4000 });
      return;
    }

    const cloneId = r.data!.id;
    const PHASE_LABELS: Record<string, string> = {
      creating_ami: 'Creating AMI snapshot…',
      ami_ready: 'AMI ready — launching instance…',
      launching: 'Launching instance…',
      complete: 'Clone complete',
      error: 'Clone failed',
    };

    poll = setInterval(async () => {
      const s = await api.get<{ phase: string; progress: number; message: string; new_instance_id?: string }>(`/clone/status/${cloneId}`);
      if (!s.ok) return;
      const { phase, progress, message, new_instance_id } = s.data!;
      const label = PHASE_LABELS[phase] ?? message;

      if (phase === 'complete') {
        clearInterval(poll!); poll = null;
        toastStore.update(toastId, { variant: 'success', title: `Clone complete: ${cloneName}`, description: new_instance_id ? `Instance ID: ${new_instance_id}` : label, progress: 100, duration: 6000 });
      } else if (phase === 'error') {
        clearInterval(poll!); poll = null;
        toastStore.update(toastId, { variant: 'danger', title: 'Clone failed', description: message, duration: 6000 });
      } else {
        toastStore.update(toastId, { description: label, progress });
      }
    }, 3000);
  }, []);

  const mainContent = (() => {
    const hasAnySessions = sessions.length > 0;
    return (
      <>
        {sessions.map((session) => {
          const isActive = view === 'session' && session.id === activeId;

          if (session.userTopology && userAWS) {
            return <div key={session.id} role="region" aria-label={`Topology for ${session.instanceId}`} style={{ position: 'absolute', inset: 0, display: isActive ? 'block' : 'none' }}>
              <TopologyRoute instanceId={session.instanceId} userScope={{ ...session.userTopology, cacheKey: session.id }} />
            </div>;
          }

          if (session.userRDP && userAWS) {
            return <div key={session.id} style={{ position: 'absolute', inset: 0, display: isActive ? 'block' : 'none' }}>
              <UserAWSRDP id={session.id} roleID={session.userRDP.roleID} instanceID={session.instanceId} instanceName={session.instanceName} region={session.userRDP.region} env={session.env} active={isActive} onClose={() => useSessionsStore.getState().closeSession(session.id)} />
            </div>;
          }

          if (session.userSSH && userAWS) {
            const inst = { instance_id: session.instanceId, name: session.instanceName, aws_profile: `user:${session.userSSH.roleID}`, aws_region: session.userSSH.region, tag2_value: session.env };
            return <div key={session.id} role="region" aria-label={`Terminal for ${session.instanceId}`} style={{ position: 'absolute', inset: 0, display: isActive ? 'block' : 'none' }}>
              <TerminalSession instance={inst} sessionId={session.id} userScoped />
            </div>;
          }

          const inst = findInstance(session.instanceId);
          if (!inst) {
            return (
              <div key={session.id} style={{ position: 'absolute', inset: 0, display: isActive ? 'flex' : 'none', alignItems: 'center', justifyContent: 'center' }}>
                <span className="text-text-dim text-sm">Loading instance data…</span>
              </div>
            );
          }
          return (
            <div
              key={session.id}
              style={{
                position: 'absolute',
                inset: 0,
                display: isActive ? 'block' : 'none',
              }}
            >
              <TerminalSession
                instance={inst}
                sessionId={session.id}
                sessionType={session.type}
                rdpToken={rdpTokens[session.id]}
                rdpConnectStatus={rdpStatus[session.id]}
                rdpRecordingName={rdpRecording[session.id]}
              />
            </div>
          );
        })}
        {view === 'session' && (!hasAnySessions || !activeId) && (userAWS && accounts.length === 0
          ? <div className="absolute inset-0 flex items-center justify-center p-8">
              <div className="max-w-sm text-center space-y-3">
                <h2 className="text-[16px] font-semibold text-text-pri">{userRoles.some((r) => r.live !== false) ? 'Open an instance' : 'Connect a cloud account'}</h2>
                <p className="text-[14px] text-text-mut">{userRoles.some((r) => r.live !== false) ? 'Pick an instance from the list to start a session.' : 'Sign in to an AWS account to list its instances. Use the account picker next to the instance filter to add or manage accounts later.'}</p>
                <Button onClick={connectCloud}>{userRoles.some((r) => r.live !== false) ? 'Connect another account' : 'Connect a cloud account'}</Button>
              </div>
            </div>
          : <div style={{ position: 'absolute', inset: 0, overflow: 'auto' }}><FleetDashboard /></div>)}
        {(kubernetesOpened || view === 'kubernetes') && enableKubernetes && (
          <KubernetesWorkspace
            visible={view === 'kubernetes'}
            iframeRef={kubernetesFrame}
            userId={userId}
            userAWS={userAWS}
            onFrameKeyDown={(event) => {
              if ((event.ctrlKey || event.metaKey) && !event.shiftKey && !event.altKey && event.key.toLowerCase() === 'k') {
                shortcuts.handle(event);
                if (event.defaultPrevented) event.stopPropagation();
              }
            }}
          />
        )}
        {view === 'databases' && enableDatabases && (
          <div className="absolute inset-0 overflow-hidden">
            <DatabasesWorkspace defaultShowExplorer={false} />
          </div>
        )}
        {view === 'settings' && <DeskPage />}
      </>
    );
  })();

  return (
    <QueryClientProvider client={queryClient}>
      <>
        <AppShell>
          {mainContent}
        </AppShell>

        <CmdKPalette />

        {rdpPendingInstance && (
          <RDPCredentialsModal
            open={rdpModalOpen}
            instance={rdpPendingInstance}
            onSubmit={handleRDPSubmit}
            onCancel={() => { setRdpModalOpen(false); setRdpPendingInstance(null); }}
          />
        )}

        <PortForwardModal
          open={portForwardModal.open}
          onOpenChange={(v) => setPortForwardModal((p) => ({ ...p, open: v }))}
          defaultInstanceId={portForwardModal.instanceId}
          defaultInstanceName={portForwardModal.instanceName}
        />

        <UploadModal
          open={uploadModal.open}
          onOpenChange={(v) => setUploadModal((p) => ({ ...p, open: v }))}
          instanceId={uploadModal.instanceId}
          instanceName={uploadModal.instanceName}
        />

        <DownloadModal
          open={downloadModal.open}
          onOpenChange={(v) => setDownloadModal((p) => ({ ...p, open: v }))}
          instanceId={downloadModal.instanceId}
          instanceName={downloadModal.instanceName}
          initialPath={downloadModal.initialPath}
        />

        <FileBrowserModal
          open={fileBrowserModal.open}
          onOpenChange={(v) => setFileBrowserModal((p) => ({ ...p, open: v }))}
          instanceId={fileBrowserModal.instanceId}
          instanceName={fileBrowserModal.instanceName}
          awsProfile={fileBrowserModal.awsProfile}
          awsRegion={fileBrowserModal.awsRegion}
          platform={fileBrowserModal.platform}
          onDownload={(path) => {
            setFileBrowserModal((p) => ({ ...p, open: false }));
            setDownloadModal({ open: true, instanceId: fileBrowserModal.instanceId, instanceName: fileBrowserModal.instanceName, initialPath: path });
          }}
          onUpload={(path) => {
            setFileBrowserModal((p) => ({ ...p, open: false }));
            setUploadModal({ open: true, instanceId: fileBrowserModal.instanceId, instanceName: fileBrowserModal.instanceName, initialPath: path });
          }}
          onExpressDownload={(path) => {
            setFileBrowserModal((p) => ({ ...p, open: false }));
            setExpressDownloadModal({ open: true, instanceId: fileBrowserModal.instanceId, instanceName: fileBrowserModal.instanceName, initialPath: path });
          }}
        />

        {userAction && <Dialog open onOpenChange={(open) => { if (!open) setUserAction(null); }} title={`${USER_ACTION_TITLE[userAction.kind]} · ${userAction.instance.name || userAction.instance.instance_id}`} size="lg">
          {(userAction.kind === 'upload' || userAction.kind === 'download') && <UserAWSTransfer key={`${userAction.kind}:${userAction.instance.instance_id}`} mode={userAction.kind} roleID={userAction.roleID} instanceID={userAction.instance.instance_id} region={userAction.instance.aws_region} platform={userAction.instance.platform ?? ''} onClose={() => setUserAction(null)} />}
          {userAction.kind === 'forward' && <UserAWSForward open roleID={userAction.roleID} instanceID={userAction.instance.instance_id} instanceName={userAction.instance.name || userAction.instance.instance_id} region={userAction.instance.aws_region} />}
          {userAction.kind === 'clone' && <UserAWSClone open roleID={userAction.roleID} instanceID={userAction.instance.instance_id} instanceName={userAction.instance.name || userAction.instance.instance_id} region={userAction.instance.aws_region} />}
        </Dialog>}
        <CloneModal
          open={cloneModal.open}
          onOpenChange={(v) => setCloneModal((p) => ({ ...p, open: v }))}
          instanceId={cloneModal.instanceId}
          instanceName={cloneModal.instanceName}
          onConfirm={(cloneName) => {
            void startCloneWithProgress(cloneModal.instanceId, cloneName);
          }}
        />

        <UploadModal
          open={expressUploadModal.open}
          onOpenChange={(v) => setExpressUploadModal((p) => ({ ...p, open: v }))}
          instanceId={expressUploadModal.instanceId}
          instanceName={expressUploadModal.instanceName}
          express
        />

        <DownloadModal
          open={expressDownloadModal.open}
          onOpenChange={(v) => setExpressDownloadModal((p) => ({ ...p, open: v }))}
          instanceId={expressDownloadModal.instanceId}
          instanceName={expressDownloadModal.instanceName}
          initialPath={expressDownloadModal.initialPath}
          express
        />

      </>
    </QueryClientProvider>
  );
}
