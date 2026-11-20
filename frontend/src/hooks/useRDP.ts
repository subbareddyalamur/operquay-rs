import { useState, useCallback } from 'react';
import { nanoid } from 'nanoid';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { useSessionsStore } from '@/stores/sessions';
import { useToastStore } from '@/stores/toast';
import type { Instance } from '@/stores/instances';

export interface RDPSessionParams {
  token: string;
  forwardId: string;
  wsUrl: string;
  recording: boolean;
}

export interface RDPStartRequest {
  instance_id: string;
  instance_name: string;
  aws_profile: string;
  aws_region: string;
  username: string;
  password: string;
  security: string;
}

export interface RDPStartResponse {
  token: string;
  forward_id: string;
  url: string;
  instance_id: string;
  instance_name: string;
  ws_url: string;
  recording: boolean;
}

export interface RDPStopRequest {
  forward_id: string;
}

export interface RDPSessionState {
  sessionId: string;
  params: RDPSessionParams;
}

export interface UseRDPReturn {
  pendingInstance: Instance | null;
  credentialsOpen: boolean;
  activeRDPSessions: Record<string, RDPSessionState>;
  startRDPSession: (instance: Instance) => void;
  submitCredentials: (instance: Instance, username: string, password: string) => Promise<void>;
  cancelCredentials: () => void;
  stopRDPSession: (sessionId: string, instanceId: string) => Promise<void>;
}

export function useRDP(): UseRDPReturn {
  const { openSession, closeSession, updateStatus } = useSessionsStore();
  const push = useToastStore((s) => s.push);

  const [pendingInstance, setPendingInstance] = useState<Instance | null>(null);
  const [credentialsOpen, setCredentialsOpen] = useState(false);
  const [activeRDPSessions, setActiveRDPSessions] = useState<Record<string, RDPSessionState>>({});

  const startRDPSession = useCallback((instance: Instance) => {
    setPendingInstance(instance);
    setCredentialsOpen(true);
  }, []);

  const cancelCredentials = useCallback(() => {
    setPendingInstance(null);
    setCredentialsOpen(false);
  }, []);

  const submitCredentials = useCallback(
    async (instance: Instance, username: string, password: string) => {
      if (!canSendCredentials('/start-guacamole-rdp')) {
        push({ variant: 'danger', title: 'RDP connection failed', description: 'HTTPS is required for RDP credentials.' });
        return;
      }
      setCredentialsOpen(false);
      setPendingInstance(null);

      const sessionId = `rdp-${instance.instance_id}-${nanoid(6)}`;
      openSession({
        id: sessionId,
        type: 'rdp',
        instanceId: instance.instance_id,
        instanceName: instance.name,
        env: instance.tag2_value,
        status: 'connecting',
      });

      const body: RDPStartRequest = {
        instance_id: instance.instance_id,
        instance_name: instance.name,
        aws_profile: instance.aws_profile,
        aws_region: instance.aws_region,
        username,
        password,
        security: 'nla',
      };

      const res = await api.post<RDPStartResponse>('/start-guacamole-rdp', body);

      if (!res.ok) {
        updateStatus(sessionId, 'error');
        push({
          variant: 'danger',
          title: 'RDP connection failed',
          description: res.error.message,
        });
        closeSession(sessionId);
        return;
      }

      if (!useSessionsStore.getState().sessions.some((s) => s.id === sessionId)) {
        await api.post('/stop-guacamole-rdp', { forward_id: res.data.forward_id });
        return;
      }

      setActiveRDPSessions((prev) => ({
        ...prev,
        [sessionId]: {
          sessionId,
          params: {
            token: res.data.token,
            forwardId: res.data.forward_id,
            wsUrl: res.data.ws_url,
            recording: res.data.recording,
          },
        },
      }));
    },
    [openSession, closeSession, updateStatus, push],
  );

  const stopRDPSession = useCallback(
    async (sessionId: string, _instanceId: string) => {
      const forwardId = activeRDPSessions[sessionId]?.params.forwardId;
      closeSession(sessionId);
      setActiveRDPSessions((prev) => {
        const next = { ...prev };
        delete next[sessionId];
        return next;
      });

      if (!forwardId) return;
      const res = await api.post<unknown>('/stop-guacamole-rdp', {
        forward_id: forwardId,
      } satisfies RDPStopRequest);

      if (!res.ok && res.error.status !== 404) {
        push({
          variant: 'warn',
          title: 'Could not cleanly stop RDP session',
          description: res.error.message,
        });
      }
    },
    [activeRDPSessions, closeSession, push],
  );

  return {
    pendingInstance,
    credentialsOpen,
    activeRDPSessions,
    startRDPSession,
    submitCredentials,
    cancelCredentials,
    stopRDPSession,
  };
}
