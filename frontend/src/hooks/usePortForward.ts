import { useCallback } from 'react';
import { useActivityStore } from '@/stores/activity';
import { apiGet, apiPost } from '@/lib/api';

interface StartTunnelRequest {
  instance_id: string;
  instance_name: string;
  port_number: number;
}

interface TunnelResponse {
  forward_id: string;
  port: number;
}

interface ActiveTunnel {
  forward_id: string;
  instance_id: string;
  instance_name: string;
  local_port: number;
  remote_port: number;
  protocol: string;
  started_at: string;
  web_browsable?: boolean;
}

export function usePortForward() {
  const add = useActivityStore((s) => s.add);
  const dismiss = useActivityStore((s) => s.dismiss);
  const finish = useActivityStore((s) => s.finish);

  const startTunnel = useCallback(
    async (
      instanceId: string,
      instanceName: string,
      localPort: number,
      remotePort: number,
      protocol = 'TCP',
    ): Promise<string | null> => {
      const result = await apiPost<TunnelResponse, StartTunnelRequest>(
        '/start-port-forward',
        { instance_id: instanceId, instance_name: instanceName, port_number: remotePort },
      );

      if (!result.ok) return null;

      const isWebPort = [80, 443, 3000, 5000, 8000, 8080, 8443].includes(localPort);
      const id = add({
        kind: 'port-forward',
        forwardId: result.value.forward_id,
        instanceId,
        instanceName,
        localPort: result.value.port,
        remotePort,
        protocol,
        elapsedSec: 0,
        webBrowsable: isWebPort,
      });
      return id;
    },
    [add],
  );

  const stopTunnel = useCallback(
    async (activityId: string, tunnelId: string): Promise<void> => {
      const result = await apiPost('/stop-port-forward', { forward_id: tunnelId });
      if (result.ok) {
        finish(activityId, 'success');
      }
    },
    [finish],
  );

  const fetchActiveTunnels = useCallback(async (): Promise<void> => {
    const result = await apiGet<ActiveTunnel[]>('/active-tunnels');
    if (!result.ok) return;

    for (const tunnel of result.value) {
      const isWebPort = [80, 443, 3000, 5000, 8000, 8080, 8443].includes(tunnel.local_port);
      add({
        kind: 'port-forward',
        forwardId: tunnel.forward_id,
        instanceId: tunnel.instance_id,
        instanceName: tunnel.instance_name,
        localPort: tunnel.local_port,
        remotePort: tunnel.remote_port,
        protocol: tunnel.protocol,
        elapsedSec: Math.floor((Date.now() - Date.parse(tunnel.started_at)) / 1000),
        webBrowsable: tunnel.web_browsable || isWebPort,
      });
    }
  }, [add]);

  const removeTunnel = useCallback(
    (activityId: string) => {
      dismiss(activityId);
    },
    [dismiss],
  );

  return { startTunnel, stopTunnel, fetchActiveTunnels, removeTunnel };
}
