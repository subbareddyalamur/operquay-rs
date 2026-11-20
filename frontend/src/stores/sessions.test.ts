// @vitest-environment-options {"url":"https://desk.example/"}
import { afterEach, expect, it, vi } from 'vitest';

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules(); });

it.each(['fleet-map', 'diagram', 'cost'])('ignores restored %s tabs without losing other sessions or saved diagrams', async type => {
  const sessionData = new Map<string, string>();
  const localData = new Map<string, string>();
  const storage = (data: Map<string, string>) => ({ getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => data.set(key, value), removeItem: (key: string) => data.delete(key) });
  vi.stubGlobal('sessionStorage', storage(sessionData));
  vi.stubGlobal('localStorage', storage(localData));
  const savedDiagram = '{"nodes":[{"id":"saved"}]}';
  localStorage.setItem('ct-diagram-board', savedDiagram);
  sessionStorage.setItem('ct-sessions', JSON.stringify({ state: {
    sessions: [
      { id: 'ssh-1', type: 'ssh', instanceId: 'i-1', instanceName: 'Server', status: 'connected', createdAt: 1 },
      { id: 'removed', type, instanceId: '', instanceName: 'Old tool', status: 'connected', createdAt: 2 },
    ],
    activeId: 'removed',
  }, version: 0 }));
  const { useSessionsStore } = await import('./sessions');
  await useSessionsStore.persist.rehydrate();
  expect(useSessionsStore.getState().sessions.map(session => session.id)).toEqual(['ssh-1']);
  expect(useSessionsStore.getState().activeId).toBe('ssh-1');
  expect(localStorage.getItem('ct-diagram-board')).toBe(savedDiagram);
  sessionStorage.setItem('ct-sessions', JSON.stringify({ state: { sessions: [
    { id: 'ssh-1', type: 'ssh', instanceId: 'i-1', instanceName: 'Server', status: 'connected', createdAt: 1 },
    { id: 'removed', type, instanceId: '', instanceName: 'Old tool', status: 'connected', createdAt: 2 },
  ], activeId: 'ssh-1' }, version: 0 }));
  await useSessionsStore.persist.rehydrate();
  expect(useSessionsStore.getState().activeId).toBe('ssh-1');
  sessionStorage.setItem('ct-sessions', JSON.stringify({ state: { sessions: [
    { id: 'removed', type, instanceId: '', instanceName: 'Old tool', status: 'connected', createdAt: 2 },
  ], activeId: 'removed' }, version: 0 }));
  await useSessionsStore.persist.rehydrate();
  expect(useSessionsStore.getState().sessions).toEqual([]);
  expect(useSessionsStore.getState().activeId).toBeNull();
});

it('does not persist user-scoped session metadata or leave it active after refresh', async () => {
  const data = new Map<string, string>();
  const storage = { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => data.set(key, value), removeItem: (key: string) => data.delete(key) };
  vi.stubGlobal('sessionStorage', storage);
  vi.stubGlobal('localStorage', storage);
  const { useSessionsStore } = await import('./sessions');
  useSessionsStore.getState().openSession({ id: 'private', type: 'rdp', instanceId: 'i-private', instanceName: 'Private server', status: 'connecting', userRDP: { roleID: 'private-role', region: 'us-east-1' } });
  useSessionsStore.getState().openSession({ id: 'private-ssh', type: 'ssh', instanceId: 'i-private-ssh', instanceName: 'Private terminal', status: 'connecting', userSSH: { roleID: 'private-role', region: 'us-east-1' } });
  useSessionsStore.getState().openSession({ id: 'private-topology', type: 'topology', instanceId: 'i-private-topology', instanceName: 'Private topology', status: 'connecting', userTopology: { roleID: 'private-role', region: 'us-east-1' } });
  const stored = sessionStorage.getItem('ct-sessions') || '';
  expect(stored).not.toContain('i-private');
  expect(stored).not.toContain('private-role');
  expect(JSON.parse(stored).state.activeId).toBeNull();
  sessionStorage.setItem('ct-sessions', JSON.stringify({ state:{ sessions:[{ id:'stale', type:'topology', instanceId:'i-private', instanceName:'Private', status:'connected', createdAt:1, userTopology:{ roleID:'private-role', region:'us-east-1' } }], activeId:'stale' }, version:0 }));
  await useSessionsStore.persist.rehydrate();
  expect(useSessionsStore.getState().sessions).toEqual([]);
  expect(useSessionsStore.getState().activeId).toBeNull();
});

it('restores a user SSH tab from local storage so a refresh can resume the shell', async () => {
  const sessionData = new Map<string, string>();
  const localData = new Map<string, string>();
  const storage = (data: Map<string, string>) => ({ getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => data.set(key, value), removeItem: (key: string) => data.delete(key) });
  vi.stubGlobal('sessionStorage', storage(sessionData));
  vi.stubGlobal('localStorage', storage(localData));
  localStorage.setItem('ct-user-ssh-tabs', JSON.stringify({ sessions: [{ id: 'tab-1', type: 'ssh', instanceId: 'i-0123456789abcdef0', instanceName: 'Kept', status: 'connected', createdAt: 1, userSSH: { roleID: '11111111-1111-4111-8111-111111111111', region: 'us-east-1' } }], activeId: 'tab-1' }));
  const { useSessionsStore } = await import('./sessions');
  await useSessionsStore.persist.rehydrate();
  expect(useSessionsStore.getState().sessions.map(session => session.id)).toEqual(['tab-1']);
  expect(useSessionsStore.getState().sessions[0]?.status).toBe('connecting');
  expect(sessionStorage.getItem('ct-sessions') ?? '').not.toContain('11111111-1111-4111-8111-111111111111');
});

it('restores a user RDP tab so a refresh shows the login form again', async () => {
  const sessionData = new Map<string, string>();
  const localData = new Map<string, string>();
  const storage = (data: Map<string, string>) => ({ getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => data.set(key, value), removeItem: (key: string) => data.delete(key) });
  vi.stubGlobal('sessionStorage', storage(sessionData));
  vi.stubGlobal('localStorage', storage(localData));
  localStorage.setItem('ct-user-rdp-tabs', JSON.stringify({ sessions: [{ id: 'rdp-1', type: 'rdp', instanceId: 'i-0123456789abcdef0', instanceName: 'Windows', env: 'DEV', status: 'connected', createdAt: 1, userRDP: { roleID: '22222222-2222-4222-8222-222222222222', region: 'eu-central-1' }, password: 'secret' }], activeId: 'rdp-1' }));
  const { useSessionsStore } = await import('./sessions');
  await useSessionsStore.persist.rehydrate();
  const restored = useSessionsStore.getState().sessions[0];
  expect(restored?.id).toBe('rdp-1');
  expect(restored?.status).toBe('disconnected');
  expect(restored?.env).toBe('DEV');
  expect(JSON.stringify(restored)).not.toContain('secret');
  expect(sessionStorage.getItem('ct-sessions') ?? '').not.toContain('22222222-2222-4222-8222-222222222222');
});

it.each(['DEV\r', 'DEV\n', 'DEV\0'])('does not restore a tab with control characters in its environment', async env => {
  const sessionData = new Map<string, string>();
  const localData = new Map<string, string>();
  const storage = (data: Map<string, string>) => ({ getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => data.set(key, value), removeItem: (key: string) => data.delete(key) });
  vi.stubGlobal('sessionStorage', storage(sessionData));
  vi.stubGlobal('localStorage', storage(localData));
  localStorage.setItem('ct-user-rdp-tabs', JSON.stringify({ sessions: [{ id: 'rdp-1', type: 'rdp', instanceId: 'i-0123456789abcdef0', instanceName: 'Windows', env, status: 'connected', createdAt: 1, userRDP: { roleID: '22222222-2222-4222-8222-222222222222', region: 'eu-central-1' } }], activeId: 'rdp-1' }));
  const { useSessionsStore } = await import('./sessions');
  expect(useSessionsStore.getState().sessions).toEqual([]);
});
