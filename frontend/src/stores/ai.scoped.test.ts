import { afterEach, expect, it, vi } from 'vitest';
import { useAIStore } from './ai';

const a = { key:'tenant/user/login/role-a', sessionId:'terminal-a', bindingId:'role-a', region:'us-east-1', instanceId:'i-a', tenantId:'tenant', userId:'user', expiresAt:9999999999 };
const b = { key:'tenant/user/login/role-b', sessionId:'terminal-b', bindingId:'role-b', region:'us-west-2', instanceId:'i-b', tenantId:'tenant', userId:'user', expiresAt:9999999999 };

afterEach(() => { useAIStore.getState().clear(); useAIStore.getState().setScope(null); vi.restoreAllMocks(); });

it('sends scoped chat only to the selected terminal and role', async () => {
  const fetch = vi.spyOn(window, 'fetch').mockResolvedValue(new Response('data: {"type":"text","text":"answer"}\n\ndata: {"type":"done"}\n\n', { status:200 }));
  useAIStore.getState().setScope(a.key);
  await useAIStore.getState().sendMessage('question', a.instanceId, a);
  expect(fetch).toHaveBeenCalledWith('/api/aws/ai/chat', expect.objectContaining({ method:'POST', body:expect.any(String) }));
  const body = JSON.parse(fetch.mock.calls[0]![1]!.body as string) as Record<string, unknown>;
  expect(body).toMatchObject({ session_id:'terminal-a', binding_id:'role-a', region:'us-east-1', instance_id:'i-a' });
  expect(useAIStore.getState().messages.at(-1)?.content).toBe('answer');
});

it('aborts and clears a previous role conversation before another role can use it', async () => {
  let complete!: (response:Response) => void;
  const first = new Promise<Response>(resolve => { complete = resolve; });
  const fetch = vi.spyOn(window, 'fetch').mockReturnValueOnce(first).mockResolvedValueOnce(new Response('data: {"type":"text","text":"new answer"}\n\n', { status:200 }));
  useAIStore.getState().setScope(a.key);
  const previous = useAIStore.getState().sendMessage('private old question', a.instanceId, a);
  const signal = fetch.mock.calls[0]![1]!.signal as AbortSignal;
  useAIStore.getState().setScope(b.key);
  expect(signal.aborted).toBe(true);
  expect(useAIStore.getState().messages).toHaveLength(0);
  await useAIStore.getState().sendMessage('new question', b.instanceId, b);
  complete(new Response('data: {"type":"text","text":"late old answer"}\n\n', { status:200 }));
  await previous;
  expect(useAIStore.getState().messages.map(message => message.content)).toEqual(['new question', 'new answer']);
});
