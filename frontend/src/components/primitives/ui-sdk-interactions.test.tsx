import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup, act } from '@testing-library/react';
import { ConfirmDialog } from './ConfirmDialog';
import { Dialog } from './Dialog';
import { Menu } from './Menu';
import { Tooltip } from './Tooltip';
import { EmptyState } from './EmptyState';
import { Skeleton, SkeletonRow, SkeletonCard } from './Skeleton';
import { InstanceContextMenu, openContextMenu } from '@/components/sidebar/InstanceContextMenu';
import { CmdKPalette } from '@/components/palette/CmdKPalette';
import { AIChatPanel } from '@/components/ai/AIChatPanel';
import { useInstancesStore } from '@/stores/instances';
import { usePaletteStore } from '@/stores/palette';
import { useAIStore } from '@/stores/ai';
import { useSessionsStore } from '@/stores/sessions';
import { useAuthStore, type AuthConfig } from '@/stores/auth';
import type { EC2Instance } from '@/lib/types';

vi.hoisted(() => {
  const values = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  });
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
});

afterEach(() => {
  cleanup();
  usePaletteStore.setState({ open: false, query: '' });
  useInstancesStore.setState({ accounts: [], favorites: [] });
  useAIStore.getState().clear();
  useAIStore.getState().setScope(null);
  useAIStore.getState().setOpen(false);
  useSessionsStore.setState({ sessions: [], activeId: null });
  useAuthStore.setState({ config: null, me: null });
  vi.restoreAllMocks();
});

describe('@ui-sdk primitives', () => {
  it('renders ConfirmDialog when open and handles confirm/cancel', () => {
    const onOpenChange = vi.fn();
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open
        onOpenChange={onOpenChange}
        title="Delete cluster?"
        description="This action cannot be undone."
        confirmLabel="Delete"
        onConfirm={onConfirm}
      />,
    );
    expect(screen.getByRole('alertdialog', { name: 'Delete cluster?' })).toBeInTheDocument();
    expect(screen.getByText('This action cannot be undone.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onOpenChange).toHaveBeenCalledWith(false, expect.anything());
  });

  it('gives each Dialog a unique aria-labelledby and dismisses on Escape', () => {
    const onClose1 = vi.fn();
    const onClose2 = vi.fn();
    render(
      <>
        <Dialog open onOpenChange={onClose1} title="First dialog">
          <p>Body 1</p>
        </Dialog>
        <Dialog open onOpenChange={onClose2} title="Second dialog">
          <p>Body 2</p>
        </Dialog>
      </>,
    );
    const dialogs = screen.getAllByRole('dialog');
    expect(dialogs).toHaveLength(2);
    const id1 = dialogs[0].getAttribute('aria-labelledby');
    const id2 = dialogs[1].getAttribute('aria-labelledby');
    expect(id1).toBeTruthy();
    expect(id2).toBeTruthy();
    expect(id1).not.toBe(id2);

    fireEvent.keyDown(dialogs[1], { key: 'Escape' });
    expect(onClose2).toHaveBeenCalledWith(false);
  });

  it('supports Menu keyboard navigation, typeahead, menuitemradio, and Escape focus recovery', async () => {
    const onTheme = vi.fn();
    render(
      <Menu
        label="Actions"
        trigger={<span>Actions</span>}
        sections={[
          {
            heading: 'Theme',
            items: [
              { label: 'Dark', checked: true, onSelect: () => onTheme('dark') },
              { label: 'Light', checked: false, onSelect: () => onTheme('light') },
            ],
          },
          {
            heading: 'Workspace',
            items: [
              { label: 'Audit log', onSelect: vi.fn() },
              { label: 'Snippets', onSelect: vi.fn() },
            ],
          },
        ]}
      />,
    );

    const trigger = screen.getByRole('button', { name: 'Actions' });
    trigger.focus();
    fireEvent.click(trigger);

    const menu = await screen.findByRole('menu', { name: 'Actions' });
    const darkRadio = screen.getByRole('menuitemradio', { name: /Dark/ });
    const lightRadio = screen.getByRole('menuitemradio', { name: /Light/ });
    const auditItem = screen.getByRole('menuitem', { name: 'Audit log' });
    const snippetsItem = screen.getByRole('menuitem', { name: 'Snippets' });

    expect(darkRadio).toHaveAttribute('aria-checked', 'true');
    expect(lightRadio).toHaveAttribute('aria-checked', 'false');

    fireEvent.keyDown(menu, { key: 'End' });
    expect(snippetsItem).toHaveFocus();

    fireEvent.keyDown(menu, { key: 'Home' });
    expect(darkRadio).toHaveFocus();

    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(lightRadio).toHaveFocus();

    fireEvent.keyDown(menu, { key: 'ArrowUp' });
    expect(darkRadio).toHaveFocus();

    fireEvent.keyDown(menu, { key: 'a' });
    expect(auditItem).toHaveFocus();

    fireEvent.keyDown(menu, { key: 'Escape' });
    expect(screen.queryByRole('menu', { name: 'Actions' })).not.toBeInTheDocument();
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('toggles favorite and navigates InstanceContextMenu via keyboard', async () => {
    useAuthStore.setState({
      config: { aws_access_mode: 'user' } as AuthConfig,
      me: { user_id: 'u1', tenant_id: 't1', email: 'op@example.test', role: 'admin', method: 'password', expires_at: 9999999999 },
    });
    const inst: EC2Instance = {
      instance_id: 'i-fav-1',
      name: 'web-prod-01',
      state: 'running',
      platform: 'linux',
      os: 'linux',
      instance_type: 't3.medium',
      private_ip: '10.0.0.10',
      public_ip: '',
      aws_profile: 'prod',
      aws_region: 'us-east-1',
      account_id: '123456789012',
      account_alias: 'prod',
      tag1_value: '',
      tag2_value: '',
      tags: {},
    };
    render(<InstanceContextMenu />);
    act(() => openContextMenu({ x: 100, y: 120, instance: inst }));

    const menu = await screen.findByRole('menu');
    const items = screen.getAllByRole('menuitem');
    expect(items.length).toBeGreaterThan(2);

    fireEvent.keyDown(menu, { key: 'End' });
    expect(items[items.length - 1]).toHaveFocus();
    fireEvent.keyDown(menu, { key: 'Home' });
    expect(items[0]).toHaveFocus();

    const favItem = screen.getByRole('menuitem', { name: /Favorite/i });
    fireEvent.click(favItem);
    expect(useInstancesStore.getState().favorites).toContain('i-fav-1');
  });

  it('navigates CmdKPalette with Home, End, PageDown, PageUp and aria-activedescendant', () => {
    useAuthStore.setState({
      config: null,
      me: { user_id: 'u1', tenant_id: 't1', email: 'op@example.test', role: 'admin', method: 'password', expires_at: 9999999999 },
    });
    usePaletteStore.setState({ open: true, query: '' });

    render(<CmdKPalette />);
    const combobox = screen.getByRole('combobox', { name: 'Command palette' });
    const options = screen.getAllByRole('option');
    expect(options.length).toBeGreaterThan(3);

    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[0].id);

    fireEvent.keyDown(combobox, { key: 'End' });
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[options.length - 1].id);

    fireEvent.keyDown(combobox, { key: 'Home' });
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[0].id);

    fireEvent.keyDown(combobox, { key: 'PageDown' });
    const afterPageDown = combobox.getAttribute('aria-activedescendant');
    expect(afterPageDown).not.toBe(options[0].id);

    fireEvent.keyDown(combobox, { key: 'PageUp' });
    expect(combobox.getAttribute('aria-activedescendant')).toBe(options[0].id);
  });

  it('recalls sent prompts with ArrowUp and ArrowDown in AIChatPanel via createInputHistory', async () => {
    Element.prototype.scrollIntoView = vi.fn();
    useAuthStore.setState({
      config: { aws_access_mode: 'user' } as AuthConfig,
      me: { user_id: 'user', tenant_id: 'tenant', email: 'admin@example.test', role: 'admin', method: 'password', expires_at: 9999999999 },
    });
    useSessionsStore.setState({
      sessions: [{ id: 's1', type: 'ssh', instanceId: 'i-1', instanceName: 'app-01', status: 'connected', createdAt: 1, userSSH: { roleID: 'r1', region: 'us-east-1' } }],
      activeId: 's1',
    });
    useAIStore.getState().setOpen(true);
    vi.spyOn(window, 'fetch').mockImplementation(async (url) =>
      String(url).includes('/api/ai/catalog')
        ? new Response(JSON.stringify({ configured: false, models: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
        : new Response('data: {"type":"text","text":"ok"}\n\n', { status: 200 }),
    );

    render(<AIChatPanel />);
    const textarea = screen.getByLabelText('Chat message input') as HTMLTextAreaElement;

    fireEvent.change(textarea, { target: { value: 'first prompt' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(useAIStore.getState().streaming).toBe(false));

    fireEvent.change(textarea, { target: { value: 'second prompt' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(useAIStore.getState().streaming).toBe(false));

    expect(textarea.value).toBe('');
    Object.defineProperty(textarea, 'selectionStart', { value: 0, configurable: true });
    Object.defineProperty(textarea, 'selectionEnd', { value: 0, configurable: true });

    fireEvent.keyDown(textarea, { key: 'ArrowUp' });
    expect(textarea.value).toBe('second prompt');

    fireEvent.keyDown(textarea, { key: 'ArrowUp' });
    expect(textarea.value).toBe('first prompt');

    fireEvent.keyDown(textarea, { key: 'ArrowDown' });
    expect(textarea.value).toBe('second prompt');

    fireEvent.keyDown(textarea, { key: 'ArrowDown' });
    expect(textarea.value).toBe('');
  });

  it('renders Tooltip trigger cleanly', () => {
    render(
      <Tooltip label="Open settings">
        <button type="button">Settings</button>
      </Tooltip>,
    );
    expect(screen.getByRole('button', { name: 'Settings' })).toBeInTheDocument();
  });

  it('renders EmptyState and Skeleton helpers', () => {
    const { container } = render(
      <>
        <EmptyState title="Nothing here" description="Try another filter." />
        <Skeleton className="h-4 w-20" />
        <SkeletonRow />
        <SkeletonCard />
      </>,
    );
    expect(screen.getByText('Nothing here')).toBeInTheDocument();
    expect(screen.getByText('Try another filter.')).toBeInTheDocument();
    expect(container.querySelectorAll('.oq-skeleton').length).toBeGreaterThan(3);
  });
});
