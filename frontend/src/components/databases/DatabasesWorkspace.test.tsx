import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { api } from '@/lib/api';
import { DatabasesWorkspace } from './DatabasesWorkspace';

describe('DatabasesWorkspace', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('starts with no dummy database connections and renders empty onboarding state', () => {
    render(<DatabasesWorkspace />);

    expect(screen.getByLabelText('Database explorer')).toBeInTheDocument();
    expect(screen.queryByText('prod-orders-pg')).not.toBeInTheDocument();
    expect(screen.queryByText('audit-ledger-pg')).not.toBeInTheDocument();
    expect(screen.queryByText('analytics-mysql')).not.toBeInTheDocument();
    expect(screen.getByText('No database connections configured yet')).toBeInTheDocument();
    expect(screen.getByLabelText('SQL query editor')).toBeInTheDocument();
    expect(screen.getByLabelText('Row inspector')).toBeInTheDocument();
  });

  it('adds a custom connection, runs SELECT 1, enforces Read-Only Guard, and shows Explain Plan and History', () => {
    render(<DatabasesWorkspace />);

    fireEvent.click(screen.getByLabelText('New database connection'));

    fireEvent.change(screen.getByLabelText(/Connection label/i), {
      target: { value: 'my-app-pg' },
    });
    fireEvent.change(screen.getByLabelText(/Hostname \/ Endpoint/i), {
      target: { value: 'pg.internal.local' },
    });
    fireEvent.change(screen.getByLabelText(/^Database$/i), {
      target: { value: 'orders_db' },
    });
    expect(screen.queryByLabelText(/IAM \/ DB Role/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Transport \/ Bastion Tunnel/i)).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/^Username$/i), {
      target: { value: 'db_operator' },
    });
    const passwordInput = screen.getByLabelText(/^Password$/i);
    expect(passwordInput).toHaveAttribute('type', 'password');
    fireEvent.change(passwordInput, {
      target: { value: 's3cr3t-pass' },
    });
    fireEvent.change(screen.getByLabelText(/^Use SSL$/i), {
      target: { value: 'false' },
    });
    expect(screen.getByLabelText(/^SSL Mode$/i)).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/^Use SSL$/i), {
      target: { value: 'true' },
    });
    expect(screen.getByLabelText(/^SSL Mode$/i)).toBeEnabled();
    fireEvent.change(screen.getByLabelText(/^SSL Mode$/i), {
      target: { value: 'verify-full' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Save Connection/i }));

    expect(screen.getByText('my-app-pg')).toBeInTheDocument();
    expect(screen.getByText('pg.internal.local:5432 · SSL: true (verify-full)')).toBeInTheDocument();

    const editor = screen.getByLabelText('SQL query editor');
    fireEvent.change(editor, { target: { value: 'SELECT 1;' } });
    fireEvent.click(screen.getByRole('button', { name: /Run/i }));

    expect(screen.getAllByText(/SELECT 1;/i).length).toBeGreaterThan(0);

    fireEvent.change(editor, { target: { value: 'DELETE FROM orders;' } });
    fireEvent.click(screen.getByRole('button', { name: /Run/i }));

    expect(screen.getByText(/Write statement blocked by Read-Only Guard/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /Explain Plan/i }));
    expect(screen.getByText(/Execution Plan/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /History/i }));
    expect(screen.getAllByText(/DELETE FROM orders;/i).length).toBeGreaterThan(1);
  });

  it('supports inline grid editing, right-panel inspector editing, Cancel, Save, and Refresh', () => {
    render(<DatabasesWorkspace />);

    fireEvent.click(screen.getByLabelText('New database connection'));
    fireEvent.change(screen.getByLabelText(/Connection label/i), {
      target: { value: 'edit-test-pg' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Save Connection/i }));

    fireEvent.click(screen.getByRole('button', { name: /Run/i }));

    const saveBtn = screen.getByRole('button', { name: 'Save' });
    const cancelBtn = screen.getByRole('button', { name: 'Cancel' });
    const refreshBtn = screen.getByRole('button', { name: 'Refresh' });

    expect(saveBtn).toBeDisabled();
    expect(cancelBtn).toBeDisabled();

    // Inline cell edit
    fireEvent.click(screen.getByTitle('1'));
    const inlineInput = screen.getByLabelText('Inline edit result row 1');
    fireEvent.change(inlineInput, { target: { value: '42' } });
    fireEvent.blur(inlineInput);

    expect(screen.getByTitle('42')).toBeInTheDocument();
    expect(screen.getByText('1 unsaved')).toBeInTheDocument();
    expect(saveBtn).toBeEnabled();
    expect(cancelBtn).toBeEnabled();

    // Cancel reverts uncommitted edits
    fireEvent.click(cancelBtn);
    expect(screen.getByTitle('1')).toBeInTheDocument();
    expect(saveBtn).toBeDisabled();
    expect(cancelBtn).toBeDisabled();

    // Right-panel Row Inspector edit + Save
    const inspectorInput = screen.getByLabelText('Edit result');
    fireEvent.change(inspectorInput, { target: { value: '99' } });
    expect(screen.getByTitle('99')).toBeInTheDocument();

    fireEvent.click(saveBtn);
    expect(screen.getByTitle('99')).toBeInTheDocument();
    expect(saveBtn).toBeDisabled();
    expect(cancelBtn).toBeDisabled();

    // Refresh re-runs query and restores fresh result
    fireEvent.click(refreshBtn);
    expect(screen.getByTitle('1')).toBeInTheDocument();
  });

  it('supports Test Connection, live Connect via /api/db/connect, live query via /api/db/query, Reconnect, Disconnect, and Edit', async () => {
    const postSpy = vi.spyOn(api, 'post').mockImplementation(async (path) => {
      if (path === '/api/db/connect') {
        return {
          ok: true,
          data: {
            connected: true,
            database: 'operquay',
            databases: ['operquay', 'postgres'],
            host: '127.0.0.1',
            port: 5433,
            tables: [
              {
                name: 'users',
                schema: 'public',
                estimatedRows: 1,
                sizeBytes: 32768,
                sizePretty: '32K',
                columns: [
                  { name: 'id', type: 'uuid', pk: true, nullable: false },
                  { name: 'email', type: 'text', pk: false, nullable: false },
                ],
                rows: [{ id: 'u-1', email: 'admin@local' }],
              },
            ],
          },
        };
      }
      if (path === '/api/db/query') {
        return {
          ok: true,
          data: {
            columns: ['id', 'email'],
            rows: [{ id: 'u-1', email: 'live@operquay.io' }],
            duration_ms: 8,
          },
        };
      }
      if (path === '/api/db/mutate') {
        return {
          ok: true,
          data: {
            committed: true,
            updated: 1,
            inserted: 0,
            duration_ms: 5,
          },
        };
      }
      return { ok: false, error: new Error(`Unexpected path: ${path}`) as never };
    });

    render(<DatabasesWorkspace />);

    fireEvent.click(screen.getByLabelText('New database connection'));
    fireEvent.change(screen.getByLabelText(/Connection label/i), { target: { value: 'operquay-live' } });
    fireEvent.change(screen.getByLabelText(/Hostname \/ Endpoint/i), { target: { value: '127.0.0.1' } });
    fireEvent.change(screen.getByLabelText(/^Port$/i), { target: { value: '5433' } });
    fireEvent.change(screen.getByLabelText(/^Database$/i), { target: { value: 'operquay' } });
    fireEvent.change(screen.getByLabelText(/^Username$/i), { target: { value: 'postgres' } });

    fireEvent.click(screen.getByRole('button', { name: /Test Connection/i }));
    await waitFor(() => {
      expect(screen.getByText(/Connection succeeded \(1 table discovered\)/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /Save Connection/i }));

    await waitFor(() => {
      expect(screen.getByText('Overview')).toBeInTheDocument();
      expect(screen.getByText('Schema')).toBeInTheDocument();
      expect(screen.getByText('public')).toBeInTheDocument();
      expect(screen.getByText('Tables')).toBeInTheDocument();
      expect(screen.getByText('users')).toBeInTheDocument();
      expect(screen.getByText('32K')).toBeInTheDocument();
    });

    // Expand table columns independently
    fireEvent.click(screen.getByLabelText('Toggle columns for users'));
    expect(screen.getByText('uuid')).toBeInTheDocument();

    expect(screen.getByTitle('admin@local')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /^Reconnect$/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole('button', { name: /^Disconnect$/i }).length).toBeGreaterThan(0);

    const editor = screen.getByLabelText('SQL query editor');
    fireEvent.change(editor, { target: { value: 'SELECT id, email FROM public.users;' } });
    fireEvent.click(screen.getByRole('button', { name: /Run Query/i }));

    await waitFor(() => {
      expect(screen.getByTitle('live@operquay.io')).toBeInTheDocument();
    });
    expect(postSpy).toHaveBeenCalledWith(
      '/api/db/query',
      expect.objectContaining({
        sql: 'SELECT id, email FROM public.users;',
        read_only: true,
      }),
    );

    // Edit row via Row Inspector and Save -> commits via /api/db/mutate
    const emailInput = screen.getByLabelText('Edit email');
    fireEvent.change(emailInput, { target: { value: 'updated@operquay.io' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(postSpy).toHaveBeenCalledWith(
        '/api/db/mutate',
        expect.objectContaining({
          schema: 'public',
          table: 'users',
          primary_keys: ['id'],
          updates: [
            {
              original: { id: 'u-1', email: 'live@operquay.io' },
              changes: { email: 'updated@operquay.io' },
            },
          ],
          inserts: [],
        }),
      );
    });

    fireEvent.click(screen.getAllByRole('button', { name: /^Disconnect$/i })[0]);
    expect(screen.getAllByRole('button', { name: /^Connect$/i }).length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: 'Edit active connection' }));
    expect(screen.getByRole('heading', { name: /Edit Database Connection/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save & Reconnect/i })).toBeInTheDocument();
  });
});
