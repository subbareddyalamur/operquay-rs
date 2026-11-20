import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DatabaseTree, type DbConnection } from './DatabaseTree';

const mockConnection: DbConnection = {
  id: 'conn-1',
  name: 'operquay',
  engine: 'postgres',
  host: '127.0.0.1',
  port: 5433,
  database: 'operquay',
  databases: ['operquay'],
  username: 'operquay',
  status: 'connected',
  liveBackend: true,
  tables: [
    {
      name: 'users',
      schema: 'public',
      estimatedRows: 48,
      sizeBytes: 48000,
      sizePretty: '48K',
      columns: [
        { name: 'id', type: 'text', pk: true },
        { name: 'email', type: 'text' },
        { name: 'role', type: 'text' },
      ],
    },
    {
      name: 'tenants',
      schema: 'public',
      estimatedRows: 32,
      sizeBytes: 32000,
      sizePretty: '32K',
      columns: [
        { name: 'id', type: 'text', pk: true },
        { name: 'name', type: 'text' },
      ],
    },
  ],
};

describe('DatabaseTree', () => {
  it('renders connection header with Reconnect, Disconnect, Edit, and Remove buttons', () => {
    const onReconnect = vi.fn();
    const onDisconnect = vi.fn();
    const onEdit = vi.fn();
    const onRemove = vi.fn();

    render(
      <DatabaseTree
        connections={[mockConnection]}
        selectedConnectionId="conn-1"
        onConnect={onReconnect}
        onDisconnect={onDisconnect}
        onEdit={onEdit}
        onRemove={onRemove}
      />,
    );

    expect(screen.getAllByText('operquay').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/127\.0\.0\.1:5433/)).toBeInTheDocument();
    expect(screen.getByLabelText('PostgreSQL')).toBeInTheDocument();
    expect(screen.getByText('PG')).toBeInTheDocument();

    const reconnectBtn = screen.getByRole('button', { name: /reconnect/i });
    const disconnectBtn = screen.getByRole('button', { name: /disconnect/i });
    const editBtn = screen.getByRole('button', { name: /edit/i });
    const removeBtn = screen.getByRole('button', { name: /remove/i });

    expect(reconnectBtn).toBeInTheDocument();
    expect(disconnectBtn).toBeInTheDocument();
    expect(editBtn).toBeInTheDocument();
    expect(removeBtn).toBeInTheDocument();

    fireEvent.click(reconnectBtn);
    expect(onReconnect).toHaveBeenCalledWith(mockConnection);

    fireEvent.click(disconnectBtn);
    expect(onDisconnect).toHaveBeenCalledWith(mockConnection);

    fireEvent.click(editBtn);
    expect(onEdit).toHaveBeenCalledWith(mockConnection);

    fireEvent.click(removeBtn);
    expect(onRemove).toHaveBeenCalledWith(mockConnection);
  });

  it('renders tree hierarchy (Databases -> operquay -> Schemas -> public -> Tables) and triggers onOpenTable when clicking a table', () => {
    const onOpenTable = vi.fn();

    render(
      <DatabaseTree
        connections={[mockConnection]}
        selectedConnectionId="conn-1"
        onOpenTable={onOpenTable}
      />,
    );

    // Verify tree items are rendered
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Schema')).toBeInTheDocument();
    expect(screen.getByText('public')).toBeInTheDocument();
    expect(screen.getByText('Tables')).toBeInTheDocument();
    expect(screen.getByText('users')).toBeInTheDocument();
    expect(screen.getByText('tenants')).toBeInTheDocument();
    expect(screen.getByText('48K')).toBeInTheDocument();
    expect(screen.getByText('32K')).toBeInTheDocument();

    // Click on table row
    fireEvent.click(screen.getByText('users'));
    expect(onOpenTable).toHaveBeenCalledWith(mockConnection, mockConnection.tables[0]);
  });

  it('expands table node to show columns with PK icons and types', () => {
    render(
      <DatabaseTree
        connections={[mockConnection]}
        selectedConnectionId="conn-1"
      />,
    );

    // Click the chevron button next to table 'users'
    const userRow = screen.getByText('users').closest('div');
    expect(userRow).not.toBeNull();
    const chevronBtn = userRow?.querySelector('button');
    expect(chevronBtn).not.toBeNull();
    fireEvent.click(chevronBtn!);

    // Column 'email' and 'role' should be displayed
    expect(screen.getByText('email')).toBeInTheDocument();
    expect(screen.getByText('role')).toBeInTheDocument();
  });

  it('filters tables based on filterText', () => {
    render(
      <DatabaseTree
        connections={[mockConnection]}
        selectedConnectionId="conn-1"
        filterText="tenant"
      />,
    );

    expect(screen.getByText('tenants')).toBeInTheDocument();
    expect(screen.queryByText('users')).not.toBeInTheDocument();
  });

  it('shows full table name on hover only when truncated', async () => {
    const longTableConn: DbConnection = {
      ...mockConnection,
      tables: [
        {
          schema: 'public',
          name: 'aws_user_credential_obfuscated_long_table_name',
          estimatedRows: 100,
          sizeBytes: 16000,
          sizePretty: '16K',
          columns: [],
        },
        {
          schema: 'public',
          name: 'short_tbl',
          estimatedRows: 10,
          sizeBytes: 8000,
          sizePretty: '8K',
          columns: [],
        },
      ],
    };

    render(
      <DatabaseTree
        connections={[longTableConn]}
        selectedConnectionId="conn-1"
      />,
    );

    const longLabel = screen.getByText('aws_user_credential_obfuscated_long_table_name');
    Object.defineProperty(longLabel, 'scrollWidth', { value: 260, configurable: true });
    Object.defineProperty(longLabel, 'clientWidth', { value: 120, configurable: true });

    const shortLabel = screen.getByText('short_tbl');
    Object.defineProperty(shortLabel, 'scrollWidth', { value: 60, configurable: true });
    Object.defineProperty(shortLabel, 'clientWidth', { value: 120, configurable: true });

    const shortBtn = shortLabel.closest('button')!;
    fireEvent.pointerEnter(shortBtn);
    fireEvent.mouseEnter(shortBtn);
    await new Promise((r) => setTimeout(r, 450));
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
    fireEvent.pointerLeave(shortBtn);
    fireEvent.mouseLeave(shortBtn);

    const longBtn = longLabel.closest('button')!;
    fireEvent.pointerEnter(longBtn);
    fireEvent.mouseEnter(longBtn);

    await waitFor(
      () => {
        const tooltip = screen.getByRole('tooltip');
        expect(tooltip).toHaveTextContent('aws_user_credential_obfuscated_long_table_name');
      },
      { timeout: 1500 },
    );
  });
});
