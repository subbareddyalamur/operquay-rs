// @vitest-environment-options {"url":"https://desk.example/"}
import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { RDPCredentialsModal } from './RDPCredentialsModal';
import type { Instance } from '@/stores/instances';

it('accepts per-connection credentials without offering to save or retrieve them', () => {
  const submit = vi.fn();
  const instance = { instance_id: 'i-1', name: 'Windows' } as Instance;
  render(<RDPCredentialsModal open instance={instance} onSubmit={submit} onCancel={() => {}} />);
  expect(screen.getByLabelText('Security')).toHaveValue('any');
  expect(screen.getAllByRole('option').map(option => option.textContent)).toEqual([
    'Security: Auto (any)', 'Security: NLA', 'Security: TLS', 'Security: RDP',
  ]);
  expect(screen.queryByText(/vault/i)).not.toBeInTheDocument();
  expect(screen.queryByLabelText(/record this session/i)).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'Administrator' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'temporary-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
  expect(submit).toHaveBeenCalledWith(expect.objectContaining({ username: 'Administrator', password: 'temporary-password', security: 'any' }));
  expect(submit.mock.calls[0][0]).not.toHaveProperty('saveToVault');
  expect(submit.mock.calls[0][0]).not.toHaveProperty('record');
});
