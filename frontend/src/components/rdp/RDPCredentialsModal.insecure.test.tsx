// @vitest-environment-options {"url":"http://desk.example/"}
import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { RDPCredentialsModal } from './RDPCredentialsModal';
import type { Instance } from '@/stores/instances';

it('does not submit RDP credentials over HTTP', () => {
  const submit = vi.fn();
  render(<RDPCredentialsModal open instance={{ instance_id: 'i-1', name: 'Windows' } as Instance} onSubmit={submit} onCancel={() => {}} />);
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'Administrator' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'temporary-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
  expect(screen.getByText(/HTTPS is required/i)).toBeInTheDocument();
  expect(submit).not.toHaveBeenCalled();
});
