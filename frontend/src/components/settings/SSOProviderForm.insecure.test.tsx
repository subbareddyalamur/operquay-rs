// @vitest-environment-options {"url":"http://desk.example/"}
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SSOProviderForm } from './SSOProviderForm';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { post: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it('does not send provider credentials from an HTTP page', () => {
  render(<SSOProviderForm canManage onAdded={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Issuer URL' }), { target: { value: 'https://idp.example' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Client ID' }), { target: { value: 'client' } });
  fireEvent.change(screen.getByLabelText(/Client secret/), { target: { value: 'secret' } });
  fireEvent.change(screen.getByLabelText('Other users'), { target: { value: 'readonly' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  expect(screen.getByRole('alert')).toHaveTextContent(/HTTPS is required/i);
  expect(api.post).not.toHaveBeenCalled();
});
