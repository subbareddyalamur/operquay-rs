// @vitest-environment-options {"url":"http://localhost/"}
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SignInPage } from './SignInPage';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('does not send a login password over HTTP', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  render(<SignInPage />);
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'admin@local' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'test-password-only' } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/HTTPS is required/i);
  expect(fetch).not.toHaveBeenCalled();
});
