// @vitest-environment-options {"url":"http://localhost/"}
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SnippetsModal } from './SnippetsModal';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), patch: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it('does not load or submit preferences over HTTP', () => {
  render(<SnippetsModal open onOpenChange={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Delete Uptime' }));
  expect(api.get).not.toHaveBeenCalled();
  expect(api.patch).not.toHaveBeenCalled();
});
