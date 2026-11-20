import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { api, APIError } from '@/lib/api';
import { RecordingsList } from './RecordingsList';

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('reports unavailable storage and retries instead of showing an empty list', async () => {
  vi.spyOn(api, 'get')
    .mockResolvedValueOnce({ ok: false, error: new APIError(503, 'unavailable') })
    .mockResolvedValueOnce({ ok: true, data: [] });
  render(<RecordingsList onPlay={() => {}} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Recordings are unavailable');
  expect(screen.queryByText('No recordings yet')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
  await waitFor(() => expect(screen.getByText('No recordings yet')).toBeInTheDocument());
});
