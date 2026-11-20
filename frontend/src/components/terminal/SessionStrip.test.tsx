import { render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { SessionStrip } from './SessionStrip';

it('shows only an accessible red indicator when recording', () => {
  const props = { kind: 'rdp' as const, name: 'Server', instanceId: 'i-1', env: '', detailsOpen: false, onDetails: vi.fn(), focus: false, onFocus: vi.fn(), more: [], onEnd: vi.fn() };
  const view = render(<SessionStrip {...props} recording={false} />);
  expect(screen.queryByLabelText('Recording')).not.toBeInTheDocument();
  expect(screen.queryByText('Not recording')).not.toBeInTheDocument();
  view.rerender(<SessionStrip {...props} recording />);
  expect(screen.getByLabelText('Recording')).toHaveClass('bg-red-500', 'motion-safe:animate-pulse');
  expect(screen.queryByText('Recording')).not.toBeInTheDocument();
});
