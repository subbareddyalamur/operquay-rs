import { beforeAll, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import ResizableHeader from './ResizableHeader.jsx';

beforeAll(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      disconnect() {}
    },
  );
  if (typeof globalThis.PointerEvent === 'undefined') {
    vi.stubGlobal('PointerEvent', MouseEvent);
  }
});

describe('ResizableHeader', () => {
  it('renders single-line truncated header label with hover tooltip', () => {
    const onResize = vi.fn();
    render(
      <table>
        <thead>
          <tr>
            <ResizableHeader label="Controller" width="13%" onResize={onResize} />
          </tr>
        </thead>
      </table>,
    );

    const th = screen.getByRole('columnheader', { name: /Controller/i });
    expect(th).toHaveAttribute('title', 'Controller');
    expect(screen.getByText('Controller')).toHaveAttribute('title', 'Controller');
  });

  it('trades column width 1:1 between adjacent columns inside fixed table width during drag', () => {
    const onResize = vi.fn();
    const onBatchResize = vi.fn();

    render(
      <table>
        <thead>
          <tr>
            <ResizableHeader label="Name" width="50%" onResize={onResize} onBatchResize={onBatchResize} />
            <ResizableHeader label="Namespace" width="50%" onResize={onResize} onBatchResize={onBatchResize} />
          </tr>
        </thead>
      </table>,
    );

    const table = screen.getByRole('table');
    const [nameTh, nsTh] = screen.getAllByRole('columnheader');

    vi.spyOn(table, 'getBoundingClientRect').mockReturnValue({
      width: 1000,
      height: 40,
      top: 0,
      left: 0,
      right: 1000,
      bottom: 40,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
    vi.spyOn(nameTh, 'getBoundingClientRect').mockReturnValue({
      width: 500,
      height: 40,
      top: 0,
      left: 0,
      right: 500,
      bottom: 40,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
    vi.spyOn(nsTh, 'getBoundingClientRect').mockReturnValue({
      width: 500,
      height: 40,
      top: 0,
      left: 500,
      right: 1000,
      bottom: 40,
      x: 500,
      y: 0,
      toJSON: () => ({}),
    });

    const separator = screen.getByRole('separator', { name: 'Resize Name' });
    fireEvent.pointerDown(separator, { clientX: 500, pointerId: 1 });
    expect(document.body.style.cursor).toBe('col-resize');

    fireEvent.pointerMove(separator, { clientX: 600, pointerId: 1 });

    expect(onBatchResize).toHaveBeenCalledWith({
      Name: '60.0000%',
      Namespace: '40.0000%',
    });
    expect(nameTh.style.width).toBe('60%');
    expect(nsTh.style.width).toBe('40%');

    fireEvent.pointerUp(separator, { clientX: 600, pointerId: 1 });
    expect(document.body.style.cursor).toBe('');
  });
});
