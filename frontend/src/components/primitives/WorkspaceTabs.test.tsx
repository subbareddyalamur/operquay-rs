import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { WorkspaceTab, WorkspaceTabBar } from './WorkspaceTabs';

afterEach(() => {
  cleanup();
});

describe('WorkspaceTabBar & WorkspaceTab', () => {
  it('renders container-tab items with selection state and keyboard activation', () => {
    const onSelectA = vi.fn();
    const onSelectB = vi.fn();

    render(
      <WorkspaceTabBar ariaLabel="Open sessions">
        <WorkspaceTab
          active
          label="web-prod-01"
          onSelect={onSelectA}
          onClose={vi.fn()}
          closeLabel="Close web-prod-01"
        />
        <WorkspaceTab
          label="api-staging-02"
          onSelect={onSelectB}
          onClose={vi.fn()}
          closeLabel="Close api-staging-02"
        />
      </WorkspaceTabBar>,
    );

    const tablist = screen.getByRole('tablist', { name: 'Open sessions' });
    expect(tablist).toHaveClass('oq-tab-list');

    const tabs = screen.getAllByRole('tab');
    expect(tabs).toHaveLength(2);
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true');
    expect(tabs[0]).toHaveClass('oq-tab', 'active');
    expect(tabs[1]).toHaveAttribute('aria-selected', 'false');

    fireEvent.keyDown(tabs[1], { key: 'Enter' });
    fireEvent.keyDown(tabs[1], { key: ' ' });
    expect(onSelectB).toHaveBeenCalledTimes(2);
    expect(onSelectA).not.toHaveBeenCalled();
  });

  it('closes without triggering selection on close button click or middle-click', () => {
    const onSelect = vi.fn();
    const onClose = vi.fn();

    render(
      <WorkspaceTabBar ariaLabel="Open sessions">
        <WorkspaceTab
          active
          label="worker-01"
          onSelect={onSelect}
          onClose={onClose}
          closeLabel="Close worker-01"
        />
      </WorkspaceTabBar>,
    );

    const closeBtn = screen.getByRole('button', { name: 'Close worker-01' });
    expect(closeBtn).toHaveClass('oq-tab-close');
    fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onSelect).not.toHaveBeenCalled();

    const tab = screen.getByRole('tab');
    fireEvent(tab, new MouseEvent('auxclick', { bubbles: true, button: 1 }));
    expect(onClose).toHaveBeenCalledTimes(2);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('renders confirmation button when confirmClose is true', () => {
    const onSelect = vi.fn();
    const onConfirmClose = vi.fn();

    render(
      <WorkspaceTabBar ariaLabel="Open sessions">
        <WorkspaceTab
          active
          label="db-prod-01"
          accentColor="var(--warn)"
          onSelect={onSelect}
          onClose={vi.fn()}
          closeLabel="Close db-prod-01"
          confirmClose
          confirmLabel="End?"
          confirmAriaLabel="Confirm close db-prod-01"
          onConfirmClose={onConfirmClose}
        />
      </WorkspaceTabBar>,
    );

    const confirmBtn = screen.getByRole('button', { name: 'Confirm close db-prod-01' });
    expect(confirmBtn).toHaveTextContent('End?');
    expect(confirmBtn).toHaveClass('oq-tab-confirm');
    fireEvent.click(confirmBtn);
    expect(onConfirmClose).toHaveBeenCalledTimes(1);
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('supports split-button mode used by Kubernetes resource tabs', () => {
    const onSelect = vi.fn();
    const onClose = vi.fn();

    render(
      <WorkspaceTabBar role="none" className="lens-tabs">
        <WorkspaceTab
          mode="split-button"
          className="lens-tab"
          active
          label="Pods - syca-plat-euc1-low"
          onSelect={onSelect}
          onClose={onClose}
          closeLabel="Close Pods tab"
        />
      </WorkspaceTabBar>,
    );

    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
    const selectBtn = screen.getByRole('button', { name: 'Pods - syca-plat-euc1-low' });
    const closeBtn = screen.getByRole('button', { name: 'Close Pods tab' });
    expect(selectBtn).toHaveClass('oq-tab-trigger');
    expect(closeBtn).toHaveClass('oq-tab-close');

    fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onSelect).not.toHaveBeenCalled();

    fireEvent.click(selectBtn);
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it('supports trigger-tab mode used by Kubernetes bottom panel shell tabs', () => {
    const onSelect = vi.fn();
    const onClose = vi.fn();

    render(
      <div role="tablist" aria-label="Pod shells">
        <WorkspaceTab
          mode="trigger-tab"
          size="sm"
          className="shell-tab"
          active
          label="web-123 / app"
          onSelect={onSelect}
          onClose={onClose}
          closeLabel="Close web-123 / app shell"
        />
      </div>,
    );

    const tab = screen.getByRole('tab', { name: 'web-123 / app' });
    expect(tab).toHaveAttribute('aria-selected', 'true');
    expect(tab.parentElement).toHaveClass('oq-tab', 'oq-tab-sm', 'active', 'shell-tab');

    const closeBtn = screen.getByRole('button', { name: 'Close web-123 / app shell' });
    fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(onSelect).not.toHaveBeenCalled();

    fireEvent.click(tab);
    expect(onSelect).toHaveBeenCalledTimes(1);
  });
});

