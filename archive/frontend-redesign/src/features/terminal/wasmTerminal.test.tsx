import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { createRef } from 'react';
import { OperquayTerminal, type OperquayTerminalRef } from './OperquayTerminal';
import { WasmTerminalDriver } from './wasmTerminal';

const wasmPath = path.resolve(process.cwd(), 'public/operquay_term.wasm');
const wasmBytes = fs.readFileSync(wasmPath);

describe('Pure-Rust WASM Terminal (operquay_term.wasm)', () => {
  it('executes compiled Rust WASM binary directly for ANSI/TrueColor/search/serialize/bracketed-paste', async () => {
    const drv = await WasmTerminalDriver.create(40, 8, 50, wasmBytes);
    const reply = drv.feed('\x1b[38;2;63;184;175mok\x1b[0m findme\x1b[?2004h\x1b[?1h\x1b[6n');
    expect(new TextDecoder().decode(reply)).toBe('\x1b[1;10R');

    const snap = drv.snapshot();
    expect(snap.cols).toBe(40);
    expect(snap.rows).toBe(8);
    expect(snap.bracketedPaste).toBe(true);
    expect(snap.appCursor).toBe(true);

    expect(drv.encodeKey('ArrowUp', false, false)).toBe('\x1bOA');
    expect(drv.encodePaste('echo \x1bhi')).toBe('\x1b[200~echo hi\x1b[201~');

    const hits = drv.search('findme');
    expect(hits).toHaveLength(1);
    expect(hits[0].colStart).toBe(3);

    expect(drv.serializeVt()).toContain('38;2;63;184;175mok\x1b[0m findme');
    expect(drv.plainText()).toContain('ok findme');
    drv.dispose();
  });

  it('mounts OperquayTerminal React component, writes output, searches & forwards keystrokes', async () => {
    const onData = vi.fn();
    const termRef = createRef<OperquayTerminalRef>();
    render(
      <OperquayTerminal
        ref={termRef}
        cols={30}
        rows={6}
        wasmBytes={wasmBytes}
        onData={onData}
      />,
    );

    await vi.waitFor(() => {
      expect(screen.queryByText(/Initializing pure-Rust WASM/)).not.toBeInTheDocument();
    });

    await act(async () => {
      termRef.current?.write('prod-bastion$ uname -a\r\nLinux arm64');
    });
    expect(termRef.current?.plainText()).toContain('Linux arm64');

    await act(async () => {
      expect(termRef.current?.search('bastion')).toBe(1);
    });
    const region = screen.getByRole('textbox', { name: /Operquay pure-Rust WebAssembly terminal/ });
    fireEvent.keyDown(region, { key: 'l' });
    expect(onData).toHaveBeenCalledWith('l');
  });
});
