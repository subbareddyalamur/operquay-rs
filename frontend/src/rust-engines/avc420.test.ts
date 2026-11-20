import { describe, expect, it, vi } from 'vitest';
import {
  isAnnexBKeyframe,
  PersistentAvc420Decoder,
  type EncodedVideoChunkCtorLike,
  type VideoDecoderCtorLike,
} from './avc420';

describe('PersistentAvc420Decoder (M12.5)', () => {
  it('detects Annex-B IDR/SPS keyframes vs P-frame delta slices', () => {
    const sps = new Uint8Array([0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xe0, 0x1f]);
    const idr = new Uint8Array([0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21]);
    const pSlice = new Uint8Array([0x00, 0x00, 0x00, 0x01, 0x41, 0x9a, 0x22]);

    expect(isAnnexBKeyframe(sps)).toBe(true);
    expect(isAnnexBKeyframe(idr)).toBe(true);
    expect(isAnnexBKeyframe(pSlice)).toBe(false);
  });

  it('reuses one VideoDecoder instance across frames and reconfigures on resize', () => {
    const configure = vi.fn();
    const decode = vi.fn();
    const close = vi.fn();
    let ctorCalls = 0;
    const outputRefs: Array<(f: { close: () => void } & CanvasImageSource) => void> = [];

    class MockDecoder {
      state = 'configured';
      constructor(init: { output: (f: { close: () => void } & CanvasImageSource) => void }) {
        ctorCalls += 1;
        outputRefs.push(init.output);
      }
      configure = configure;
      decode = decode;
      close = () => {
        this.state = 'closed';
        close();
      };
    }
    class MockChunk {
      constructor(public init: { type: 'key' | 'delta'; timestamp: number; data: Uint8Array }) {}
    }

    const drawn: Array<{ w: number; h: number }> = [];
    const bridge = new PersistentAvc420Decoder(
      (_frame, rect) => drawn.push({ w: rect.w, h: rect.h }),
      () => ({
        VDec: MockDecoder as unknown as VideoDecoderCtorLike,
        VChunk: MockChunk as unknown as EncodedVideoChunkCtorLike,
      }),
    );

    const delta = new Uint8Array([0x00, 0x00, 0x00, 0x01, 0x41, 0x9a, 0x22]);
    const key = new Uint8Array([0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84]);

    // Delta before initial keyframe is skipped safely after configuring
    expect(bridge.decodeFrame(delta, { x: 0, y: 0, w: 1280, h: 720 })).toBe(false);
    expect(ctorCalls).toBe(1);

    // Keyframe + subsequent delta reuse the same decoder instance
    expect(bridge.decodeFrame(key, { x: 0, y: 0, w: 1280, h: 720 })).toBe(true);
    expect(bridge.decodeFrame(delta, { x: 0, y: 0, w: 1280, h: 720 })).toBe(true);
    expect(ctorCalls).toBe(1);
    expect(decode).toHaveBeenCalledTimes(2);

    const fakeFrame = { close: vi.fn() } as unknown as { close: () => void } & CanvasImageSource;
    outputRefs[0]?.(fakeFrame);
    expect(drawn).toEqual([{ w: 1280, h: 720 }]);
    expect(fakeFrame.close).toHaveBeenCalledTimes(1);

    // Resize reconfigures and closes old decoder
    expect(bridge.decodeFrame(key, { x: 0, y: 0, w: 1920, h: 1080 })).toBe(true);
    expect(ctorCalls).toBe(2);
    expect(close).toHaveBeenCalledTimes(1);

    bridge.close();
    expect(close).toHaveBeenCalledTimes(2);
  });
});
