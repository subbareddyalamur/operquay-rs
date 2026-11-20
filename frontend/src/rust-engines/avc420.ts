export interface AvcRect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface VideoDecoderLike {
  state?: string;
  configure: (cfg: { codec: string; hardwareAcceleration?: string; optimizeForLatency?: boolean }) => void;
  decode: (chunk: unknown) => void;
  flush?: () => Promise<void>;
  close: () => void;
}

export type VideoDecoderCtorLike = new (init: {
  output: (frame: { close: () => void } & CanvasImageSource) => void;
  error: (err: unknown) => void;
}) => VideoDecoderLike;

export type EncodedVideoChunkCtorLike = new (init: {
  type: 'key' | 'delta';
  timestamp: number;
  data: Uint8Array;
}) => unknown;

/**
 * Scan Annex-B NALU start codes (`00 00 01` or `00 00 00 01`) to detect IDR (5) or SPS (7)
 * keyframes so WebCodecs VideoDecoder receives an explicit `key` chunk on stream start or IDR.
 */
export function isAnnexBKeyframe(annexB: Uint8Array): boolean {
  for (let i = 0; i + 3 < annexB.length; i += 1) {
    if (annexB[i] === 0 && annexB[i + 1] === 0) {
      let naluOffset = -1;
      if (annexB[i + 2] === 1) {
        naluOffset = i + 3;
      } else if (i + 4 < annexB.length && annexB[i + 2] === 0 && annexB[i + 3] === 1) {
        naluOffset = i + 4;
      }
      if (naluOffset >= 0 && naluOffset < annexB.length) {
        const nalType = annexB[naluOffset] & 0x1f;
        if (nalType === 5 || nalType === 7) {
          return true;
        }
      }
    }
  }
  return false;
}

/**
 * Persistent WebCodecs H.264 / AVC420 decoder reused across OQR2 `0x0A` frames to avoid
 * per-frame VideoDecoder construction and pipeline flush stalls (`M12.5`).
 */
export class PersistentAvc420Decoder {
  private decoder: VideoDecoderLike | null = null;
  private configuredW = 0;
  private configuredH = 0;
  private hasSeenKeyframe = false;
  private lastRect: AvcRect = { x: 0, y: 0, w: 0, h: 0 };
  private frameSeq = 0;
  private readonly onFrame: (frame: { close: () => void } & CanvasImageSource, rect: AvcRect) => void;
  private readonly getConstructors: () => {
    VDec?: VideoDecoderCtorLike;
    VChunk?: EncodedVideoChunkCtorLike;
  };

  constructor(
    onFrame: (frame: { close: () => void } & CanvasImageSource, rect: AvcRect) => void,
    getConstructors?: () => { VDec?: VideoDecoderCtorLike; VChunk?: EncodedVideoChunkCtorLike },
  ) {
    this.onFrame = onFrame;
    this.getConstructors =
      getConstructors ??
      (() => {
        const win = window as unknown as {
          VideoDecoder?: VideoDecoderCtorLike;
          EncodedVideoChunk?: EncodedVideoChunkCtorLike;
        };
        return { VDec: win.VideoDecoder, VChunk: win.EncodedVideoChunk };
      });
  }

  public decodeFrame(annexB: Uint8Array, rect: AvcRect): boolean {
    if (annexB.length <= 4) {
      return false;
    }
    const { VDec, VChunk } = this.getConstructors();
    if (!VDec || !VChunk) {
      return false;
    }
    const isKey = isAnnexBKeyframe(annexB);
    const sizeChanged =
      rect.w > 0 && rect.h > 0 && (rect.w !== this.configuredW || rect.h !== this.configuredH);

    if (!this.decoder || this.decoder.state === 'closed' || sizeChanged) {
      this.close();
      this.decoder = new VDec({
        output: (frame) => {
          try {
            this.onFrame(frame, this.lastRect);
          } finally {
            frame.close();
          }
        },
        error: () => {
          this.hasSeenKeyframe = false;
        },
      });
      this.decoder.configure({
        codec: 'avc1.42E01F',
        hardwareAcceleration: 'prefer-hardware',
        optimizeForLatency: true,
      });
      this.configuredW = rect.w;
      this.configuredH = rect.h;
      this.hasSeenKeyframe = false;
    }

    if (!this.hasSeenKeyframe && !isKey) {
      // WebCodecs requires first decoded chunk after configure() to be a keyframe.
      return false;
    }
    if (isKey) {
      this.hasSeenKeyframe = true;
    }
    this.lastRect = rect;
    this.frameSeq += 1;
    try {
      this.decoder.decode(
        new VChunk({
          type: isKey ? 'key' : 'delta',
          timestamp: this.frameSeq * 16_667,
          data: annexB,
        }),
      );
      return true;
    } catch {
      this.close();
      return false;
    }
  }

  public close(): void {
    if (this.decoder) {
      try {
        if (this.decoder.state !== 'closed') {
          this.decoder.close();
        }
      } catch {
        // Ignore close errors if codec already tore down
      }
      this.decoder = null;
    }
    this.configuredW = 0;
    this.configuredH = 0;
    this.hasSeenKeyframe = false;
  }
}
