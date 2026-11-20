export type Oqr2DecodedMessage =
  | {
      type: 'hello_ack';
      seq: number;
      width: number;
      height: number;
      cursorPrediction: boolean;
      traceId: string;
      protocol: string;
    }
  | {
      type: 'tile_png';
      seq: number;
      layer: number;
      x: number;
      y: number;
      w: number;
      h: number;
      bytes: Uint8Array;
    }
  | {
      type: 'tile_jpeg';
      seq: number;
      layer: number;
      x: number;
      y: number;
      w: number;
      h: number;
      bytes: Uint8Array;
    }
  | {
      type: 'solid_fill';
      seq: number;
      layer: number;
      x: number;
      y: number;
      w: number;
      h: number;
      rgba: [number, number, number, number];
    }
  | {
      type: 'copy_rect';
      seq: number;
      srcLayer: number;
      sx: number;
      sy: number;
      w: number;
      h: number;
      dstLayer: number;
      dx: number;
      dy: number;
    }
  | {
      type: 'cursor_shape';
      seq: number;
      hotX: number;
      hotY: number;
      w: number;
      h: number;
      rgba: Uint8Array;
    }
  | { type: 'cursor_move'; seq: number; x: number; y: number }
  | { type: 'resize_surface'; seq: number; layer: number; w: number; h: number }
  | {
      type: 'stats_sync';
      seq: number;
      serverTsMs: number;
      lagMs: number;
      fps: number;
      jpegQuality: number;
      droppedFrames: number;
      codecTag: string;
    }
  | {
      type: 'h264_frame';
      seq: number;
      layer: number;
      x: number;
      y: number;
      w: number;
      h: number;
      annexB: Uint8Array;
    }
  | {
      type: 'clipboard_text';
      seq: number;
      text: string;
    };

export function decodeOqr2Frame(buffer: ArrayBuffer): Oqr2DecodedMessage {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  if (bytes.length < 9) {
    throw new Error(`OQR2 frame too short: ${bytes.length}`);
  }
  if (bytes[0] !== 0x4f || bytes[1] !== 0x51 || bytes[2] !== 0x52 || bytes[3] !== 0x32) {
    throw new Error('Invalid OQR2 magic');
  }

  const opcode = view.getUint8(4);
  const seq = view.getUint32(5, true);
  let offset = 9;

  const readStr = (): string => {
    const len = view.getUint16(offset, true);
    offset += 2;
    const str = new TextDecoder().decode(bytes.subarray(offset, offset + len));
    offset += len;
    return str;
  };

  switch (opcode) {
    case 0x01: {
      const width = view.getUint16(offset, true);
      const height = view.getUint16(offset + 2, true);
      const cursorPrediction = view.getUint8(offset + 4) !== 0;
      offset += 5;
      const traceId = readStr();
      const protocol = readStr();
      return { type: 'hello_ack', seq, width, height, cursorPrediction, traceId, protocol };
    }
    case 0x02:
    case 0x03: {
      const layer = view.getInt32(offset, true);
      const x = view.getUint16(offset + 4, true);
      const y = view.getUint16(offset + 6, true);
      const w = view.getUint16(offset + 8, true);
      const h = view.getUint16(offset + 10, true);
      const len = view.getUint32(offset + 12, true);
      offset += 16;
      const slice = bytes.subarray(offset, offset + len);
      return {
        type: opcode === 0x02 ? 'tile_png' : 'tile_jpeg',
        seq,
        layer,
        x,
        y,
        w,
        h,
        bytes: slice,
      };
    }
    case 0x04: {
      const layer = view.getInt32(offset, true);
      const x = view.getUint16(offset + 4, true);
      const y = view.getUint16(offset + 6, true);
      const w = view.getUint16(offset + 8, true);
      const h = view.getUint16(offset + 10, true);
      offset += 12;
      return {
        type: 'solid_fill',
        seq,
        layer,
        x,
        y,
        w,
        h,
        rgba: [bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]],
      };
    }
    case 0x05: {
      const srcLayer = view.getInt32(offset, true);
      const sx = view.getUint16(offset + 4, true);
      const sy = view.getUint16(offset + 6, true);
      const w = view.getUint16(offset + 8, true);
      const h = view.getUint16(offset + 10, true);
      const dstLayer = view.getInt32(offset + 12, true);
      const dx = view.getUint16(offset + 16, true);
      const dy = view.getUint16(offset + 18, true);
      return { type: 'copy_rect', seq, srcLayer, sx, sy, w, h, dstLayer, dx, dy };
    }
    case 0x06: {
      const hotX = view.getUint16(offset, true);
      const hotY = view.getUint16(offset + 2, true);
      const w = view.getUint16(offset + 4, true);
      const h = view.getUint16(offset + 6, true);
      const len = view.getUint32(offset + 8, true);
      offset += 12;
      return {
        type: 'cursor_shape',
        seq,
        hotX,
        hotY,
        w,
        h,
        rgba: bytes.subarray(offset, offset + len),
      };
    }
    case 0x07: {
      return {
        type: 'cursor_move',
        seq,
        x: view.getUint16(offset, true),
        y: view.getUint16(offset + 2, true),
      };
    }
    case 0x08: {
      return {
        type: 'resize_surface',
        seq,
        layer: view.getInt32(offset, true),
        w: view.getUint16(offset + 4, true),
        h: view.getUint16(offset + 6, true),
      };
    }
    case 0x09: {
      const low = view.getUint32(offset, true);
      const high = view.getUint32(offset + 4, true);
      const serverTsMs = high * 4294967296 + low;
      const lagMs = view.getUint32(offset + 8, true);
      const fps = view.getUint16(offset + 12, true);
      const jpegQuality = view.getUint8(offset + 14);
      const dLow = view.getUint32(offset + 15, true);
      const dHigh = view.getUint32(offset + 19, true);
      const droppedFrames = dHigh * 4294967296 + dLow;
      offset += 23;
      const codecTag = readStr();
      return {
        type: 'stats_sync',
        seq,
        serverTsMs,
        lagMs,
        fps,
        jpegQuality,
        droppedFrames,
        codecTag,
      };
    }
    case 0x0a: {
      const layer = view.getInt32(offset, true);
      const x = view.getUint16(offset + 4, true);
      const y = view.getUint16(offset + 6, true);
      const w = view.getUint16(offset + 8, true);
      const h = view.getUint16(offset + 10, true);
      const len = view.getUint32(offset + 12, true);
      offset += 16;
      return {
        type: 'h264_frame',
        seq,
        layer,
        x,
        y,
        w,
        h,
        annexB: bytes.subarray(offset, offset + len),
      };
    }
    case 0x0b: {
      const len = view.getUint32(offset, true);
      offset += 4;
      return {
        type: 'clipboard_text',
        seq,
        text: new TextDecoder().decode(bytes.subarray(offset, offset + len)),
      };
    }
    default:
      throw new Error(`Unknown OQR2 opcode 0x${opcode.toString(16)}`);
  }
}

