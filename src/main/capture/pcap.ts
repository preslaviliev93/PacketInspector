// Streaming reader for classic pcap and pcapng, plus a pcapng writer.
// Bytes may arrive in arbitrary chunks (e.g. from a child process' stdout),
// so the reader buffers until a complete record is available.

export interface RawFrame {
  /** Seconds since epoch, fractional. */
  ts: number;
  /** DLT / LINKTYPE value. */
  linkType: number;
  data: Uint8Array;
  /** Original length on the wire (may exceed data.length when truncated). */
  origLen: number;
}

export const LINKTYPE = {
  NULL: 0,
  ETHERNET: 1,
  RAW: 101,
  LINUX_SLL: 113,
  IPV4: 228,
  IPV6: 229,
  LINUX_SLL2: 276,
  LOOP: 108,
} as const;

const PCAPNG_SHB = 0x0a0d0d0a;

export class PcapStreamReader {
  private buf: Buffer = Buffer.alloc(0);
  private format: 'unknown' | 'pcap' | 'pcapng' = 'unknown';
  private le = true;
  // classic pcap
  private nanos = false;
  private linkType = LINKTYPE.ETHERNET as number;
  private headerDone = false;
  // pcapng
  private interfaces: { linkType: number; tsDiv: number }[] = [];

  constructor(private onFrame: (f: RawFrame) => void) {}

  push(chunk: Buffer | Uint8Array): void {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : Buffer.from(chunk);
    let consumed = 0;
    for (;;) {
      const n = this.step(consumed);
      if (n <= 0) break;
      consumed += n;
    }
    if (consumed > 0) this.buf = this.buf.subarray(consumed);
  }

  /** Try to parse one unit at `pos`. Returns bytes consumed, or 0 if more data is needed. */
  private step(pos: number): number {
    const avail = this.buf.length - pos;
    if (this.format === 'unknown') {
      if (avail < 4) return 0;
      const magicBE = this.buf.readUInt32BE(pos);
      if (magicBE === PCAPNG_SHB) {
        this.format = 'pcapng';
      } else {
        this.format = 'pcap';
      }
    }
    return this.format === 'pcap' ? this.stepPcap(pos, avail) : this.stepPcapng(pos, avail);
  }

  private u32(pos: number): number {
    return this.le ? this.buf.readUInt32LE(pos) : this.buf.readUInt32BE(pos);
  }
  private u16(pos: number): number {
    return this.le ? this.buf.readUInt16LE(pos) : this.buf.readUInt16BE(pos);
  }

  private stepPcap(pos: number, avail: number): number {
    if (!this.headerDone) {
      if (avail < 24) return 0;
      const m = this.buf.readUInt32LE(pos);
      if (m === 0xa1b2c3d4) { this.le = true; this.nanos = false; }
      else if (m === 0xd4c3b2a1) { this.le = false; this.nanos = false; }
      else if (m === 0xa1b23c4d) { this.le = true; this.nanos = true; }
      else if (m === 0x4d3cb2a1) { this.le = false; this.nanos = true; }
      else throw new Error('Not a pcap/pcapng stream (bad magic number)');
      this.linkType = this.u32(pos + 20) & 0x0fffffff;
      this.headerDone = true;
      return 24;
    }
    if (avail < 16) return 0;
    const sec = this.u32(pos);
    const frac = this.u32(pos + 4);
    const incl = this.u32(pos + 8);
    const orig = this.u32(pos + 12);
    if (incl > 0x4000000) throw new Error('Corrupt pcap record length');
    if (avail < 16 + incl) return 0;
    const data = new Uint8Array(this.buf.subarray(pos + 16, pos + 16 + incl));
    this.onFrame({
      ts: sec + frac / (this.nanos ? 1e9 : 1e6),
      linkType: this.linkType,
      data,
      origLen: orig,
    });
    return 16 + incl;
  }

  private stepPcapng(pos: number, avail: number): number {
    if (avail < 12) return 0;
    const typeBE = this.buf.readUInt32BE(pos);
    if (typeBE === PCAPNG_SHB) {
      // Byte-order magic decides endianness for the whole section.
      const bom = this.buf.readUInt32LE(pos + 8);
      if (bom === 0x1a2b3c4d) this.le = true;
      else if (bom === 0x4d3c2b1a) this.le = false;
      else throw new Error('Corrupt pcapng section header');
      this.interfaces = [];
    }
    const type = this.u32(pos);
    const len = this.u32(pos + 4);
    if (len < 12 || len > 0x4000000) throw new Error('Corrupt pcapng block length');
    if (avail < len) return 0;
    const body = pos + 8;
    switch (type) {
      case 1: { // Interface Description Block
        const linkType = this.u16(body);
        let tsDiv = 1e6;
        // options start after linktype(2) reserved(2) snaplen(4)
        let o = body + 8;
        const end = pos + len - 4;
        while (o + 4 <= end) {
          const code = this.u16(o);
          const olen = this.u16(o + 2);
          if (code === 0) break;
          if (code === 9 && olen >= 1) {
            const v = this.buf[o + 4];
            tsDiv = v & 0x80 ? Math.pow(2, v & 0x7f) : Math.pow(10, v);
          }
          o += 4 + ((olen + 3) & ~3);
        }
        this.interfaces.push({ linkType, tsDiv });
        break;
      }
      case 6: { // Enhanced Packet Block
        const ifId = this.u32(body);
        const hi = this.u32(body + 4);
        const lo = this.u32(body + 8);
        const cap = this.u32(body + 12);
        const orig = this.u32(body + 16);
        const iface = this.interfaces[ifId] ?? { linkType: LINKTYPE.ETHERNET, tsDiv: 1e6 };
        const raw = hi * 4294967296 + lo;
        const data = new Uint8Array(this.buf.subarray(body + 20, body + 20 + cap));
        this.onFrame({ ts: raw / iface.tsDiv, linkType: iface.linkType, data, origLen: orig });
        break;
      }
      case 3: { // Simple Packet Block (no timestamp)
        const orig = this.u32(body);
        const iface = this.interfaces[0] ?? { linkType: LINKTYPE.ETHERNET, tsDiv: 1e6 };
        const cap = Math.min(orig, len - 16);
        const data = new Uint8Array(this.buf.subarray(body + 4, body + 4 + cap));
        this.onFrame({ ts: Date.now() / 1000, linkType: iface.linkType, data, origLen: orig });
        break;
      }
      default:
        break; // name resolution, stats, custom blocks: ignored
    }
    return len;
  }
}

// ---------------------------------------------------------------------------
// pcapng writer

function pad4(n: number): number {
  return (n + 3) & ~3;
}

function block(type: number, body: Buffer): Buffer {
  const total = 12 + body.length;
  const out = Buffer.alloc(total);
  out.writeUInt32LE(type, 0);
  out.writeUInt32LE(total, 4);
  body.copy(out, 8);
  out.writeUInt32LE(total, total - 4);
  return out;
}

/** Serialize frames into a single pcapng file (one interface per link type). */
export function writePcapng(frames: RawFrame[]): Buffer {
  const parts: Buffer[] = [];
  const shb = Buffer.alloc(16);
  shb.writeUInt32LE(0x1a2b3c4d, 0);
  shb.writeUInt16LE(1, 4);
  shb.writeUInt16LE(0, 6);
  shb.writeInt32LE(-1, 8); // section length unknown
  shb.writeInt32LE(-1, 12);
  parts.push(block(PCAPNG_SHB, shb));

  const ifIndex = new Map<number, number>();
  for (const f of frames) {
    if (ifIndex.has(f.linkType)) continue;
    ifIndex.set(f.linkType, ifIndex.size);
    const idb = Buffer.alloc(8);
    idb.writeUInt16LE(f.linkType, 0);
    idb.writeUInt32LE(262144, 4);
    parts.push(block(1, idb));
  }

  for (const f of frames) {
    const padded = pad4(f.data.length);
    const epb = Buffer.alloc(20 + padded);
    const micros = Math.round(f.ts * 1e6);
    epb.writeUInt32LE(ifIndex.get(f.linkType)!, 0);
    epb.writeUInt32LE(Math.floor(micros / 4294967296), 4);
    epb.writeUInt32LE(micros % 4294967296, 8);
    epb.writeUInt32LE(f.data.length, 12);
    epb.writeUInt32LE(f.origLen, 16);
    Buffer.from(f.data).copy(epb, 20);
    parts.push(block(6, epb));
  }
  return Buffer.concat(parts);
}
