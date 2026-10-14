// TZSP (TaZmen Sniffer Protocol) support. MikroTik's packet sniffer can stream
// captured frames to a remote host as UDP datagrams (default port 37008), each
// one wrapped in a small TZSP header. We unwrap them so the real traffic is
// analysed instead of thousands of identical "UDP to 37008" packets.

import { createSocket, type Socket } from 'node:dgram';
import { LINKTYPE, type RawFrame } from './pcap';

export const TZSP_PORT = 37008;

const ENCAPSULATION: Record<number, number> = {
  1: LINKTYPE.ETHERNET,
};

/** Decode a TZSP payload. Returns the inner frame, or null if it isn't TZSP we understand. */
export function decodeTzsp(p: Uint8Array): { linkType: number; data: Uint8Array } | null {
  if (p.length < 5 || p[0] !== 1) return null;
  const type = p[1];
  if (type !== 0 && type !== 1) return null; // received / transmitted packet
  const linkType = ENCAPSULATION[(p[2] << 8) | p[3]];
  if (linkType === undefined) return null;
  let o = 4;
  // Tagged fields end with TAG_END (1); TAG_PADDING (0) is a single byte.
  while (o < p.length) {
    const tag = p[o];
    if (tag === 1) { o++; break; }
    if (tag === 0) { o++; continue; }
    if (o + 1 >= p.length) return null;
    o += 2 + p[o + 1];
  }
  if (o >= p.length) return null;
  return { linkType, data: p.subarray(o) };
}

/**
 * If `frame` is an Ethernet/IPv4/UDP datagram carrying TZSP, return the inner
 * frame (same timestamp); otherwise return `frame` unchanged.
 */
export function unwrapTzsp(frame: RawFrame): RawFrame {
  const d = frame.data;
  let o: number;
  if (frame.linkType === LINKTYPE.ETHERNET) {
    if (d.length < 14 + 20 + 8 || d[12] !== 0x08 || d[13] !== 0x00) return frame;
    o = 14;
  } else if (frame.linkType === LINKTYPE.RAW || frame.linkType === LINKTYPE.IPV4) {
    o = 0;
  } else if (frame.linkType === LINKTYPE.LINUX_SLL) {
    if (d.length < 16 || d[14] !== 0x08 || d[15] !== 0x00) return frame;
    o = 16;
  } else if (frame.linkType === LINKTYPE.LINUX_SLL2) {
    if (d.length < 20 || d[0] !== 0x08 || d[1] !== 0x00) return frame;
    o = 20;
  } else {
    return frame;
  }
  if (d.length < o + 28 || d[o] >> 4 !== 4 || d[o + 9] !== 17) return frame;
  const ihl = (d[o] & 0x0f) * 4;
  const u = o + ihl;
  if (d.length < u + 8 || ((d[u + 2] << 8) | d[u + 3]) !== TZSP_PORT) return frame;
  const inner = decodeTzsp(d.subarray(u + 8));
  if (!inner) return frame;
  const data = new Uint8Array(inner.data);
  return { ts: frame.ts, linkType: inner.linkType, data, origLen: data.length };
}

/** Receives a MikroTik sniffer stream directly, no capture driver needed. */
export class TzspListener {
  private sock: Socket | null = null;
  /** Packets received so far (used to notice when nothing arrives). */
  received = 0;

  constructor(private onFrame: (f: RawFrame) => void, private onExit: (error?: string) => void) {}

  start(port = TZSP_PORT): void {
    const sock = createSocket({ type: 'udp4', reuseAddr: true });
    this.sock = sock;
    sock.on('message', (msg) => {
      const inner = decodeTzsp(msg);
      if (!inner) return;
      const data = new Uint8Array(inner.data);
      this.received++;
      this.onFrame({ ts: Date.now() / 1000, linkType: inner.linkType, data, origLen: data.length });
    });
    sock.on('error', (err: NodeJS.ErrnoException) => {
      this.stop();
      this.onExit(err.code === 'EADDRINUSE'
        ? `UDP port ${port} is already in use by another program (Wireshark or another sniffer?). Close it and try again.`
        : `Could not listen for the MikroTik stream: ${err.message}`);
    });
    sock.bind(port);
  }

  stop(): void {
    try { this.sock?.close(); } catch { /* already closed */ }
    this.sock = null;
  }
}
