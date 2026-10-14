import type { Field } from '../../shared/types';

export function f(label: string, value: string | number, offset?: number, length?: number, children?: Field[]): Field {
  const fld: Field = { label, value: String(value) };
  if (offset !== undefined) fld.offset = offset;
  if (length !== undefined) fld.length = length;
  if (children && children.length) fld.children = children;
  return fld;
}

export function u16(d: Uint8Array, o: number): number {
  return (d[o] << 8) | d[o + 1];
}

export function u32(d: Uint8Array, o: number): number {
  return ((d[o] << 24) >>> 0) + (d[o + 1] << 16) + (d[o + 2] << 8) + d[o + 3];
}

export function hex(n: number, width = 4): string {
  return '0x' + n.toString(16).padStart(width, '0');
}

export function mac(d: Uint8Array, o: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) parts.push(d[o + i].toString(16).padStart(2, '0'));
  return parts.join(':');
}

export function ipv4(d: Uint8Array, o: number): string {
  return `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;
}

/** RFC 5952 textual form: lowercase, longest zero run compressed. */
export function ipv6(d: Uint8Array, o: number): string {
  const words: number[] = [];
  for (let i = 0; i < 8; i++) words.push(u16(d, o + i * 2));
  let bestStart = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (words[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLen && j - i > 1) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hexw = words.map((w) => w.toString(16));
  if (bestStart < 0) return hexw.join(':');
  const head = hexw.slice(0, bestStart).join(':');
  const tail = hexw.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

export function ascii(d: Uint8Array, start: number, end: number): string {
  let s = '';
  for (let i = start; i < end && i < d.length; i++) s += String.fromCharCode(d[i]);
  return s;
}

export function isPrintableText(d: Uint8Array, start: number, end: number): boolean {
  const stop = Math.min(end, d.length, start + 64);
  if (stop <= start) return false;
  for (let i = start; i < stop; i++) {
    const c = d[i];
    if (c === 9 || c === 10 || c === 13) continue;
    if (c < 32 || c > 126) return false;
  }
  return true;
}

export type IpScope = 'loopback' | 'private' | 'link-local' | 'multicast' | 'broadcast' | 'public' | 'unspecified';

export function ipScope(ip: string): IpScope {
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    if (l === '::1') return 'loopback';
    if (l === '::') return 'unspecified';
    if (l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb')) return 'link-local';
    if (l.startsWith('ff')) return 'multicast';
    if (l.startsWith('fc') || l.startsWith('fd')) return 'private';
    return 'public';
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return 'public';
  if (p[0] === 127) return 'loopback';
  if (p[0] === 0) return 'unspecified';
  if (ip === '255.255.255.255') return 'broadcast';
  if (p[0] >= 224 && p[0] <= 239) return 'multicast';
  if (p[0] === 169 && p[1] === 254) return 'link-local';
  if (p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168)) return 'private';
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return 'private'; // CGNAT
  return 'public';
}

export function isLocal(ip: string): boolean {
  const s = ipScope(ip);
  return s !== 'public';
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
