// Watch rules: parsing, validation and matching. Shared by the engine (which
// matches traffic) and the UI (which validates what the user types), so both
// always agree on what a rule means.

import type { WatchKind, WatchRule } from './types';

export const WATCH_KIND_LABEL: Record<WatchKind, string> = {
  ip: 'IP address', network: 'Network', host: 'Host name', port: 'Port',
};

// ------------------------------------------------------------------ addresses as numbers

function parseV4(s: string): bigint | null {
  const p = s.split('.');
  if (p.length !== 4) return null;
  let n = 0n;
  for (const x of p) {
    if (!/^\d{1,3}$/.test(x) || Number(x) > 255) return null;
    n = (n << 8n) | BigInt(Number(x));
  }
  return n;
}

function parseV6(s: string): bigint | null {
  let str = s.toLowerCase();
  const pct = str.indexOf('%');
  if (pct >= 0) str = str.slice(0, pct);
  // Embedded IPv4 tail (::ffff:1.2.3.4)
  const v4tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(str);
  if (v4tail) {
    const v4 = parseV4(v4tail[1]);
    if (v4 === null) return null;
    str = str.slice(0, -v4tail[1].length) + ((v4 >> 16n) & 0xffffn).toString(16) + ':' + (v4 & 0xffffn).toString(16);
  }
  const halves = str.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const words = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (words.length !== 8) return null;
  let n = 0n;
  for (const w of words) {
    if (!/^[0-9a-f]{1,4}$/.test(w)) return null;
    n = (n << 16n) | BigInt(parseInt(w, 16));
  }
  return n;
}

export function parseIp(s: string): { v6: boolean; n: bigint } | null {
  const t = s.trim();
  if (t.includes(':')) { const n = parseV6(t); return n === null ? null : { v6: true, n }; }
  const n = parseV4(t);
  return n === null ? null : { v6: false, n };
}

export interface Cidr { v6: boolean; base: bigint; mask: bigint; bits: number }

export function parseCidr(s: string): Cidr | null {
  const [addr, bitsStr] = s.trim().split('/');
  const ip = parseIp(addr);
  if (!ip) return null;
  const max = ip.v6 ? 128 : 32;
  const bits = bitsStr === undefined ? max : Number(bitsStr);
  if (!Number.isInteger(bits) || bits < 0 || bits > max) return null;
  const all = (1n << BigInt(max)) - 1n;
  const mask = bits === 0 ? 0n : (all << BigInt(max - bits)) & all;
  return { v6: ip.v6, base: ip.n & mask, mask, bits };
}

export function inCidr(ip: string, c: Cidr): boolean {
  const p = parseIp(ip);
  return !!p && p.v6 === c.v6 && (p.n & c.mask) === c.base;
}

// ------------------------------------------------------------------ validation

/** Normalise what the user typed, or explain why it isn't valid. */
export function normalizeRuleValue(kind: WatchKind, raw: string): { value: string } | { error: string } {
  const v = raw.trim();
  if (!v) return { error: 'Enter a value.' };
  switch (kind) {
    case 'ip': {
      const p = parseIp(v);
      return p ? { value: v.toLowerCase() } : { error: 'That is not a valid IPv4 or IPv6 address, e.g. 203.0.113.7' };
    }
    case 'network': {
      if (!v.includes('/')) return { error: 'Add the prefix length, e.g. 10.20.0.0/16 or 2001:db8::/32' };
      const c = parseCidr(v);
      return c ? { value: v.toLowerCase() } : { error: 'That is not a valid network, e.g. 10.20.0.0/16 or 2001:db8::/32' };
    }
    case 'host': {
      const h = v.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
      return /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$/.test(h) ? { value: h } : { error: 'Enter a host name like example.com (it also covers sub-domains).' };
    }
    case 'port': {
      const n = Number(v);
      return Number.isInteger(n) && n >= 1 && n <= 65535 ? { value: String(n) } : { error: 'Enter a port number between 1 and 65535.' };
    }
  }
}

// ------------------------------------------------------------------ matching

export interface WatchSubject {
  src?: string;
  dst?: string;
  sport?: number;
  dport?: number;
  /** Host names involved in this packet: DNS question, TLS SNI, HTTP Host, and resolved names of src/dst. */
  hostNames: { name: string; via: string }[];
}

export interface WatchMatch {
  rule: WatchRule;
  /** What matched, e.g. "203.0.113.77", "files.example.com", "port 3389". */
  matched: string;
  /** How it matched, for the alert text ("DNS lookup", "TLS server name", "address"...). */
  via: string;
}

interface Compiled { rule: WatchRule; ip?: bigint; ipV6?: boolean; cidr?: Cidr; host?: string; port?: number }

export class WatchMatcher {
  private compiled: Compiled[] = [];

  set(rules: WatchRule[]): void {
    this.compiled = [];
    for (const rule of rules) {
      if (!rule.enabled) continue;
      const c: Compiled = { rule };
      if (rule.kind === 'ip') { const p = parseIp(rule.value); if (!p) continue; c.ip = p.n; c.ipV6 = p.v6; }
      else if (rule.kind === 'network') { const n = parseCidr(rule.value); if (!n) continue; c.cidr = n; }
      else if (rule.kind === 'host') c.host = rule.value.toLowerCase();
      else c.port = Number(rule.value);
      this.compiled.push(c);
    }
  }

  get empty(): boolean {
    return this.compiled.length === 0;
  }

  match(s: WatchSubject): WatchMatch[] {
    const out: WatchMatch[] = [];
    for (const c of this.compiled) {
      if (c.ip !== undefined) {
        for (const a of [s.src, s.dst]) {
          const p = a ? parseIp(a) : null;
          if (p && p.v6 === c.ipV6 && p.n === c.ip) { out.push({ rule: c.rule, matched: a!, via: 'address' }); break; }
        }
      } else if (c.cidr) {
        for (const a of [s.src, s.dst]) {
          if (a && inCidr(a, c.cidr)) { out.push({ rule: c.rule, matched: a, via: 'address' }); break; }
        }
      } else if (c.host) {
        const h = s.hostNames.find((x) => x.name === c.host || x.name.endsWith('.' + c.host));
        if (h) out.push({ rule: c.rule, matched: h.name, via: h.via });
      } else if (c.port !== undefined) {
        if (s.sport === c.port || s.dport === c.port) out.push({ rule: c.rule, matched: `port ${c.port}`, via: 'port' });
      }
    }
    return out;
  }
}
