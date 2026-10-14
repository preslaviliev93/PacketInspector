// Minimal packet builder used by the demo traffic generator and tests.
// Produces real on-the-wire bytes so demo traffic exercises the same
// dissection and analysis code as live captures.

function macBytes(m: string): number[] {
  return m.split(':').map((x) => parseInt(x, 16));
}
function ip4Bytes(ip: string): number[] {
  return ip.split('.').map(Number);
}
function be16(n: number): number[] {
  return [(n >> 8) & 0xff, n & 0xff];
}
function be32(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}
function str(s: string): number[] {
  return [...Buffer.from(s, 'latin1')];
}

function checksum(bytes: number[]): number {
  let sum = 0;
  for (let i = 0; i < bytes.length; i += 2) sum += (bytes[i] << 8) + (bytes[i + 1] ?? 0);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

export function ethernet(src: string, dst: string, type: number, payload: number[]): Uint8Array {
  return new Uint8Array([...macBytes(dst), ...macBytes(src), ...be16(type), ...payload]);
}

export function ipv4(src: string, dst: string, proto: number, payload: number[], ttl = 64, id = 0): number[] {
  const hdr = [0x45, 0, ...be16(20 + payload.length), ...be16(id), 0x40, 0, ttl, proto, 0, 0, ...ip4Bytes(src), ...ip4Bytes(dst)];
  const c = checksum(hdr);
  hdr[10] = c >> 8;
  hdr[11] = c & 0xff;
  return [...hdr, ...payload];
}

export interface TcpFlags { syn?: boolean; ack?: boolean; fin?: boolean; rst?: boolean; psh?: boolean }

export function tcp(src: string, dst: string, sport: number, dport: number, seq: number, ack: number, flags: TcpFlags, payload: number[] = [], win = 64240): number[] {
  const fl = (flags.fin ? 1 : 0) | (flags.syn ? 2 : 0) | (flags.rst ? 4 : 0) | (flags.psh ? 8 : 0) | (flags.ack ? 16 : 0);
  const opts = flags.syn ? [2, 4, ...be16(1460), 1, 3, 3, 8, 4, 2, 1, 1] : [];
  const hl = 20 + opts.length;
  const seg = [...be16(sport), ...be16(dport), ...be32(seq >>> 0), ...be32(ack >>> 0), (hl / 4) << 4, fl, ...be16(win), 0, 0, 0, 0, ...opts, ...payload];
  const pseudo = [...ip4Bytes(src), ...ip4Bytes(dst), 0, 6, ...be16(seg.length)];
  const c = checksum([...pseudo, ...seg]);
  seg[16] = c >> 8;
  seg[17] = c & 0xff;
  return seg;
}

export function udp(sport: number, dport: number, payload: number[]): number[] {
  return [...be16(sport), ...be16(dport), ...be16(8 + payload.length), 0, 0, ...payload];
}

function dnsName(name: string): number[] {
  const out: number[] = [];
  for (const label of name.split('.')) out.push(label.length, ...str(label));
  out.push(0);
  return out;
}

export function dnsQuery(id: number, name: string, type = 1): number[] {
  return [...be16(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, ...dnsName(name), ...be16(type), 0, 1];
}

export function dnsResponse(id: number, name: string, ips: string[], rcode = 0, cname?: string): number[] {
  const answers: number[] = [];
  let count = 0;
  let target = 0xc00c; // pointer to the question name
  if (cname && rcode === 0) {
    const cn = dnsName(cname);
    answers.push(...be16(target), 0, 5, 0, 1, ...be32(300), ...be16(cn.length), ...cn);
    count++;
    target = 0xc000 | (12 + dnsName(name).length + 4 + 12);
  }
  if (rcode === 0) {
    for (const ip of ips) {
      answers.push(...be16(target), 0, 1, 0, 1, ...be32(60), 0, 4, ...ip4Bytes(ip));
      count++;
    }
  }
  return [...be16(id), 0x81, 0x80 | rcode, 0, 1, ...be16(count), 0, 0, 0, 0, ...dnsName(name), 0, 1, 0, 1, ...answers];
}

export function arp(op: 1 | 2, senderMac: string, senderIp: string, targetMac: string, targetIp: string): number[] {
  return [0, 1, 8, 0, 6, 4, 0, op, ...macBytes(senderMac), ...ip4Bytes(senderIp), ...macBytes(targetMac), ...ip4Bytes(targetIp)];
}

export function icmpEcho(reply: boolean, id: number, seq: number): number[] {
  const body = [reply ? 0 : 8, 0, 0, 0, ...be16(id), ...be16(seq), ...str('abcdefghijklmnopqrstuvwabcdefghi')];
  const c = checksum(body);
  body[2] = c >> 8;
  body[3] = c & 0xff;
  return body;
}

export function icmpUnreachable(code: number, original: number[]): number[] {
  const body = [3, code, 0, 0, 0, 0, 0, 0, ...original.slice(0, 28)];
  const c = checksum(body);
  body[2] = c >> 8;
  body[3] = c & 0xff;
  return body;
}

export function tlsClientHello(sni: string): number[] {
  const name = str(sni);
  const sniExt = [0, 0, ...be16(name.length + 5), ...be16(name.length + 3), 0, ...be16(name.length), ...name];
  const alpn = [0, 16, 0, 14, 0, 12, 2, ...str('h2'), 8, ...str('http/1.1')];
  const versions = [0, 43, 0, 5, 4, 3, 4, 3, 3];
  const exts = [...sniExt, ...alpn, ...versions];
  const random = Array.from({ length: 32 }, (_, i) => (i * 37) & 0xff);
  const ciphers = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f];
  const hello = [3, 3, ...random, 0, ...be16(ciphers.length), ...ciphers, 1, 0, ...be16(exts.length), ...exts];
  const hs = [1, 0, ...be16(hello.length), ...hello];
  return [22, 3, 1, ...be16(hs.length), ...hs];
}

export function tlsServerHello(version: 'TLS 1.3' | 'TLS 1.0' = 'TLS 1.3'): number[] {
  const random = Array.from({ length: 32 }, (_, i) => (i * 53) & 0xff);
  const exts = version === 'TLS 1.3' ? [0, 43, 0, 2, 3, 4] : [];
  const legacy = version === 'TLS 1.0' ? [3, 1] : [3, 3];
  const hello = [...legacy, ...random, 0, 0x13, 0x01, 0, ...be16(exts.length), ...exts];
  const hs = [2, 0, ...be16(hello.length), ...hello];
  return [22, ...legacy, ...be16(hs.length), ...hs];
}

export function tlsAppData(len: number): number[] {
  return [23, 3, 3, ...be16(len), ...Array.from({ length: len }, (_, i) => (i * 131 + 7) & 0xff)];
}

export function text(s: string): number[] {
  return str(s);
}

export function dhcp(type: number, xid: number, clientMac: string, yiaddr = '0.0.0.0', opts: { server?: string; requested?: string; hostname?: string; router?: string; dns?: string[]; lease?: number } = {}): number[] {
  const body = new Array(240).fill(0);
  body[0] = type === 1 || type === 3 ? 1 : 2;
  body[1] = 1; body[2] = 6;
  be32(xid).forEach((b, i) => (body[4 + i] = b));
  ip4Bytes(yiaddr).forEach((b, i) => (body[16 + i] = b));
  macBytes(clientMac).forEach((b, i) => (body[28 + i] = b));
  [0x63, 0x82, 0x53, 0x63].forEach((b, i) => (body[236 + i] = b));
  const o: number[] = [53, 1, type];
  if (opts.server) o.push(54, 4, ...ip4Bytes(opts.server));
  if (opts.requested) o.push(50, 4, ...ip4Bytes(opts.requested));
  if (opts.hostname) o.push(12, opts.hostname.length, ...str(opts.hostname));
  if (opts.router) o.push(3, 4, ...ip4Bytes(opts.router));
  if (opts.dns) o.push(6, opts.dns.length * 4, ...opts.dns.flatMap(ip4Bytes));
  if (opts.lease) o.push(51, 4, ...be32(opts.lease));
  o.push(255);
  return [...body, ...o];
}
