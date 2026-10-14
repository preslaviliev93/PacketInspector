// Application-layer dissectors. Each one appends a Layer to `dec` and fills
// in the protocol-specific info used by the analysis engine.

import type { Field } from '../../shared/types';
import type { Decoded, DnsRecord, TlsInfo } from './types';
import { f, u16, u32, ipv4, ipv6, mac, ascii, isPrintableText, hex } from './util';

// ---------------------------------------------------------------- DNS

const DNS_TYPES: Record<number, string> = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
  33: 'SRV', 41: 'OPT', 47: 'NSEC', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY',
};
export const DNS_RCODES: Record<number, string> = {
  0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'No such name (NXDOMAIN)',
  4: 'Not implemented', 5: 'Refused',
};

function readName(d: Uint8Array, start: number, base: number, end: number): { name: string; next: number } {
  const labels: string[] = [];
  let o = start;
  let next = -1;
  let hops = 0;
  while (o < end) {
    const len = d[o];
    if (len === 0) { o++; break; }
    if ((len & 0xc0) === 0xc0) {
      if (o + 1 >= end) throw new Error('truncated name pointer');
      if (next < 0) next = o + 2;
      o = base + (((len & 0x3f) << 8) | d[o + 1]);
      if (++hops > 32) throw new Error('name pointer loop');
      continue;
    }
    if (o + 1 + len > end) throw new Error('truncated label');
    labels.push(ascii(d, o + 1, o + 1 + len));
    o += 1 + len;
  }
  return { name: labels.join('.') || '<root>', next: next >= 0 ? next : o };
}

export function dissectDns(dec: Decoded, d: Uint8Array, base: number, end: number, label: string): boolean {
  if (end - base < 12) return false;
  const id = u16(d, base);
  const flags = u16(d, base + 2);
  const qd = u16(d, base + 4), an = u16(d, base + 6), ns = u16(d, base + 8), ar = u16(d, base + 10);
  if (qd > 64 || an > 256) return false;
  const response = (flags & 0x8000) !== 0;
  const rcode = flags & 0x0f;
  const questions: DnsRecord[] = [];
  const answers: DnsRecord[] = [];
  const qFields: Field[] = [];
  const aFields: Field[] = [];
  let o = base + 12;
  try {
    for (let i = 0; i < qd; i++) {
      const s = o;
      const { name, next } = readName(d, o, base, end);
      const type = DNS_TYPES[u16(d, next)] ?? `TYPE${u16(d, next)}`;
      o = next + 4;
      questions.push({ name, type });
      qFields.push(f(`${name}: type ${type}`, '', s, o - s));
    }
    for (let i = 0; i < an + ns + ar; i++) {
      const s = o;
      const { name, next } = readName(d, o, base, end);
      if (next + 10 > end) break;
      const typeNum = u16(d, next);
      const type = DNS_TYPES[typeNum] ?? `TYPE${typeNum}`;
      const ttl = u32(d, next + 4);
      const rdlen = u16(d, next + 8);
      const rd = next + 10;
      if (rd + rdlen > end) break;
      let data = '';
      if (typeNum === 1 && rdlen === 4) data = ipv4(d, rd);
      else if (typeNum === 28 && rdlen === 16) data = ipv6(d, rd);
      else if (typeNum === 5 || typeNum === 12 || typeNum === 2) data = readName(d, rd, base, end).name;
      else if (typeNum === 15) data = readName(d, rd + 2, base, end).name;
      else if (typeNum === 16) data = ascii(d, rd + 1, rd + 1 + d[rd]);
      else data = `${rdlen} bytes`;
      o = rd + rdlen;
      if (i < an) {
        answers.push({ name, type, ttl, data });
        aFields.push(f(`${name}: ${type} ${data}`, `TTL ${ttl}s`, s, o - s));
      }
    }
  } catch {
    dec.malformed = 'DNS name decoding failed';
  }
  const mdns = label !== 'DNS';
  const rcodeName = DNS_RCODES[rcode] ?? `rcode ${rcode}`;
  dec.dns = { id, response, rcode, rcodeName, questions, answers, mdns };
  const fields: Field[] = [
    f('Transaction ID', hex(id), base, 2),
    f('Type', response ? 'Response' : 'Query', base + 2, 2),
  ];
  if (response) fields.push(f('Result', rcodeName, base + 2, 2));
  fields.push(f('Questions', qd), f('Answers', an));
  if (qFields.length) fields.push(f('Queries', '', undefined, undefined, qFields));
  if (aFields.length) fields.push(f('Answers', '', undefined, undefined, aFields));
  const q = questions[0];
  const qs = q ? `${q.type} ${q.name}` : '';
  let info: string;
  if (!response) info = `Standard query ${hex(id)} ${qs}`;
  else if (rcode !== 0) info = `Standard query response ${hex(id)} ${qs} - ${rcodeName}`;
  else info = `Standard query response ${hex(id)} ${qs} ${answers.map((a) => `${a.type} ${a.data}`).slice(0, 3).join(' ')}`;
  dec.layers.push({ name: label, summary: response ? 'Response' : 'Query', offset: base, length: end - base, fields });
  dec.proto = label;
  dec.info = info.trim();
  return true;
}

// ---------------------------------------------------------------- HTTP

const HTTP_METHODS = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT '];

export function looksLikeHttp(d: Uint8Array, o: number, end: number): boolean {
  if (end - o < 8) return false;
  const start = ascii(d, o, Math.min(end, o + 9));
  return start.startsWith('HTTP/1.') || HTTP_METHODS.some((m) => start.startsWith(m));
}

export function dissectHttp(dec: Decoded, d: Uint8Array, o: number, end: number): void {
  // Only the header block is decoded; bodies are shown in the hex view.
  const text = ascii(d, o, Math.min(end, o + 8192));
  const headEnd = text.indexOf('\r\n\r\n');
  const lines = (headEnd >= 0 ? text.slice(0, headEnd) : text).split('\r\n');
  const first = lines[0] ?? '';
  const headers = new Map<string, string>();
  const hFields: Field[] = [];
  let pos = o + first.length + 2;
  for (const line of lines.slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) {
      const k = line.slice(0, i).trim().toLowerCase();
      let v = line.slice(i + 1).trim();
      headers.set(k, v);
      if (k === 'authorization' || k === 'proxy-authorization') v = v.split(' ')[0] + ' ••••••';
      if (k === 'cookie') v = '•••••• (hidden)';
      hFields.push(f(line.slice(0, i), v, pos, line.length));
    }
    pos += line.length + 2;
  }
  const request = !first.startsWith('HTTP/');
  const http: Decoded['http'] = { request };
  if (request) {
    const [method, uri] = first.split(' ');
    http.method = method;
    http.uri = uri;
  } else {
    const m = /^HTTP\/[\d.]+ (\d{3}) ?(.*)$/.exec(first);
    if (m) { http.status = Number(m[1]); http.reason = m[2]; }
  }
  http.host = headers.get('host');
  http.userAgent = headers.get('user-agent');
  http.contentType = headers.get('content-type');
  http.server = headers.get('server');
  const auth = headers.get('authorization');
  if (auth && /^basic /i.test(auth)) {
    try {
      const decoded = Buffer.from(auth.slice(6).trim(), 'base64').toString('utf8');
      const user = decoded.split(':')[0];
      http.basicAuthUser = user;
      dec.cred = { protocol: 'HTTP Basic Auth', detail: `username "${user}" and a password sent unencrypted` };
    } catch { /* ignore */ }
  }
  dec.http = http;
  dec.layers.push({
    name: 'HTTP',
    summary: request ? `${http.method} ${http.uri}` : `${http.status} ${http.reason ?? ''}`,
    offset: o,
    length: end - o,
    fields: [f(request ? 'Request line' : 'Status line', first, o, first.length), ...hFields],
  });
  dec.proto = 'HTTP';
  dec.info = first.slice(0, 160);
}

// ---------------------------------------------------------------- TLS

const TLS_CT: Record<number, string> = { 20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data' };
const TLS_HS: Record<number, string> = {
  1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket', 8: 'Encrypted Extensions',
  11: 'Certificate', 12: 'Server Key Exchange', 13: 'Certificate Request', 14: 'Server Hello Done',
  15: 'Certificate Verify', 16: 'Client Key Exchange', 20: 'Finished',
};
const TLS_ALERTS: Record<number, string> = {
  0: 'close notify', 10: 'unexpected message', 20: 'bad record MAC', 40: 'handshake failure',
  42: 'bad certificate', 43: 'unsupported certificate', 44: 'certificate revoked', 45: 'certificate expired',
  46: 'certificate unknown', 47: 'illegal parameter', 48: 'unknown CA', 49: 'access denied',
  50: 'decode error', 51: 'decrypt error', 70: 'protocol version', 71: 'insufficient security',
  80: 'internal error', 90: 'user canceled', 112: 'unrecognized name', 116: 'certificate required',
  120: 'no application protocol',
};

function tlsVersion(v: number): string {
  switch (v) {
    case 0x0300: return 'SSL 3.0';
    case 0x0301: return 'TLS 1.0';
    case 0x0302: return 'TLS 1.1';
    case 0x0303: return 'TLS 1.2';
    case 0x0304: return 'TLS 1.3';
    default: return hex(v);
  }
}

export function looksLikeTls(d: Uint8Array, o: number, end: number): boolean {
  return end - o >= 5 && d[o] >= 20 && d[o] <= 23 && d[o + 1] === 3 && d[o + 2] <= 4;
}

export function dissectTls(dec: Decoded, d: Uint8Array, o: number, end: number): void {
  const ct = d[o];
  const recVer = u16(d, o + 1);
  const recLen = u16(d, o + 3);
  const tls: TlsInfo = { version: tlsVersion(recVer), contentType: TLS_CT[ct] ?? String(ct) };
  const fields: Field[] = [
    f('Content type', tls.contentType, o, 1),
    f('Record version', tls.version, o + 1, 2),
    f('Length', recLen, o + 3, 2),
  ];
  const b = o + 5;
  const recEnd = Math.min(end, b + recLen);
  if (ct === 21 && recEnd - b >= 2) {
    tls.alertDesc = TLS_ALERTS[d[b + 1]] ?? `alert ${d[b + 1]}`;
    fields.push(f('Alert', `${d[b] === 2 ? 'fatal' : 'warning'}: ${tls.alertDesc}`, b, 2));
  }
  if (ct === 22 && recEnd - b >= 4) {
    const hsType = d[b];
    tls.handshake = TLS_HS[hsType] ?? (recVer >= 0x0303 ? 'Encrypted Handshake Message' : `type ${hsType}`);
    fields.push(f('Handshake', tls.handshake, b, 1));
    if (hsType === 1 || hsType === 2) parseHello(d, b, recEnd, hsType === 1, tls, fields);
  }
  dec.tls = tls;
  let info = tls.handshake ?? tls.contentType;
  if (tls.sni) info += ` (SNI=${tls.sni})`;
  if (tls.alertDesc) info += `: ${tls.alertDesc}`;
  dec.layers.push({ name: 'TLS', summary: `${tls.version} ${info}`, offset: o, length: end - o, fields });
  dec.proto = 'TLS';
  dec.info = info;
}

function parseHello(d: Uint8Array, b: number, end: number, client: boolean, tls: TlsInfo, fields: Field[]): void {
  try {
    let o = b + 4;
    const helloVer = u16(d, o);
    o += 2 + 32; // version + random
    const sidLen = d[o];
    o += 1 + sidLen;
    if (client) {
      const csLen = u16(d, o);
      fields.push(f('Cipher suites offered', csLen / 2, o, 2 + csLen));
      o += 2 + csLen;
      o += 1 + d[o]; // compression methods
    } else {
      fields.push(f('Cipher suite chosen', hex(u16(d, o)), o, 2));
      o += 3;
    }
    tls.version = tlsVersion(helloVer);
    if (o + 2 > end) return;
    const extEnd = Math.min(end, o + 2 + u16(d, o));
    o += 2;
    while (o + 4 <= extEnd) {
      const type = u16(d, o);
      const len = u16(d, o + 2);
      const e = o + 4;
      if (type === 0 && client && len > 5) {
        const nameLen = u16(d, e + 3);
        tls.sni = ascii(d, e + 5, e + 5 + nameLen);
        fields.push(f('Server Name (SNI)', tls.sni, e + 5, nameLen));
      } else if (type === 16 && len > 2) {
        const alpn: string[] = [];
        let p = e + 2;
        while (p < e + len) { alpn.push(ascii(d, p + 1, p + 1 + d[p])); p += 1 + d[p]; }
        tls.alpn = alpn;
        fields.push(f('ALPN', alpn.join(', '), e, len));
      } else if (type === 43) {
        if (client) {
          const vs: string[] = [];
          for (let p = e + 1; p + 1 < e + len; p += 2) vs.push(tlsVersion(u16(d, p)));
          fields.push(f('Supported versions', vs.join(', '), e, len));
        } else {
          tls.version = tlsVersion(u16(d, e));
          fields.push(f('Negotiated version', tls.version, e, 2));
        }
      }
      o = e + len;
    }
  } catch {
    /* truncated hello: keep what we have */
  }
}

// ---------------------------------------------------------------- DHCP

const DHCP_TYPES: Record<number, string> = {
  1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform',
};

export function dissectDhcp(dec: Decoded, d: Uint8Array, o: number, end: number): boolean {
  if (end - o < 240 || u32(d, o + 236) !== 0x63825363) return false;
  const xid = u32(d, o + 4);
  const clientMac = mac(d, o + 28);
  const yiaddr = ipv4(d, o + 16);
  const dhcp: Decoded['dhcp'] = { messageType: 'BOOTP', clientMac, xid };
  if (yiaddr !== '0.0.0.0') dhcp.yourIp = yiaddr;
  const fields: Field[] = [
    f('Transaction ID', hex(xid, 8), o + 4, 4),
    f('Client MAC', clientMac, o + 28, 6),
    f('Your (client) IP', yiaddr, o + 16, 4),
  ];
  let p = o + 240;
  while (p < end) {
    const code = d[p];
    if (code === 255) break;
    if (code === 0) { p++; continue; }
    const len = d[p + 1];
    const v = p + 2;
    switch (code) {
      case 53: dhcp.messageType = DHCP_TYPES[d[v]] ?? `type ${d[v]}`; fields.push(f('Message type', dhcp.messageType, p, 2 + len)); break;
      case 50: dhcp.requestedIp = ipv4(d, v); fields.push(f('Requested IP', dhcp.requestedIp, p, 2 + len)); break;
      case 54: dhcp.serverId = ipv4(d, v); fields.push(f('DHCP server', dhcp.serverId, p, 2 + len)); break;
      case 12: dhcp.hostname = ascii(d, v, v + len); fields.push(f('Host name', dhcp.hostname, p, 2 + len)); break;
      case 3: dhcp.router = ipv4(d, v); fields.push(f('Router (gateway)', dhcp.router, p, 2 + len)); break;
      case 6: {
        const servers: string[] = [];
        for (let i = 0; i + 4 <= len; i += 4) servers.push(ipv4(d, v + i));
        dhcp.dns = servers;
        fields.push(f('DNS servers', servers.join(', '), p, 2 + len));
        break;
      }
      case 51: dhcp.leaseSecs = u32(d, v); fields.push(f('Lease time', `${dhcp.leaseSecs}s`, p, 2 + len)); break;
    }
    p = v + len;
  }
  dec.dhcp = dhcp;
  dec.layers.push({ name: 'DHCP', summary: dhcp.messageType, offset: o, length: end - o, fields });
  dec.proto = 'DHCP';
  dec.info = `DHCP ${dhcp.messageType} - Transaction ID ${hex(xid, 8)}${dhcp.yourIp ? ` offers ${dhcp.yourIp}` : ''}`;
  return true;
}

// ---------------------------------------------------------------- Cleartext text protocols

export function dissectTextProtocol(dec: Decoded, d: Uint8Array, o: number, end: number, name: string): void {
  if (!isPrintableText(d, o, end)) return;
  const line = ascii(d, o, Math.min(end, o + 200)).split(/\r?\n/)[0];
  const upper = line.toUpperCase();
  let shown = line;
  if (/^(PASS|AUTH PLAIN|AUTH LOGIN)\b/.test(upper) || (name === 'IMAP' && / LOGIN /i.test(line))) {
    const parts = line.split(' ');
    shown = name === 'IMAP' ? `${parts.slice(0, 3).join(' ')} ••••••` : `${parts[0]} ••••••`;
    dec.cred = { protocol: name, detail: `login secret sent in clear text (${parts[0]} command)` };
  } else if (/^USER\b/.test(upper)) {
    dec.cred = { protocol: name, detail: `username "${line.slice(5).trim()}" sent in clear text` };
  }
  dec.layers.push({ name, summary: shown, offset: o, length: end - o, fields: [f('Command / response', shown, o, line.length)] });
  dec.proto = name;
  dec.info = shown;
}

export function dissectSshBanner(dec: Decoded, d: Uint8Array, o: number, end: number): boolean {
  if (end - o < 8 || ascii(d, o, o + 4) !== 'SSH-') return false;
  const banner = ascii(d, o, end).split(/\r?\n/)[0];
  dec.ssh = { banner };
  dec.layers.push({ name: 'SSH', summary: banner, offset: o, length: end - o, fields: [f('Protocol banner', banner, o, banner.length)] });
  dec.proto = 'SSH';
  dec.info = `Protocol (${banner})`;
  return true;
}
