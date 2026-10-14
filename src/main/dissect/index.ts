// Frame dissector: link layer -> network -> transport -> application.
// Pure function of the frame bytes; all stateful analysis lives in ../analysis.

import type { Field } from '../../shared/types';
import { LINKTYPE, type RawFrame } from '../capture/pcap';
import type { Decoded } from './types';
import { f, u16, u32, hex, mac, ipv4, ipv6 } from './util';
import { service } from './services';
import {
  dissectDns, dissectHttp, dissectTls, dissectDhcp, dissectTextProtocol, dissectSshBanner,
  looksLikeHttp, looksLikeTls,
} from './app';
import { dissectDb, sniffDb, DB_PORTS } from './db';

export type { Decoded } from './types';

const ETHERTYPES: Record<number, string> = {
  0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: '802.1Q VLAN', 0x88cc: 'LLDP', 0x888e: 'EAPOL',
};

export function dissect(frame: RawFrame): Decoded {
  const d = frame.data;
  const dec: Decoded = { layers: [], proto: 'Unknown', info: '' };
  dec.layers.push({
    name: 'Frame',
    summary: `${frame.origLen} bytes on wire, ${d.length} bytes captured`,
    offset: 0,
    length: d.length,
    fields: [
      f('Arrival time', new Date(frame.ts * 1000).toISOString()),
      f('Frame length', `${frame.origLen} bytes`),
      f('Capture length', `${d.length} bytes`),
      f('Link type', linkTypeName(frame.linkType)),
    ],
  });
  try {
    switch (frame.linkType) {
      case LINKTYPE.ETHERNET: ethernet(dec, d, 0); break;
      case LINKTYPE.LINUX_SLL: sll(dec, d); break;
      case LINKTYPE.LINUX_SLL2: sll2(dec, d); break;
      case LINKTYPE.NULL:
      case LINKTYPE.LOOP: nullLink(dec, d, frame.linkType); break;
      case LINKTYPE.RAW:
      case LINKTYPE.IPV4:
      case LINKTYPE.IPV6: rawIp(dec, d, 0); break;
      default:
        dec.proto = 'Link ' + frame.linkType;
        dec.info = `Unsupported link type ${frame.linkType}`;
    }
  } catch (e) {
    dec.malformed = (e as Error).message;
  }
  if (dec.malformed && !dec.info) dec.info = `Malformed packet: ${dec.malformed}`;
  return dec;
}

function linkTypeName(lt: number): string {
  switch (lt) {
    case LINKTYPE.ETHERNET: return 'Ethernet';
    case LINKTYPE.LINUX_SLL: return 'Linux cooked capture';
    case LINKTYPE.LINUX_SLL2: return 'Linux cooked capture v2';
    case LINKTYPE.NULL: return 'Loopback (BSD/Npcap)';
    case LINKTYPE.LOOP: return 'Loopback (OpenBSD)';
    case LINKTYPE.RAW: case LINKTYPE.IPV4: case LINKTYPE.IPV6: return 'Raw IP';
    default: return `DLT ${lt}`;
  }
}

function need(d: Uint8Array, end: number, what: string): void {
  if (d.length < end) throw new Error(`truncated ${what}`);
}

// ---------------------------------------------------------------- link layer

function ethernet(dec: Decoded, d: Uint8Array, o: number): void {
  need(d, o + 14, 'Ethernet header');
  dec.linkDst = mac(d, o);
  dec.linkSrc = mac(d, o + 6);
  let type = u16(d, o + 12);
  let p = o + 14;
  const fields: Field[] = [
    f('Destination', dec.linkDst + (dec.linkDst === 'ff:ff:ff:ff:ff:ff' ? ' (broadcast)' : ''), o, 6),
    f('Source', dec.linkSrc, o + 6, 6),
  ];
  while (type === 0x8100 || type === 0x88a8) {
    need(d, p + 4, 'VLAN tag');
    fields.push(f('VLAN ID', u16(d, p) & 0x0fff, p, 2));
    type = u16(d, p + 2);
    p += 4;
  }
  fields.push(f('Type', `${ETHERTYPES[type] ?? 'Unknown'} (${hex(type)})`, p - 2, 2));
  dec.layers.push({ name: 'Ethernet II', summary: `${dec.linkSrc} → ${dec.linkDst}`, offset: o, length: p - o, fields });
  dec.src = dec.linkSrc;
  dec.dst = dec.linkDst;
  ethertype(dec, d, p, type);
}

function ethertype(dec: Decoded, d: Uint8Array, p: number, type: number): void {
  switch (type) {
    case 0x0800: ip4(dec, d, p); break;
    case 0x86dd: ip6(dec, d, p); break;
    case 0x0806: arp(dec, d, p); break;
    default:
      dec.proto = ETHERTYPES[type] ?? `Ethertype ${hex(type)}`;
      dec.info = type < 0x0600 ? 'IEEE 802.3 / LLC frame' : `Ethertype ${hex(type)}`;
  }
}

function sll(dec: Decoded, d: Uint8Array): void {
  need(d, 16, 'Linux cooked header');
  const halen = u16(d, 4);
  if (halen === 6) dec.linkSrc = mac(d, 6);
  const type = u16(d, 14);
  dec.layers.push({
    name: 'Linux cooked capture', summary: dec.linkSrc ?? '', offset: 0, length: 16,
    fields: [f('Packet type', u16(d, 0), 0, 2), f('Protocol', hex(type), 14, 2)],
  });
  ethertype(dec, d, 16, type);
}

function sll2(dec: Decoded, d: Uint8Array): void {
  need(d, 20, 'Linux cooked v2 header');
  const type = u16(d, 0);
  if (d[11] === 6) dec.linkSrc = mac(d, 12);
  dec.layers.push({
    name: 'Linux cooked capture v2', summary: dec.linkSrc ?? '', offset: 0, length: 20,
    fields: [f('Protocol', hex(type), 0, 2), f('Interface index', u32(d, 4), 4, 4)],
  });
  ethertype(dec, d, 20, type);
}

function nullLink(dec: Decoded, d: Uint8Array, lt: number): void {
  need(d, 4, 'loopback header');
  // DLT_NULL family is in host byte order of the capturing machine.
  const fam = lt === LINKTYPE.LOOP ? u32(d, 0) : d[0] !== 0 ? d[0] | (d[1] << 8) : u32(d, 0);
  dec.layers.push({ name: 'Loopback', summary: `family ${fam}`, offset: 0, length: 4, fields: [f('Family', fam, 0, 4)] });
  if (fam === 2) ip4(dec, d, 4);
  else if (fam === 24 || fam === 28 || fam === 30) ip6(dec, d, 4);
  else { dec.proto = 'Loopback'; dec.info = `Address family ${fam}`; }
}

function rawIp(dec: Decoded, d: Uint8Array, o: number): void {
  need(d, o + 1, 'IP header');
  const v = d[o] >> 4;
  if (v === 4) ip4(dec, d, o);
  else if (v === 6) ip6(dec, d, o);
  else { dec.proto = 'Raw'; dec.info = `Unknown IP version ${v}`; }
}

function arp(dec: Decoded, d: Uint8Array, o: number): void {
  need(d, o + 28, 'ARP');
  const op = u16(d, o + 6);
  const info = {
    op: op === 1 ? 'request' : op === 2 ? 'reply' : 'other',
    senderMac: mac(d, o + 8), senderIp: ipv4(d, o + 14),
    targetMac: mac(d, o + 18), targetIp: ipv4(d, o + 24),
  } as const;
  dec.arp = { ...info };
  dec.layers.push({
    name: 'ARP', summary: info.op, offset: o, length: 28,
    fields: [
      f('Operation', `${info.op} (${op})`, o + 6, 2),
      f('Sender MAC', info.senderMac, o + 8, 6),
      f('Sender IP', info.senderIp, o + 14, 4),
      f('Target MAC', info.targetMac, o + 18, 6),
      f('Target IP', info.targetIp, o + 24, 4),
    ],
  });
  dec.proto = 'ARP';
  dec.src = info.senderIp;
  dec.dst = op === 1 ? info.targetIp : info.targetIp;
  if (op === 1) {
    dec.info = info.senderIp === info.targetIp
      ? `Gratuitous ARP for ${info.senderIp}`
      : `Who has ${info.targetIp}? Tell ${info.senderIp}`;
  } else if (op === 2) {
    dec.info = `${info.senderIp} is at ${info.senderMac}`;
  } else {
    dec.info = `ARP op ${op}`;
  }
}

// ---------------------------------------------------------------- network layer

const IP_PROTOS: Record<number, string> = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 132: 'SCTP' };

function ip4(dec: Decoded, d: Uint8Array, o: number): void {
  need(d, o + 20, 'IPv4 header');
  const ihl = (d[o] & 0x0f) * 4;
  const total = u16(d, o + 2);
  const flagsFrag = u16(d, o + 6);
  const fragOffset = (flagsFrag & 0x1fff) * 8;
  const mf = (flagsFrag & 0x2000) !== 0;
  const df = (flagsFrag & 0x4000) !== 0;
  dec.ipVersion = 4;
  dec.ttl = d[o + 8];
  dec.ipProto = d[o + 9];
  dec.src = ipv4(d, o + 12);
  dec.dst = ipv4(d, o + 16);
  dec.fragment = fragOffset > 0 || mf;
  // Total length may be 0 with TSO offload; fall back to captured bytes.
  const end = total >= ihl ? Math.min(d.length, o + total) : d.length;
  dec.layers.push({
    name: 'Internet Protocol v4', summary: `${dec.src} → ${dec.dst}`, offset: o, length: ihl,
    fields: [
      f('Header length', `${ihl} bytes`, o, 1),
      f('Total length', total, o + 2, 2),
      f('Identification', hex(u16(d, o + 4)), o + 4, 2),
      f('Flags', `${df ? "Don't fragment" : ''}${mf ? ' More fragments' : ''}`.trim() || 'none', o + 6, 2),
      f('Fragment offset', fragOffset, o + 6, 2),
      f('Time to live', dec.ttl, o + 8, 1),
      f('Protocol', `${IP_PROTOS[dec.ipProto] ?? 'Unknown'} (${dec.ipProto})`, o + 9, 1),
      f('Header checksum', hex(u16(d, o + 10)), o + 10, 2),
      f('Source address', dec.src, o + 12, 4),
      f('Destination address', dec.dst, o + 16, 4),
    ],
  });
  if (fragOffset > 0) {
    dec.proto = 'IPv4';
    dec.info = `Fragmented IP protocol (proto=${IP_PROTOS[dec.ipProto] ?? dec.ipProto}, off=${fragOffset})`;
    return;
  }
  transport(dec, d, o + ihl, end, dec.ipProto);
}

function ip6(dec: Decoded, d: Uint8Array, o: number): void {
  need(d, o + 40, 'IPv6 header');
  const plen = u16(d, o + 4);
  let next = d[o + 6];
  dec.ipVersion = 6;
  dec.ttl = d[o + 7];
  dec.src = ipv6(d, o + 8);
  dec.dst = ipv6(d, o + 24);
  const end = plen ? Math.min(d.length, o + 40 + plen) : d.length;
  const fields: Field[] = [
    f('Payload length', plen, o + 4, 2),
    f('Next header', `${IP_PROTOS[next] ?? next}`, o + 6, 1),
    f('Hop limit', dec.ttl, o + 7, 1),
    f('Source address', dec.src, o + 8, 16),
    f('Destination address', dec.dst, o + 24, 16),
  ];
  let p = o + 40;
  // Walk extension headers.
  while ([0, 43, 60, 44, 51].includes(next) && p + 8 <= end) {
    const hdrNext = d[p];
    const len = next === 44 ? 8 : next === 51 ? (d[p + 1] + 2) * 4 : (d[p + 1] + 1) * 8;
    fields.push(f('Extension header', next === 44 ? 'Fragment' : next === 0 ? 'Hop-by-hop' : next === 43 ? 'Routing' : next === 60 ? 'Destination options' : 'AH', p, len));
    if (next === 44 && (u16(d, p + 2) & 0xfff8) !== 0) dec.fragment = true;
    next = hdrNext;
    p += len;
  }
  dec.ipProto = next;
  dec.layers.push({ name: 'Internet Protocol v6', summary: `${dec.src} → ${dec.dst}`, offset: o, length: p - o, fields });
  if (dec.fragment) { dec.proto = 'IPv6'; dec.info = 'IPv6 fragment'; return; }
  transport(dec, d, p, end, next);
}

// ---------------------------------------------------------------- transport layer

function transport(dec: Decoded, d: Uint8Array, o: number, end: number, proto: number): void {
  switch (proto) {
    case 6: tcp(dec, d, o, end); break;
    case 17: udp(dec, d, o, end); break;
    case 1: icmp(dec, d, o, end, false); break;
    case 58: icmp(dec, d, o, end, true); break;
    default:
      dec.proto = IP_PROTOS[proto] ?? `IP proto ${proto}`;
      dec.info = `${dec.proto} packet`;
  }
}

function tcp(dec: Decoded, d: Uint8Array, o: number, end: number): void {
  need(d, o + 20, 'TCP header');
  const sport = u16(d, o), dport = u16(d, o + 2);
  const seq = u32(d, o + 4), ack = u32(d, o + 8);
  const hl = (d[o + 12] >> 4) * 4;
  const fl = d[o + 13];
  const flags = {
    fin: !!(fl & 1), syn: !!(fl & 2), rst: !!(fl & 4), psh: !!(fl & 8), ack: !!(fl & 16), urg: !!(fl & 32),
  };
  const window = u16(d, o + 14);
  const payloadOffset = Math.min(o + hl, end);
  const payloadLen = Math.max(0, end - payloadOffset);
  const info: Decoded['tcp'] = { sport, dport, seq, ack, flags, window, payloadOffset, payloadLen };
  const optFields: Field[] = [];
  for (let p = o + 20; p < o + hl && p < end; ) {
    const kind = d[p];
    if (kind === 0) break;
    if (kind === 1) { p++; continue; }
    const len = d[p + 1];
    if (len < 2) break;
    if (kind === 2 && len === 4) { info.mss = u16(d, p + 2); optFields.push(f('Max segment size', info.mss, p, len)); }
    else if (kind === 3 && len === 3) { info.wscale = d[p + 2]; optFields.push(f('Window scale', `${info.wscale} (×${1 << info.wscale})`, p, len)); }
    else if (kind === 4) optFields.push(f('SACK permitted', 'yes', p, len));
    else if (kind === 5) optFields.push(f('SACK blocks', (len - 2) / 8, p, len));
    else if (kind === 8) optFields.push(f('Timestamps', `val ${u32(d, p + 2)} echo ${u32(d, p + 6)}`, p, len));
    p += len;
  }
  dec.tcp = info;
  const flagStr = flagsString(flags);
  const fields: Field[] = [
    f('Source port', sport, o, 2),
    f('Destination port', dport, o + 2, 2),
    f('Sequence number', seq, o + 4, 4),
    f('Acknowledgment number', ack, o + 8, 4),
    f('Header length', `${hl} bytes`, o + 12, 1),
    f('Flags', flagStr, o + 13, 1, [
      f('SYN (open connection)', flags.syn ? 'set' : 'not set'),
      f('ACK (acknowledges data)', flags.ack ? 'set' : 'not set'),
      f('PSH (deliver now)', flags.psh ? 'set' : 'not set'),
      f('FIN (finish)', flags.fin ? 'set' : 'not set'),
      f('RST (reset/abort)', flags.rst ? 'set' : 'not set'),
    ]),
    f('Window size', window, o + 14, 2),
    f('Checksum', hex(u16(d, o + 16)), o + 16, 2),
  ];
  if (optFields.length) fields.push(f('Options', '', o + 20, hl - 20, optFields));
  if (payloadLen) fields.push(f('Payload', `${payloadLen} bytes`, payloadOffset, payloadLen));
  dec.layers.push({ name: 'Transmission Control Protocol', summary: `${sport} → ${dport} [${flagStr}]`, offset: o, length: hl, fields });
  dec.proto = 'TCP';
  dec.info = `${sport} → ${dport} [${flagStr}] Seq=${seq}${flags.ack ? ` Ack=${ack}` : ''} Win=${window} Len=${payloadLen}`;
  if (payloadLen > 0) tcpApp(dec, d, payloadOffset, end, sport, dport);
}

export function flagsString(fl: { syn: boolean; ack: boolean; fin: boolean; rst: boolean; psh: boolean; urg: boolean }): string {
  const out: string[] = [];
  if (fl.syn) out.push('SYN');
  if (fl.fin) out.push('FIN');
  if (fl.rst) out.push('RST');
  if (fl.psh) out.push('PSH');
  if (fl.ack) out.push('ACK');
  if (fl.urg) out.push('URG');
  return out.join(', ') || 'none';
}

function tcpApp(dec: Decoded, d: Uint8Array, o: number, end: number, sport: number, dport: number): void {
  const has = (p: number) => sport === p || dport === p;
  if (looksLikeTls(d, o, end)) return dissectTls(dec, d, o, end);
  // Databases: by well-known port, or by handshake signature on any port.
  const dbSystem = DB_PORTS[dport] ?? DB_PORTS[sport];
  if (dbSystem && dissectDb(dec, d, o, end, dbSystem, DB_PORTS[dport] === dbSystem)) return;
  const sniffed = sniffDb(d, o, end);
  if (sniffed && dissectDb(dec, d, o, end, sniffed, sniffed === 'PostgreSQL')) return;
  if (looksLikeHttp(d, o, end)) return dissectHttp(dec, d, o, end);
  if (dissectSshBanner(dec, d, o, end)) return;
  if (has(53) && end - o > 14) { if (dissectDns(dec, d, o + 2, end, 'DNS')) return; }
  for (const [port, name] of [[21, 'FTP'], [110, 'POP3'], [143, 'IMAP'], [25, 'SMTP'], [587, 'SMTP'], [23, 'Telnet']] as const) {
    if (has(port)) return dissectTextProtocol(dec, d, o, end, name);
  }
  const svc = service('TCP', Math.min(sport, dport)) ?? service('TCP', Math.max(sport, dport));
  if (svc && !['HTTP', 'HTTPS', 'DNS'].includes(svc.name)) {
    dec.proto = svc.name;
  }
}

function udp(dec: Decoded, d: Uint8Array, o: number, end: number): void {
  need(d, o + 8, 'UDP header');
  const sport = u16(d, o), dport = u16(d, o + 2);
  const len = u16(d, o + 4);
  const uend = len >= 8 ? Math.min(end, o + len) : end;
  dec.udp = { sport, dport, payloadOffset: o + 8, payloadLen: Math.max(0, uend - o - 8) };
  dec.layers.push({
    name: 'User Datagram Protocol', summary: `${sport} → ${dport}`, offset: o, length: 8,
    fields: [
      f('Source port', sport, o, 2), f('Destination port', dport, o + 2, 2),
      f('Length', len, o + 4, 2), f('Checksum', hex(u16(d, o + 6)), o + 6, 2),
    ],
  });
  dec.proto = 'UDP';
  dec.info = `${sport} → ${dport} Len=${dec.udp.payloadLen}`;
  const p = o + 8;
  const has = (x: number) => sport === x || dport === x;
  if (has(53) && dissectDns(dec, d, p, uend, 'DNS')) return;
  if (has(5353) && dissectDns(dec, d, p, uend, 'mDNS')) return;
  if (has(5355) && dissectDns(dec, d, p, uend, 'LLMNR')) return;
  if ((has(67) || has(68)) && dissectDhcp(dec, d, p, uend)) return;
  if (has(443) && uend > p) {
    const long = (d[p] & 0x80) !== 0;
    dec.quic = { longHeader: long };
    if (long && uend - p >= 5) dec.quic.version = hex(u32(d, p + 1), 8);
    dec.layers.push({ name: 'QUIC', summary: long ? 'Long header (handshake)' : 'Short header (data)', offset: p, length: uend - p, fields: [f('Header form', long ? 'Long' : 'Short', p, 1)] });
    dec.proto = 'QUIC';
    dec.info = `QUIC ${long ? 'handshake' : 'protected payload'}`;
    return;
  }
  const svc = service('UDP', dport) ?? service('UDP', sport);
  if (svc) dec.proto = svc.name;
}

const ICMP4_TYPES: Record<number, string> = {
  0: 'Echo reply', 3: 'Destination unreachable', 5: 'Redirect', 8: 'Echo request', 11: 'Time exceeded',
};
const ICMP6_TYPES: Record<number, string> = {
  1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 128: 'Echo request', 129: 'Echo reply',
  133: 'Router solicitation', 134: 'Router advertisement', 135: 'Neighbor solicitation', 136: 'Neighbor advertisement', 143: 'MLDv2 report',
};
const UNREACH_CODES: Record<number, string> = {
  0: 'network unreachable', 1: 'host unreachable', 2: 'protocol unreachable', 3: 'port unreachable',
  4: 'fragmentation needed', 9: 'network administratively prohibited', 10: 'host administratively prohibited', 13: 'communication administratively prohibited',
};

function icmp(dec: Decoded, d: Uint8Array, o: number, end: number, v6: boolean): void {
  need(d, o + 4, 'ICMP header');
  const type = d[o], code = d[o + 1];
  const typeName = (v6 ? ICMP6_TYPES : ICMP4_TYPES)[type] ?? `Type ${type}`;
  const info: Decoded['icmp'] = { v6, type, code, typeName };
  const fields: Field[] = [f('Type', `${type} (${typeName})`, o, 1), f('Code', code, o + 1, 1)];
  const echo = v6 ? type === 128 || type === 129 : type === 0 || type === 8;
  const errorMsg = v6 ? type >= 1 && type <= 3 : type === 3 || type === 11;
  if (echo && end - o >= 8) {
    info.echoId = u16(d, o + 4);
    info.echoSeq = u16(d, o + 6);
    fields.push(f('Identifier', info.echoId, o + 4, 2), f('Sequence', info.echoSeq, o + 6, 2));
  }
  if (errorMsg && end - o >= 8 + 20) {
    // The original (offending) packet header is embedded after 8 bytes.
    const inner = o + 8;
    if (!v6 && d[inner] >> 4 === 4) {
      const ihl = (d[inner] & 0x0f) * 4;
      info.origDst = ipv4(d, inner + 16);
      const ip = d[inner + 9];
      info.origProto = IP_PROTOS[ip] ?? String(ip);
      if ((ip === 6 || ip === 17) && inner + ihl + 4 <= end) info.origPort = u16(d, inner + ihl + 2);
    } else if (v6 && end - inner >= 40) {
      info.origDst = ipv6(d, inner + 24);
      const nh = d[inner + 6];
      info.origProto = IP_PROTOS[nh] ?? String(nh);
      if ((nh === 6 || nh === 17) && inner + 44 <= end) info.origPort = u16(d, inner + 42);
    }
    if (info.origDst) fields.push(f('Original destination', `${info.origDst}${info.origPort ? ':' + info.origPort : ''} (${info.origProto})`, inner));
    if (!v6 && type === 3) fields.push(f('Reason', UNREACH_CODES[code] ?? `code ${code}`, o + 1, 1));
  }
  if (v6 && (type === 135 || type === 136) && end - o >= 24) {
    info.ndpTarget = ipv6(d, o + 8);
    fields.push(f('Target address', info.ndpTarget, o + 8, 16));
  }
  dec.icmp = info;
  const name = v6 ? 'ICMPv6' : 'ICMP';
  dec.layers.push({ name: v6 ? 'Internet Control Message Protocol v6' : 'Internet Control Message Protocol', summary: typeName, offset: o, length: end - o, fields });
  dec.proto = name;
  let s = typeName;
  if (echo) s += ` id=${info.echoId} seq=${info.echoSeq} ttl=${dec.ttl}`;
  if (!v6 && type === 3) s += ` (${UNREACH_CODES[code] ?? 'code ' + code})`;
  if (info.origDst) s += ` for ${info.origDst}${info.origPort ? ':' + info.origPort : ''}`;
  if (info.ndpTarget) s += (type === 135 ? ` for ${info.ndpTarget}` : ` ${info.ndpTarget} is here`);
  dec.info = s;
}
