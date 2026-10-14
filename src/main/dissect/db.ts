// Database protocol decoders: MySQL/MariaDB, PostgreSQL, Microsoft SQL Server
// (TDS), MongoDB, Redis and Oracle (TNS).
//
// The goal is visibility rather than full decoding: who connected to which
// database, as which user, with which server version, whether the login worked,
// whether the session is encrypted, and which queries ran. Passwords are never
// shown; when one crosses the wire readable, `dec.cred` is set so it raises an
// alert.

import type { DbSystem, Field } from '../../shared/types';
import type { Decoded } from './types';
import { f, ascii } from './util';

export type DbEvent =
  | 'greeting' | 'ssl-request' | 'ssl-accepted' | 'ssl-refused' | 'login' | 'auth-ok' | 'auth-failed'
  | 'auth-challenge' | 'password' | 'query' | 'error' | 'quit' | 'other';

export interface DbPacket {
  system: DbSystem;
  /** True when this packet was sent by the client (towards the database). */
  fromClient: boolean;
  event: DbEvent;
  version?: string;
  user?: string;
  database?: string;
  application?: string;
  query?: string;
  error?: string;
  /** For SQL Server pre-login: whether encryption was offered/required. */
  encryption?: string;
}

export const DB_PORTS: Record<number, DbSystem> = {
  3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 27017: 'MongoDB', 6379: 'Redis', 1521: 'Oracle',
};

const MAX_QUERY = 500;

const le16 = (d: Uint8Array, o: number) => d[o] | (d[o + 1] << 8);
const le32 = (d: Uint8Array, o: number) => (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0;
const be16 = (d: Uint8Array, o: number) => (d[o] << 8) | d[o + 1];
const be32 = (d: Uint8Array, o: number) => ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;

function cstr(d: Uint8Array, o: number, end: number): { s: string; next: number } {
  let e = o;
  while (e < end && d[e] !== 0) e++;
  return { s: ascii(d, o, e), next: e + 1 };
}

function utf16(d: Uint8Array, o: number, chars: number, end: number): string {
  let s = '';
  for (let i = 0; i < chars && o + i * 2 + 1 < end; i++) s += String.fromCharCode(le16(d, o + i * 2));
  return s;
}

function clip(q: string): string {
  const one = q.replace(/\s+/g, ' ').trim();
  return one.length > MAX_QUERY ? one.slice(0, MAX_QUERY) + '…' : one;
}

/** Signature checks for databases running on non-standard ports. */
export function sniffDb(d: Uint8Array, o: number, end: number): DbSystem | null {
  const n = end - o;
  // MySQL server greeting: 3-byte length, sequence 0, protocol 10, "5.7.x"/"8.0.x"/"10.x-MariaDB".
  if (n > 10 && d[o + 3] === 0 && d[o + 4] === 0x0a && (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16)) === n - 4 && d[o + 5] >= 0x30 && d[o + 5] <= 0x39) return 'MySQL';
  // PostgreSQL startup message (protocol 3.0) or SSLRequest.
  if (n >= 8 && be32(d, o) === n && (be32(d, o + 4) === 196608 || be32(d, o + 4) === 80877103)) return 'PostgreSQL';
  return null;
}

export function dissectDb(dec: Decoded, d: Uint8Array, o: number, end: number, system: DbSystem, fromClient: boolean): boolean {
  let p: DbPacket | null = null;
  const fields: Field[] = [];
  try {
    switch (system) {
      case 'MySQL': p = mysql(d, o, end, fromClient, fields); break;
      case 'PostgreSQL': p = postgres(dec, d, o, end, fromClient, fields); break;
      case 'MSSQL': p = tds(dec, d, o, end, fromClient, fields); break;
      case 'MongoDB': p = mongo(d, o, end, fromClient, fields); break;
      case 'Redis': p = redis(dec, d, o, end, fromClient, fields); break;
      case 'Oracle': p = oracle(d, o, end, fromClient, fields); break;
    }
  } catch {
    p = null;
  }
  if (!p) return false;
  dec.db = p;
  const label = system === 'MSSQL' ? 'SQL Server (TDS)' : system;
  dec.layers.push({ name: label, summary: describe(p), offset: o, length: end - o, fields });
  dec.proto = system;
  dec.info = describe(p);
  return true;
}

function describe(p: DbPacket): string {
  switch (p.event) {
    case 'greeting': return `Server greeting${p.version ? ` (${p.version})` : ''}`;
    case 'ssl-request': return 'Client asks to switch to TLS encryption';
    case 'ssl-accepted': return 'Server agrees to TLS encryption';
    case 'ssl-refused': return 'Server refuses TLS - session stays unencrypted';
    case 'login': return `Login${p.user ? ` as "${p.user}"` : ''}${p.database ? ` to database "${p.database}"` : ''}${p.application ? ` from ${p.application}` : ''}`;
    case 'auth-challenge': return 'Server asks for a password';
    case 'password': return 'Client sends password (hidden)';
    case 'auth-ok': return `Login accepted${p.version ? ` (server ${p.version})` : ''}`;
    case 'auth-failed': return `Login rejected: ${p.error ?? 'authentication failed'}`;
    case 'query': return `Query: ${p.query}`;
    case 'error': return `Error: ${p.error}`;
    case 'quit': return 'Client closes the session';
    default: return p.encryption ? `Pre-login (encryption: ${p.encryption})` : p.query ? p.query : `${p.system} message`;
  }
}

// ------------------------------------------------------------------ MySQL / MariaDB

function mysql(d: Uint8Array, o: number, end: number, fromClient: boolean, fields: Field[]): DbPacket | null {
  if (end - o < 5) return null;
  const len = d[o] | (d[o + 1] << 8) | (d[o + 2] << 16);
  const seq = d[o + 3];
  const b = o + 4;
  const pend = Math.min(end, b + len);
  fields.push(f('Packet length', len, o, 3), f('Sequence', seq, o + 3, 1));
  const p: DbPacket = { system: 'MySQL', fromClient, event: 'other' };
  if (!fromClient) {
    if (seq === 0 && d[b] === 0x0a) {
      p.event = 'greeting';
      p.version = cstr(d, b + 1, pend).s;
      fields.push(f('Protocol', 10, b, 1), f('Server version', p.version, b + 1, p.version.length));
    } else if (d[b] === 0xff && pend - b >= 3) {
      const code = le16(d, b + 1);
      let m = b + 3;
      if (d[m] === 0x23) m += 6; // '#' + 5-char SQLSTATE
      p.error = `${ascii(d, m, pend)} (error ${code})`;
      p.event = code === 1045 || code === 1044 || code === 1698 ? 'auth-failed' : 'error';
      fields.push(f('Error code', code, b + 1, 2), f('Message', ascii(d, m, pend), m, pend - m));
    } else if (d[b] === 0x00 && seq >= 2 && seq <= 4) {
      p.event = 'auth-ok';
      fields.push(f('Result', 'OK', b, 1));
    } else if (d[b] === 0xfe && seq >= 2) {
      p.event = 'auth-challenge';
      fields.push(f('Result', 'Auth switch request', b, 1));
    } else {
      return { ...p, event: 'other' };
    }
    return p;
  }
  // Client side
  if (seq === 1 && pend - b >= 32) {
    const caps = le32(d, b);
    if (pend - b === 32 && caps & 0x800) {
      p.event = 'ssl-request';
      fields.push(f('Capabilities', `0x${caps.toString(16)} (SSL requested)`, b, 4));
      return p;
    }
    let m = b + 32;
    const u = cstr(d, m, pend);
    p.user = u.s;
    m = u.next;
    fields.push(f('Capabilities', `0x${caps.toString(16)}`, b, 4), f('User', p.user, b + 32, p.user.length));
    // Auth response (a password hash, never a readable password): skip it.
    if (caps & 0x00200000) { const l = d[m]; m += 1 + l; } else if (caps & 0x8000) { const l = d[m]; m += 1 + l; } else { m = cstr(d, m, pend).next; }
    fields.push(f('Auth response', '(hashed password, hidden)', m));
    if (caps & 0x08 && m < pend) {
      p.database = cstr(d, m, pend).s;
      fields.push(f('Database', p.database));
    }
    p.event = 'login';
    return p;
  }
  if (seq === 0 && pend > b) {
    const cmd = d[b];
    if (cmd === 0x03 || cmd === 0x16) {
      p.event = 'query';
      p.query = clip(new TextDecoder().decode(d.subarray(b + 1, pend)));
      fields.push(f(cmd === 0x03 ? 'COM_QUERY' : 'COM_STMT_PREPARE', p.query, b + 1, pend - b - 1));
    } else if (cmd === 0x02) {
      p.event = 'query';
      p.database = ascii(d, b + 1, pend);
      p.query = `USE ${p.database}`;
      fields.push(f('COM_INIT_DB', p.database, b + 1, pend - b - 1));
    } else if (cmd === 0x01) {
      p.event = 'quit';
      fields.push(f('Command', 'COM_QUIT', b, 1));
    } else {
      fields.push(f('Command', `0x${cmd.toString(16)}`, b, 1));
    }
    return p;
  }
  return p;
}

// ------------------------------------------------------------------ PostgreSQL

const PG_ERRORS: Record<string, string> = {
  '28P01': 'invalid password', '28000': 'invalid authorization', '3D000': 'database does not exist', '42501': 'insufficient privilege',
};

function postgres(dec: Decoded, d: Uint8Array, o: number, end: number, fromClient: boolean, fields: Field[]): DbPacket | null {
  const n = end - o;
  const p: DbPacket = { system: 'PostgreSQL', fromClient, event: 'other' };
  if (fromClient && n >= 8 && be32(d, o) <= n) {
    const code = be32(d, o + 4);
    if (code === 80877103) { p.event = 'ssl-request'; fields.push(f('Request', 'SSLRequest', o + 4, 4)); return p; }
    if (code === 80877104) { p.event = 'ssl-request'; fields.push(f('Request', 'GSSENCRequest', o + 4, 4)); return p; }
    if (code === 196608) {
      p.event = 'login';
      let m = o + 8;
      const pend = o + be32(d, o);
      while (m < pend && d[m] !== 0) {
        const k = cstr(d, m, pend);
        const v = cstr(d, k.next, pend);
        if (k.s === 'user') p.user = v.s;
        else if (k.s === 'database') p.database = v.s;
        else if (k.s === 'application_name') p.application = v.s;
        fields.push(f(k.s, v.s, m, v.next - m));
        m = v.next;
      }
      return p;
    }
  }
  if (!fromClient && n === 1 && (d[o] === 0x53 || d[o] === 0x4e)) {
    p.event = d[o] === 0x53 ? 'ssl-accepted' : 'ssl-refused';
    fields.push(f('SSL response', d[o] === 0x53 ? "'S' (accepted)" : "'N' (refused)", o, 1));
    return p;
  }
  // Typed messages; a segment can hold several.
  let m = o;
  let any = false;
  while (m + 5 <= end) {
    const type = String.fromCharCode(d[m]);
    const len = be32(d, m + 1);
    if (len < 4 || len > 1 << 24) break;
    const body = m + 5;
    const mend = Math.min(end, m + 1 + len);
    any = true;
    if (fromClient) {
      if (type === 'Q') { p.event = 'query'; p.query = clip(cstr(d, body, mend).s); fields.push(f('Query', p.query, body, mend - body)); }
      else if (type === 'P') { const name = cstr(d, body, mend); p.event = 'query'; p.query = clip(cstr(d, name.next, mend).s); fields.push(f('Parse (prepared statement)', p.query, name.next)); }
      else if (type === 'p') { p.event = 'password'; fields.push(f('Password message', '(hidden)', m, len + 1)); }
      else if (type === 'X') { p.event = 'quit'; fields.push(f('Terminate', '', m, 5)); }
    } else {
      if (type === 'R') {
        const code = be32(d, body);
        if (code === 0) { if (p.event !== 'auth-failed') p.event = 'auth-ok'; fields.push(f('Authentication', 'OK', m, len + 1)); }
        else {
          if (p.event === 'other') p.event = 'auth-challenge';
          const method = code === 3 ? 'cleartext password' : code === 5 ? 'MD5' : code === 10 ? 'SCRAM-SHA-256' : `method ${code}`;
          fields.push(f('Authentication request', method, m, len + 1));
          if (code === 3) dec.cred = { protocol: 'PostgreSQL', detail: 'database password requested in clear text (the client will send it readable)' };
        }
      } else if (type === 'S') {
        const k = cstr(d, body, mend);
        const v = cstr(d, k.next, mend);
        if (k.s === 'server_version') { p.version = v.s; fields.push(f('Server version', v.s, k.next, v.s.length)); }
      } else if (type === 'E') {
        let q = body;
        let code = '', msg = '';
        while (q < mend && d[q] !== 0) {
          const t = String.fromCharCode(d[q]);
          const v = cstr(d, q + 1, mend);
          if (t === 'C') code = v.s;
          if (t === 'M') msg = v.s;
          q = v.next;
        }
        p.error = `${msg}${code ? ` (${code}${PG_ERRORS[code] ? `, ${PG_ERRORS[code]}` : ''})` : ''}`;
        p.event = code.startsWith('28') ? 'auth-failed' : 'error';
        fields.push(f('Error', p.error, m, len + 1));
      }
    }
    m += 1 + len;
  }
  if (!any) return null;
  return p;
}

// ------------------------------------------------------------------ Microsoft SQL Server (TDS)

function tds(dec: Decoded, d: Uint8Array, o: number, end: number, fromClient: boolean, fields: Field[]): DbPacket | null {
  if (end - o < 8) return null;
  const type = d[o];
  const len = be16(d, o + 2);
  if (len < 8) return null;
  const b = o + 8;
  const pend = Math.min(end, o + len);
  const p: DbPacket = { system: 'MSSQL', fromClient, event: 'other' };
  const names: Record<number, string> = { 0x01: 'SQL batch', 0x03: 'RPC', 0x04: 'Response', 0x10: 'Login (LOGIN7)', 0x12: 'Pre-login', 0x0e: 'Transaction manager', 0x06: 'Attention' };
  if (!names[type]) return null;
  fields.push(f('Packet type', names[type], o, 1), f('Length', len, o + 2, 2));
  if (type === 0x12) {
    // Option list: token, offset, length ... 0xFF
    let m = b;
    while (m < pend && d[m] !== 0xff) {
      const tok = d[m], off = be16(d, m + 1), l = be16(d, m + 3);
      const v = b + off;
      if (tok === 0x00 && l >= 6 && !fromClient) {
        p.version = `${d[v]}.${d[v + 1]}.${be16(d, v + 2)}`;
        fields.push(f('Server version', p.version, v, l));
      }
      if (tok === 0x01 && l >= 1) {
        p.encryption = ['off', 'on', 'not supported', 'required'][d[v]] ?? `0x${d[v].toString(16)}`;
        fields.push(f('Encryption', p.encryption, v, 1));
      }
      m += 5;
    }
    return p;
  }
  if (type === 0x10 && fromClient && pend - b >= 94) {
    const str = (at: number) => utf16(d, b + le16(d, b + at), le16(d, b + at + 2), pend);
    p.event = 'login';
    const host = str(36);
    p.user = str(40);
    p.application = str(48);
    const server = str(52);
    p.database = str(68);
    fields.push(f('Client host', host), f('User', p.user || '(Windows authentication)'), f('Password', '(hidden)'), f('Application', p.application), f('Server name', server), f('Database', p.database));
    if (le16(d, b + 46) > 0) dec.cred = { protocol: 'SQL Server', detail: `SQL login "${p.user}" with a password that is only trivially scrambled, not encrypted` };
    return p;
  }
  if (type === 0x01 && fromClient) {
    let m = b;
    const total = le32(d, m);
    if (total >= 4 && total < pend - m) m += total; // skip ALL_HEADERS (TDS 7.2+)
    p.event = 'query';
    p.query = clip(utf16(d, m, (pend - m) >> 1, pend));
    fields.push(f('SQL', p.query, m, pend - m));
    return p;
  }
  if (type === 0x04 && !fromClient) {
    // Look for ERROR (0xAA) or LOGINACK (0xAD) tokens.
    for (let m = b; m < pend - 8; m++) {
      if (d[m] === 0xaa) {
        const num = le32(d, m + 3);
        const msgLen = le16(d, m + 9);
        const msg = utf16(d, m + 11, msgLen, pend);
        if (msg && num > 0 && num < 1_000_000) {
          p.error = `${msg} (error ${num})`;
          p.event = num === 18456 || num === 18452 || num === 4060 ? 'auth-failed' : 'error';
          fields.push(f('Error', p.error, m));
          return p;
        }
      }
      if (d[m] === 0xad && le16(d, m + 1) > 10 && le16(d, m + 1) < 200) {
        p.event = 'auth-ok';
        fields.push(f('Login', 'accepted (LOGINACK)', m));
        return p;
      }
    }
    return p;
  }
  return p;
}

// ------------------------------------------------------------------ MongoDB

function bsonFirstKeyAndDb(d: Uint8Array, o: number, end: number): { first?: string; db?: string; user?: string; text: string } {
  const out: { first?: string; db?: string; user?: string; text: string } = { text: '' };
  const size = le32(d, o);
  const dend = Math.min(end, o + size);
  let m = o + 4;
  while (m < dend - 1) {
    const type = d[m];
    if (type === 0) break;
    const k = cstr(d, m + 1, dend);
    m = k.next;
    if (out.first === undefined) out.first = k.s;
    let len: number;
    switch (type) {
      case 0x01: case 0x09: case 0x11: case 0x12: len = 8; break;
      case 0x02: {
        const l = le32(d, m);
        const v = ascii(d, m + 4, m + 3 + l);
        if (k.s === '$db') out.db = v;
        if (k.s === 'user' || k.s === 'username') out.user = v;
        if (k.s === out.first) out.text = v;
        len = 4 + l;
        break;
      }
      case 0x03: case 0x04: len = le32(d, m); break;
      case 0x05: len = 5 + le32(d, m); break;
      case 0x07: len = 12; break;
      case 0x08: len = 1; break;
      case 0x0a: len = 0; break;
      case 0x10: len = 4; break;
      default: return out;
    }
    m += len;
  }
  return out;
}

function mongo(d: Uint8Array, o: number, end: number, fromClient: boolean, fields: Field[]): DbPacket | null {
  if (end - o < 21) return null;
  const op = le32(d, o + 12);
  const p: DbPacket = { system: 'MongoDB', fromClient, event: 'other' };
  let doc = -1;
  if (op === 2013) { // OP_MSG: flags(4), then section kind 0 = body document
    if (d[o + 20] === 0) doc = o + 21;
  } else if (op === 2004) { // OP_QUERY (legacy handshake)
    const coll = cstr(d, o + 20, end);
    doc = coll.next + 8;
    fields.push(f('Collection', coll.s, o + 20, coll.s.length));
  } else if (op === 1) { // OP_REPLY
    doc = o + 36;
  } else {
    return null;
  }
  fields.push(f('Opcode', op === 2013 ? 'OP_MSG' : op === 2004 ? 'OP_QUERY' : 'OP_REPLY', o + 12, 4));
  if (doc < 0 || doc + 5 > end) return p;
  const info = bsonFirstKeyAndDb(d, doc, end);
  if (fromClient && info.first) {
    p.database = info.db;
    const cmd = info.first;
    fields.push(f('Command', cmd, doc + 5), ...(info.db ? [f('Database', info.db)] : []));
    if (/^(saslStart|authenticate)$/i.test(cmd)) { p.event = 'login'; p.user = info.user; }
    else if (/^(hello|ismaster|isMaster|buildinfo|ping|saslContinue|endSessions)$/.test(cmd)) p.event = 'other';
    else { p.event = 'query'; p.query = info.text ? `${cmd} ${info.text}` : cmd; }
    if (p.event === 'other') p.query = cmd;
  } else if (!fromClient) {
    const text = ascii(d, doc, Math.min(end, doc + 400));
    if (/Authentication failed/i.test(text)) { p.event = 'auth-failed'; p.error = 'Authentication failed'; }
    const v = /version\x00.{4}([0-9][0-9.]+)/.exec(text);
    if (v) p.version = v[1];
    fields.push(f('Reply', p.error ?? (p.version ? `server ${p.version}` : 'result document'), doc));
  }
  return p;
}

// ------------------------------------------------------------------ Redis

function redis(dec: Decoded, d: Uint8Array, o: number, end: number, fromClient: boolean, fields: Field[]): DbPacket | null {
  const text = ascii(d, o, Math.min(end, o + 2000));
  const p: DbPacket = { system: 'Redis', fromClient, event: 'other' };
  if (fromClient) {
    let parts: string[];
    if (text.startsWith('*')) {
      parts = text.split('\r\n').filter((_, i) => i > 0 && i % 2 === 0);
    } else if (/^[A-Za-z]+[ \r\n]/.test(text)) {
      parts = text.split('\r\n')[0].split(' ');
    } else {
      return null;
    }
    const cmd = (parts[0] ?? '').toUpperCase();
    if (!cmd) return null;
    if (cmd === 'AUTH') {
      p.event = 'login';
      if (parts.length > 2) p.user = parts[1];
      dec.cred = { protocol: 'Redis', detail: `AUTH command with the password in clear text${p.user ? ` (user "${p.user}")` : ''}` };
      fields.push(f('Command', 'AUTH ••••••', o, end - o));
    } else if (cmd === 'HELLO' && parts.some((x) => x.toUpperCase() === 'AUTH')) {
      p.event = 'login';
      dec.cred = { protocol: 'Redis', detail: 'HELLO … AUTH with the password in clear text' };
      fields.push(f('Command', 'HELLO … AUTH ••••••', o, end - o));
    } else if (cmd === 'QUIT') {
      p.event = 'quit';
      fields.push(f('Command', 'QUIT', o, end - o));
    } else {
      p.event = 'query';
      p.query = clip(parts.slice(0, 4).join(' ') + (parts.length > 4 ? ' …' : ''));
      fields.push(f('Command', p.query, o, end - o));
    }
    return p;
  }
  const first = text.split('\r\n')[0];
  if (!/^[+\-:$*]/.test(first)) return null;
  if (first.startsWith('-')) {
    p.error = first.slice(1);
    p.event = /WRONGPASS|invalid password|invalid username-password/i.test(first) ? 'auth-failed' : /NOAUTH/.test(first) ? 'error' : 'error';
  } else if (first === '+OK') {
    p.event = 'other';
  }
  const v = /redis_version:([0-9.]+)/.exec(text);
  if (v) p.version = v[1];
  fields.push(f('Reply', first.slice(0, 200), o, first.length));
  return p;
}

// ------------------------------------------------------------------ Oracle (TNS)

function oracle(d: Uint8Array, o: number, end: number, fromClient: boolean, fields: Field[]): DbPacket | null {
  if (end - o < 8) return null;
  const type = d[o + 4];
  const names: Record<number, string> = { 1: 'Connect', 2: 'Accept', 4: 'Refuse', 5: 'Redirect', 6: 'Data', 11: 'Resend', 12: 'Marker' };
  if (!names[type]) return null;
  const p: DbPacket = { system: 'Oracle', fromClient, event: 'other' };
  fields.push(f('Packet type', names[type], o + 4, 1));
  const text = ascii(d, o, Math.min(end, o + 2000));
  if (type === 1) {
    p.event = 'login';
    const svc = /\((?:SERVICE_NAME|SID)=([^)]+)\)/i.exec(text);
    const user = /\(USER=([^)]+)\)/i.exec(text);
    const prog = /\(PROGRAM=([^)]+)\)/i.exec(text);
    if (svc) p.database = svc[1];
    if (user) p.user = `${user[1]} (OS user)`;
    if (prog) p.application = prog[1];
    const desc = text.indexOf('(DESCRIPTION');
    if (desc >= 0) fields.push(f('Connect descriptor', text.slice(desc, desc + 300)));
  } else if (type === 4) {
    p.event = 'error';
    p.error = 'connection refused by the listener';
  }
  const ora = /ORA-(\d{5})[^\x00]{0,120}/.exec(text);
  if (ora) {
    p.error = ora[0].replace(/[^\x20-\x7e]+/g, ' ').trim();
    p.event = ora[1] === '01017' || ora[1] === '28000' ? 'auth-failed' : 'error';
    fields.push(f('Oracle error', p.error));
  }
  return p;
}
