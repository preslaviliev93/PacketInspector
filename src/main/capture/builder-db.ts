// Builders for database protocol payloads (TCP payload bytes), used by the
// demo network and the tests.

const enc = (s: string) => [...Buffer.from(s, 'utf8')];
const z = (s: string) => [...enc(s), 0];
const le16 = (n: number) => [n & 0xff, (n >> 8) & 0xff];
const le32 = (n: number) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
const be16 = (n: number) => [(n >> 8) & 0xff, n & 0xff];
const be32 = (n: number) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
const utf16 = (s: string) => [...Buffer.from(s, 'utf16le')];

// ------------------------------------------------------------------ MySQL

function mysqlPacket(seq: number, payload: number[]): number[] {
  const n = payload.length;
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, seq, ...payload];
}

export function mysqlGreeting(version: string): number[] {
  return mysqlPacket(0, [0x0a, ...z(version), ...le32(42), ...Array(8).fill(0x41), 0, ...le16(0xf7ff), 0x21, ...le16(2), ...le16(0x81ff), 21, ...Array(10).fill(0), ...Array(12).fill(0x42), 0, ...z('mysql_native_password')]);
}

export function mysqlLogin(user: string, db?: string, ssl = false): number[] {
  // CLIENT_PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH (+ CONNECT_WITH_DB, + SSL)
  const caps = 0x200 | 0x8000 | 0x80000 | (db ? 0x08 : 0) | (ssl ? 0x800 : 0);
  const head = [...le32(caps), ...le32(16777216), 0x21, ...Array(23).fill(0)];
  if (ssl) return mysqlPacket(1, head);
  return mysqlPacket(1, [...head, ...z(user), 20, ...Array(20).fill(0x5a), ...(db ? z(db) : []), ...z('mysql_native_password')]);
}

export function mysqlOk(seq = 2): number[] {
  return mysqlPacket(seq, [0x00, 0, 0, 2, 0, 0, 0]);
}

export function mysqlErr(code: number, msg: string, seq = 2): number[] {
  return mysqlPacket(seq, [0xff, ...le16(code), 0x23, ...enc('28000'), ...enc(msg)]);
}

export function mysqlQuery(sql: string): number[] {
  return mysqlPacket(0, [0x03, ...enc(sql)]);
}

// ------------------------------------------------------------------ PostgreSQL

export function pgStartup(user: string, db: string, app = 'psql'): number[] {
  const body = [...be32(196608), ...z('user'), ...z(user), ...z('database'), ...z(db), ...z('application_name'), ...z(app), 0];
  return [...be32(body.length + 4), ...body];
}

export function pgSslRequest(): number[] {
  return [...be32(8), ...be32(80877103)];
}

function pgMsg(type: string, body: number[]): number[] {
  return [type.charCodeAt(0), ...be32(body.length + 4), ...body];
}

export function pgAuthRequest(method: number): number[] {
  return pgMsg('R', [...be32(method), ...(method === 5 ? [1, 2, 3, 4] : [])]);
}

export function pgPassword(): number[] {
  return pgMsg('p', z('md5' + 'f'.repeat(32)));
}

export function pgAuthOk(version: string): number[] {
  return [...pgMsg('R', be32(0)), ...pgMsg('S', [...z('server_version'), ...z(version)]), ...pgMsg('Z', enc('I'))];
}

export function pgError(code: string, message: string): number[] {
  return pgMsg('E', [...enc('S'), ...z('FATAL'), ...enc('C'), ...z(code), ...enc('M'), ...z(message), 0]);
}

export function pgQuery(sql: string): number[] {
  return pgMsg('Q', z(sql));
}

// ------------------------------------------------------------------ SQL Server (TDS)

function tdsPacket(type: number, payload: number[]): number[] {
  return [type, 0x01, ...be16(payload.length + 8), 0, 0, 1, 0, ...payload];
}

export function tdsPrelogin(encryption: number, version?: [number, number, number]): number[] {
  // VERSION (token 0, 6 bytes) and ENCRYPTION (token 1, 1 byte); offsets are relative to the payload.
  const opts = [0x00, ...be16(11), ...be16(6), 0x01, ...be16(17), ...be16(1), 0xff];
  const ver = version ? [version[0], version[1], ...be16(version[2]), 0, 0] : [0, 0, 0, 0, 0, 0];
  return tdsPacket(0x12, [...opts, ...ver, encryption]);
}

export function tdsLogin7(user: string, password: string, db: string, host = 'WORKSTATION', app = 'Report Builder', server = 'SQL01'): number[] {
  const strings: [string, boolean][] = [[host, false], [user, false], [password, true], [app, false], [server, false], ['', false], ['ODBC', false], ['', false], [db, false]];
  const fixed = 94;
  const body: number[] = [];
  const table: number[] = [];
  let off = fixed;
  for (const [s, scramble] of strings) {
    let bytes = utf16(s);
    if (scramble) bytes = bytes.map((b) => (((b << 4) | (b >> 4)) & 0xff) ^ 0xa5);
    table.push(...le16(off), ...le16(s.length));
    body.push(...bytes);
    off += bytes.length;
  }
  const head = [...le32(fixed + body.length), ...le32(0x74000004), ...le32(4096), ...le32(7), ...le32(1234), ...le32(0), 0xe0, 0x03, 0, 0, ...le32(0), ...le32(0x409)];
  const rest = [...table.slice(0, 36), ...Array(6).fill(0), ...le16(off), ...le16(0), ...le16(off), ...le16(0), ...le32(0)];
  const payload = [...head, ...rest];
  while (payload.length < fixed) payload.push(0);
  return tdsPacket(0x10, [...payload.slice(0, fixed), ...body]);
}

export function tdsLoginFailed(user: string): number[] {
  const msg = utf16(`Login failed for user '${user}'.`);
  const tok = [...le32(18456), 1, 14, ...le16(msg.length / 2), ...msg, 0, 0, ...le32(1)];
  return tdsPacket(0x04, [0xaa, ...le16(tok.length), ...tok, 0xfd, ...le16(2), ...le16(0), ...le32(0), ...le32(0)]);
}

// ------------------------------------------------------------------ MongoDB

function bsonString(key: string, value: string): number[] {
  const v = z(value);
  return [0x02, ...z(key), ...le32(v.length), ...v];
}

export function mongoMsg(command: string, collection: string, db: string): number[] {
  const elems = [...bsonString(command, collection), ...bsonString('$db', db)];
  const doc = [...le32(elems.length + 5), ...elems, 0];
  const body = [...le32(0), 0, ...doc];
  return [...le32(body.length + 16), ...le32(7), ...le32(0), ...le32(2013), ...body];
}

// ------------------------------------------------------------------ Redis

export function redisCommand(...args: string[]): number[] {
  return enc(`*${args.length}\r\n` + args.map((a) => `$${Buffer.byteLength(a)}\r\n${a}\r\n`).join(''));
}

export function redisReply(line: string): number[] {
  return enc(`${line}\r\n`);
}

// ------------------------------------------------------------------ Oracle (TNS)

export function tnsConnect(service: string, host: string, program: string, osUser: string): number[] {
  const data = enc(`(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=${service})(CID=(PROGRAM=${program})(HOST=${host})(USER=${osUser})))(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.5)(PORT=1521)))`);
  const fixed = [...be16(0x013a), ...be16(0x012c), 0, 0, ...be16(0x7fff), ...be16(0x7f08), 0, 0, ...be16(1), ...be16(data.length), ...be16(58), ...Array(24).fill(0)];
  const total = 8 + fixed.length + data.length;
  return [...be16(total), 0, 0, 1, 0, 0, 0, ...fixed, ...data];
}
