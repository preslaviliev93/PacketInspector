import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as B from '../src/main/capture/builder';
import * as DB from '../src/main/capture/builder-db';
import { LINKTYPE, type RawFrame } from '../src/main/capture/pcap';
import { dissect } from '../src/main/dissect';
import { Engine } from '../src/main/engine';
import { DemoSource } from '../src/main/capture/demo';
import { normalizeRuleValue, parseCidr, inCidr } from '../src/shared/watch';
import type { WatchRule } from '../src/shared/types';

const C = { ip: '192.168.1.10', mac: '02:00:00:00:00:0a' };
const S = { ip: '192.168.1.20', mac: '02:00:00:00:00:14' };
let clock = 1_700_000_000;
const frame = (data: Uint8Array): RawFrame => ({ ts: (clock += 0.01), linkType: LINKTYPE.ETHERNET, data, origLen: data.length });
const tcpTo = (port: number, payload: number[], fromClient = true, sport = 50000, src = C, dst = S) =>
  fromClient
    ? frame(B.ethernet(src.mac, dst.mac, 0x0800, B.ipv4(src.ip, dst.ip, 6, B.tcp(src.ip, dst.ip, sport, port, 1, 1, { ack: true, psh: true }, payload))))
    : frame(B.ethernet(dst.mac, src.mac, 0x0800, B.ipv4(dst.ip, src.ip, 6, B.tcp(dst.ip, src.ip, port, sport, 1, 1, { ack: true, psh: true }, payload))));

test('MySQL: greeting, login, query and access denied', () => {
  assert.equal(dissect(tcpTo(3306, DB.mysqlGreeting('8.0.36'), false)).db?.version, '8.0.36');
  const login = dissect(tcpTo(3306, DB.mysqlLogin('shop_app', 'shop')));
  assert.equal(login.db?.event, 'login');
  assert.equal(login.db?.user, 'shop_app');
  assert.equal(login.db?.database, 'shop');
  assert.equal(dissect(tcpTo(3306, DB.mysqlLogin('x', undefined, true))).db?.event, 'ssl-request');
  assert.equal(dissect(tcpTo(3306, DB.mysqlQuery('SELECT 1'))).db?.query, 'SELECT 1');
  const err = dissect(tcpTo(3306, DB.mysqlErr(1045, "Access denied for user 'root'"), false));
  assert.equal(err.db?.event, 'auth-failed');
  assert.match(err.db?.error ?? '', /Access denied/);
});

test('MySQL and PostgreSQL are recognised on non-standard ports', () => {
  const my = dissect(tcpTo(13306, DB.mysqlGreeting('10.11.6-MariaDB'), false));
  assert.equal(my.db?.system, 'MySQL');
  assert.equal(my.db?.version, '10.11.6-MariaDB');
  assert.equal(dissect(tcpTo(6543, DB.pgStartup('app', 'orders'))).db?.user, 'app');
});

test('PostgreSQL: startup, server version, error codes, queries', () => {
  const s = dissect(tcpTo(5432, DB.pgStartup('report', 'sales', 'metabase'))).db!;
  assert.deepEqual([s.event, s.user, s.database, s.application], ['login', 'report', 'sales', 'metabase']);
  assert.equal(dissect(tcpTo(5432, DB.pgAuthOk('16.2'), false)).db?.version, '16.2');
  const e = dissect(tcpTo(5432, DB.pgError('28P01', 'password authentication failed for user "report"'), false)).db!;
  assert.equal(e.event, 'auth-failed');
  assert.equal(dissect(tcpTo(5432, DB.pgQuery('select count(*) from orders'))).db?.query, 'select count(*) from orders');
  // Cleartext password request is flagged as an exposed credential.
  assert.ok(dissect(tcpTo(5432, DB.pgAuthRequest(3), false)).cred);
});

test('SQL Server: pre-login encryption, LOGIN7 user/database, login failure', () => {
  const pre = dissect(tcpTo(1433, DB.tdsPrelogin(2, [15, 0, 2000]), false)).db!;
  assert.equal(pre.encryption, 'not supported');
  assert.equal(pre.version, '15.0.2000');
  const login = dissect(tcpTo(1433, DB.tdsLogin7('sa', 'Summer2024', 'master')));
  assert.equal(login.db?.user, 'sa');
  assert.equal(login.db?.database, 'master');
  assert.ok(login.cred, 'SQL login password is only scrambled');
  assert.ok(!JSON.stringify(login).includes('Summer2024'));
  assert.equal(dissect(tcpTo(1433, DB.tdsLoginFailed('sa'), false)).db?.event, 'auth-failed');
});

test('MongoDB, Redis and Oracle', () => {
  const m = dissect(tcpTo(27017, DB.mongoMsg('find', 'customers', 'crm'))).db!;
  assert.equal(m.database, 'crm');
  assert.equal(m.query, 'find customers');
  const r = dissect(tcpTo(6379, DB.redisCommand('AUTH', 'hunter2')));
  assert.equal(r.db?.event, 'login');
  assert.ok(r.cred);
  assert.ok(!JSON.stringify(r).includes('hunter2'), 'Redis password must not appear');
  assert.equal(dissect(tcpTo(6379, DB.redisReply('-WRONGPASS invalid username-password pair'), false)).db?.event, 'auth-failed');
  const o = dissect(tcpTo(1521, DB.tnsConnect('ORCLPDB1', 'build-01', 'sqlplus', 'jenkins'))).db!;
  assert.equal(o.database, 'ORCLPDB1');
  assert.equal(o.application, 'sqlplus');
});

test('watch rule values are validated and normalised', () => {
  assert.deepEqual(normalizeRuleValue('host', '*.Example.COM.'), { value: 'example.com' });
  assert.deepEqual(normalizeRuleValue('port', '3389'), { value: '3389' });
  assert.ok('error' in normalizeRuleValue('ip', '300.1.1.1'));
  assert.ok('error' in normalizeRuleValue('network', '10.0.0.0'));
  assert.ok('error' in normalizeRuleValue('port', '70000'));
  const v4 = parseCidr('10.20.0.0/16')!;
  assert.ok(inCidr('10.20.255.1', v4));
  assert.ok(!inCidr('10.21.0.1', v4));
  const v6 = parseCidr('2001:db8::/32')!;
  assert.ok(inCidr('2001:db8:abcd::1', v6));
  assert.ok(!inCidr('2001:db9::1', v6));
  assert.ok(!inCidr('10.20.0.1', v6));
});

test('watchlist raises alerts for addresses, networks, host names and ports', () => {
  const rules: WatchRule[] = [
    { id: 'r1', kind: 'ip', value: '203.0.113.77', label: 'Telemetry box', severity: 'high', enabled: true, created: 0 },
    { id: 'r2', kind: 'network', value: '198.51.100.0/24', severity: 'medium', enabled: true, created: 0 },
    { id: 'r3', kind: 'host', value: 'example-data.net', label: 'Data broker', severity: 'medium', enabled: true, created: 0 },
    { id: 'r4', kind: 'port', value: '4444', severity: 'low', enabled: true, created: 0 },
    { id: 'r5', kind: 'port', value: '443', severity: 'low', enabled: false, created: 0 },
  ];
  const engine = new Engine();
  engine.setWatchRules(rules);
  for (const f of new DemoSource(() => {}).generate(95)) engine.ingest(f);
  const st = engine.fullState();
  const watch = st.alerts.filter((a) => a.kind === 'watchlist');
  const hits = st.stats!.watchHits;
  assert.ok(hits.r1 > 0 && hits.r2 > 0 && hits.r3 > 0 && hits.r4 > 0, JSON.stringify(hits));
  assert.equal(hits.r5 ?? 0, 0, 'disabled rules never match');
  assert.ok(watch.some((a) => a.title.includes('Telemetry box') && a.severity === 'high'));
  assert.ok(watch.some((a) => /looked up the watched host name .*example-data\.net/.test(a.description)));
  for (const a of watch) assert.ok(a.packetIds.length > 0);
  assert.ok(st.packets.some((p) => p.tags.includes('watch')));
});

test('demo: database sessions and database alerts end to end', () => {
  const engine = new Engine();
  for (const f of new DemoSource(() => {}).generate(95)) engine.ingest(f);
  const st = engine.fullState();
  const kinds = new Set(st.alerts.map((a) => a.kind));
  for (const k of ['db-unencrypted', 'db-bruteforce', 'db-external', 'db-exposed', 'sql-suspicious', 'db-login-failed']) assert.ok(kinds.has(k), `missing ${k}: ${[...kinds].join(', ')}`);
  const mysql = st.flows.find((f) => f.db?.system === 'MySQL')!;
  assert.deepEqual([mysql.db!.user, mysql.db!.database, mysql.db!.version, mysql.db!.login, mysql.db!.encrypted], ['shop_app', 'shop', '8.0.36', 'ok', false]);
  assert.equal(mysql.db!.queries, 2);
  const pg = st.flows.filter((f) => f.db?.system === 'PostgreSQL');
  assert.equal(pg.length, 6);
  assert.ok(pg.every((f) => f.db!.login === 'failed' && f.db!.user === 'postgres'));
  const mssql = st.flows.find((f) => f.db?.system === 'MSSQL')!;
  assert.equal(mssql.db!.version, '15.0.2000');
  assert.equal(mssql.db!.user, 'sa');
  assert.ok(st.alerts.some((a) => a.kind === 'cleartext-credentials' && /Redis/.test(a.title)));
  assert.equal(st.flows.find((f) => f.db?.system === 'Redis')!.db!.login, 'ok', 'Redis +OK after AUTH counts as a successful login');
  // Detail view decodes the database layer and explains it.
  const q = st.packets.find((p) => p.proto === 'MySQL' && /UNION/.test(p.info))!;
  const d = engine.detail(q.id)!;
  assert.ok(d.layers.some((l) => l.name === 'MySQL'));
});

test('display filter: db:, db:<system> with aliases, is:db and net:', async () => {
  const { compileFilter } = await import('../src/renderer/filter');
  const pkt = (id: number, flowId: number | undefined, src: string, proto = 'TCP') => ({ id, ts: 0, len: 60, src, dst: '192.168.1.40', proto, info: '', tags: [], flowId });
  const rows = [pkt(1, 10, '192.168.1.23', 'MySQL'), pkt(2, 10, '192.168.1.23'), pkt(3, 11, '192.168.1.66', 'PostgreSQL'), pkt(4, 12, '10.20.3.4', 'TLS'), pkt(5, undefined, '10.20.9.9', 'ARP')];
  const dbOf = (id: number) => ({ 10: 'MySQL', 11: 'PostgreSQL', 13: 'MSSQL' } as Record<number, string>)[id];
  const ids = (q: string) => rows.filter(compileFilter(q, () => undefined, dbOf).test).map((r) => r.id);
  assert.deepEqual(ids('db:'), [1, 2, 3]);
  assert.deepEqual(ids('is:db'), [1, 2, 3]);
  assert.deepEqual(ids('db:mysql'), [1, 2], 'includes the plain TCP packet of the MySQL session');
  assert.deepEqual(ids('db:mariadb'), [1, 2]);
  assert.deepEqual(ids('db:pg'), [3]);
  assert.deepEqual(ids('db:sqlserver'), []);
  assert.deepEqual(ids('-db:'), [4, 5]);
  assert.match(compileFilter('db:excel', () => undefined, dbOf).error ?? '', /Unknown database/);
  assert.deepEqual(ids('net:10.20.0.0/16'), [4, 5]);
});

test('filter bar: text <-> chips round trip and plain-language labels', async () => {
  const { parseQuery, composeQuery, chipLabel } = await import('../src/renderer/filterbar');
  const p = parseQuery('host:192.168.1.5 -port:443 proto:dns,tls db: is:problem flow:12 id:5,9 hello world');
  assert.deepEqual(p.chips.map((c) => `${c.neg ? '-' : ''}${c.key}:${c.value}`), ['host:192.168.1.5', '-port:443', 'proto:dns,tls', 'db:', 'is:problem', 'flow:12', 'id:5,9']);
  assert.equal(p.text, 'hello world');
  assert.equal(composeQuery(p.chips, p.text), 'host:192.168.1.5 -port:443 proto:dns,tls db: is:problem flow:12 id:5,9 hello world');
  assert.deepEqual(p.chips.map(chipLabel), ['Host 192.168.1.5', 'Not port 443 (HTTPS)', 'Protocol DNS, TLS', 'Any database', 'Problems only', 'Connection #12', '2 selected packets']);
  assert.equal(chipLabel({ key: 'db', value: 'mssql', neg: false }), 'Database SQL Server');
  assert.equal(chipLabel({ key: 'tag', value: 'mikrotik', neg: false }), 'From MikroTik stream');
  // Unknown "key:value" words stay as plain search text.
  assert.deepEqual(parseQuery('foo:bar').chips, []);
});
