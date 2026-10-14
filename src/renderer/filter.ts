// Display filter: a small, forgiving language designed to be typed by humans.
//
//   dns                      free text: matches protocol, addresses, ports, names, info
//   host:192.168.1.5         either address (or resolved name) contains the value
//   src:10.0.0.1  dst:...    one side only
//   port:443                 either port
//   net:10.0.0.0/8           either address inside a network (IPv4 or IPv6)
//   db:  db:mysql            database sessions (any, or one system: mysql, postgresql, mssql, mongodb, redis, oracle)
//   proto:dns,tls            protocol list
//   flow:12                  one connection
//   id:5,9,12                specific packets (used by "show evidence")
//   tag:retransmission       problem markers (retransmission, rst, syn, dup-ack, zero-window, alert, credentials)
//   is:problem               any loss/reset/zero-window marker
//   -term                    negate any term
//
// Terms are combined with AND.

import type { PacketSummary } from '../shared/types';
import { parseCidr, inCidr } from '../shared/watch';

type Pred = (p: PacketSummary, nameOf: (ip: string) => string | undefined) => boolean;

export interface CompiledFilter {
  test: (p: PacketSummary) => boolean;
  error?: string;
  empty: boolean;
}

const PROBLEM_TAGS = ['retransmission', 'rst', 'dup-ack', 'zero-window', 'malformed', 'dns-error'];

function tokenize(q: string): string[] {
  const out: string[] = [];
  const re = /(-?\w+:"[^"]*"|-?"[^"]*"|\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(q))) out.push(m[1].replace(/"/g, ''));
  return out;
}

function addrMatch(ip: string, v: string, nameOf: (ip: string) => string | undefined): boolean {
  if (ip.toLowerCase().includes(v)) return true;
  const n = nameOf(ip);
  return !!n && n.toLowerCase().includes(v);
}

/** Database system names people type, mapped to what the engine reports. */
const DB_ALIASES: Record<string, string> = {
  mysql: 'mysql', mariadb: 'mysql', postgres: 'postgresql', postgresql: 'postgresql', pg: 'postgresql',
  mssql: 'mssql', sqlserver: 'mssql', tds: 'mssql', mongo: 'mongodb', mongodb: 'mongodb', redis: 'redis', oracle: 'oracle', tns: 'oracle',
};

export function compileFilter(q: string, nameOf: (ip: string) => string | undefined, dbOf: (flowId: number) => string | undefined = () => undefined): CompiledFilter {
  const preds: Pred[] = [];
  let error: string | undefined;
  for (let tok of tokenize(q.trim())) {
    let neg = false;
    if (tok.startsWith('-') && tok.length > 1) { neg = true; tok = tok.slice(1); }
    const i = tok.indexOf(':');
    const key = i > 0 ? tok.slice(0, i).toLowerCase() : '';
    const val = (i > 0 ? tok.slice(i + 1) : tok).toLowerCase();
    let p: Pred;
    switch (key) {
      case 'host': case 'ip': p = (x, n) => addrMatch(x.src, val, n) || addrMatch(x.dst, val, n); break;
      case 'src': p = (x, n) => addrMatch(x.src, val, n); break;
      case 'dst': p = (x, n) => addrMatch(x.dst, val, n); break;
      case 'net': case 'network': case 'subnet': {
        const c = parseCidr(val.includes('/') ? val : `${val}/32`);
        if (!c) { error = `"${val}" is not a network - try net:10.0.0.0/8`; continue; }
        p = (x) => inCidr(x.src, c) || inCidr(x.dst, c);
        break;
      }
      case 'port': {
        const port = Number(val);
        if (!Number.isInteger(port)) { error = `"${val}" is not a port number`; continue; }
        p = (x) => x.sport === port || x.dport === port;
        break;
      }
      case 'proto': case 'protocol': {
        const set = new Set(val.split(','));
        p = (x) => set.has(x.proto.toLowerCase());
        break;
      }
      case 'flow': case 'conv': { const id = Number(val); p = (x) => x.flowId === id; break; }
      case 'id': { const set = new Set(val.split(',').map(Number)); p = (x) => set.has(x.id); break; }
      case 'tag': p = (x) => x.tags.includes(val); break;
      case 'is':
        p = val === 'problem' ? (x) => x.tags.some((t) => PROBLEM_TAGS.includes(t))
          : val === 'db' || val === 'database' ? (x) => x.flowId !== undefined && dbOf(x.flowId) !== undefined
          : (x) => x.tags.includes(val);
        break;
      case 'db': case 'database': {
        // Matches every packet of a database session (including plain TCP acknowledgements).
        if (!val || val === 'any' || val === 'all') { p = (x) => x.flowId !== undefined && dbOf(x.flowId) !== undefined; break; }
        const want = DB_ALIASES[val];
        if (!want) { error = `Unknown database "${val}" - try db:mysql, db:postgresql, db:mssql, db:mongodb, db:redis or db:oracle`; continue; }
        p = (x) => x.flowId !== undefined && dbOf(x.flowId)?.toLowerCase() === want;
        break;
      }
      case '':
        p = (x, n) =>
          x.proto.toLowerCase() === val ||
          x.info.toLowerCase().includes(val) ||
          addrMatch(x.src, val, n) || addrMatch(x.dst, val, n) ||
          String(x.sport) === val || String(x.dport) === val;
        break;
      default:
        error = `Unknown filter key "${key}:" - try host:, net:, port:, proto:, db:, flow:, tag: or plain text`;
        continue;
    }
    preds.push(neg ? (x, n) => !p(x, n) : p);
  }
  return {
    empty: preds.length === 0,
    error,
    test: (x) => preds.every((p) => p(x, nameOf)),
  };
}
