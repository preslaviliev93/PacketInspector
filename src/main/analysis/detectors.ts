// Heuristic detectors for suspicious activity and network problems.
// Every alert keeps the packet ids that triggered it so the UI can trace
// the alert back to concrete evidence.

import type { Alert, AlertCategory, Severity } from '../../shared/types';
import type { Decoded } from '../dissect/types';
import type { FlowResult } from './flows';
import { SUSPICIOUS_PORTS, service } from '../dissect/services';
import { entropy, ipScope, isLocal, formatBytes } from '../dissect/util';
import type { DbSystem } from '../../shared/types';
import { WATCH_KIND_LABEL, type WatchMatch } from '../../shared/watch';

/** How to turn on encryption, per database. */
const DB_TLS_ADVICE: Record<DbSystem, string> = {
  MySQL: 'Enable TLS on the server (require_secure_transport=ON) and connect with ssl-mode=REQUIRED (or VERIFY_IDENTITY).',
  PostgreSQL: 'Set ssl = on in postgresql.conf, use hostssl lines in pg_hba.conf, and connect with sslmode=require (better: verify-full).',
  MSSQL: 'Turn on "Force Encryption" in SQL Server Configuration Manager and use Encrypt=True (with a trusted certificate) in connection strings.',
  MongoDB: 'Start mongod with --tlsMode requireTLS and connect with tls=true.',
  Redis: 'Enable TLS (tls-port) or keep Redis reachable only on localhost or a private network, and use ACL users with strong passwords.',
  Oracle: 'Require native network encryption (SQLNET.ENCRYPTION_SERVER=required) or use a TCPS listener.',
};

/** Patterns typical of SQL injection, data theft or command execution through a database. */
const SUSPICIOUS_SQL: [RegExp, string][] = [
  [/\bunion\s+(all\s+)?select\b/i, 'UNION SELECT, a classic SQL injection pattern'],
  [/\bor\s+'?\d+'?\s*=\s*'?\d+'?\s*(--|#|$)/i, 'an always-true condition (OR 1=1), a classic SQL injection pattern'],
  [/\bxp_cmdshell\b/i, 'xp_cmdshell, which runs operating-system commands from SQL Server'],
  [/\binto\s+(out|dump)file\b/i, 'INTO OUTFILE, which writes query results to a file on the server'],
  [/\bload_file\s*\(/i, 'LOAD_FILE(), which reads files from the server'],
  [/\bcopy\b[\s\S]*\bfrom\s+program\b/i, 'COPY ... FROM PROGRAM, which runs commands on a PostgreSQL server'],
  [/\b(pg_sleep|benchmark|sleep)\s*\(|\bwaitfor\s+delay\b/i, 'a deliberate delay, typical of blind SQL injection'],
  [/;\s*(drop|truncate)\s+(table|database)\b/i, 'a DROP/TRUNCATE chained after another statement'],
  [/^config\s+set\s+(dir|dbfilename)\b/i, 'CONFIG SET dir/dbfilename, used to make Redis write files (a known takeover technique)'],
  [/^(slaveof|replicaof|module\s+load)\b/i, 'a command that makes Redis load external code or data'],
];

const MAX_EVIDENCE = 200;

/** A packet remembered by a windowed detector, so the alert can cite it later. */
interface Probe { ts?: number; pid: number; flowId?: number }

interface AlertSpec {
  severity: Severity;
  category: AlertCategory;
  kind: string;
  title: string;
  description: string;
  advice: string;
  hosts: string[];
}

export class Detectors {
  private alerts = new Map<string, Alert>();
  private nextId = 1;
  readonly changed = new Set<Alert>();

  // detector state
  private synTargets = new Map<string, Map<number, Probe>>(); // src>dst -> port -> first probe
  private sweep = new Map<string, Map<string, Probe>>(); // src|dport -> dst -> first probe
  private synFlood = new Map<string, { syns: number[]; done: number }>();
  private arpTable = new Map<string, { mac: string; ts: number; macs: Set<string>; evidence: Probe[] }>();
  private nxdomain = new Map<string, number[]>();
  private dhcpServers = new Map<string, number>();
  private beacons = new Map<string, Probe[]>();
  private seenOnce = new Set<string>();
  private dbFailures = new Map<string, Probe[]>();
  private watchCounts = new Map<string, number>();

  constructor(private nameOf: (ip: string) => string | undefined) {}

  clear(): void {
    this.alerts.clear();
    this.changed.clear();
    this.nextId = 1;
    this.synTargets.clear();
    this.sweep.clear();
    this.synFlood.clear();
    this.arpTable.clear();
    this.nxdomain.clear();
    this.dhcpServers.clear();
    this.beacons.clear();
    this.seenOnce.clear();
    this.dbFailures.clear();
    this.watchCounts.clear();
  }

  all(): Alert[] {
    return [...this.alerts.values()];
  }

  private label(ip: string): string {
    const n = this.nameOf(ip);
    return n ? `${ip} (${n})` : ip;
  }

  /** Create or extend an alert identified by `dedupeKey`. Returns the alert. */
  private raise(dedupeKey: string, ts: number, pid: number, flowId: number | undefined, spec: AlertSpec, earlier: Probe[] = []): Alert {
    let a = this.alerts.get(dedupeKey);
    if (!a) {
      a = { id: this.nextId++, ts, packetIds: [], flowIds: [], ...spec };
      this.alerts.set(dedupeKey, a);
    } else {
      // Keep the latest wording (counts grow over time) but never downgrade severity.
      const rank = { info: 0, low: 1, medium: 2, high: 3 };
      a.title = spec.title;
      a.description = spec.description;
      if (rank[spec.severity] > rank[a.severity]) a.severity = spec.severity;
    }
    for (const e of [...earlier, { pid, flowId }]) {
      if (a.packetIds.length < MAX_EVIDENCE && !a.packetIds.includes(e.pid)) a.packetIds.push(e.pid);
      if (e.flowId !== undefined && !a.flowIds.includes(e.flowId) && a.flowIds.length < MAX_EVIDENCE) a.flowIds.push(e.flowId);
    }
    a.packetIds.sort((x, y) => x - y);
    this.changed.add(a);
    this.touched = true;
    return a;
  }

  inspect(pid: number, ts: number, dec: Decoded, fr: FlowResult | null, watch: WatchMatch[] = []): string[] {
    this.touched = false;
    const flowId = fr?.flow.id;
    let watched = false;
    if (watch.length) { this.watch(pid, ts, dec, flowId, watch); watched = true; }
    if (fr?.flow.db && (dec.db || fr.flow.packetsAB + fr.flow.packetsBA <= 2)) this.database(pid, ts, dec, fr);

    if (dec.arp) this.arp(pid, ts, dec);
    if (dec.tcp && dec.src && dec.dst) this.tcp(pid, ts, dec, fr);
    if (dec.dns) this.dns(pid, ts, dec, flowId);
    if (dec.cred && dec.src && dec.dst) {
      this.raise(`cred|${dec.src}|${dec.dst}|${dec.cred.protocol}`, ts, pid, flowId, {
        severity: 'high', category: 'security', kind: 'cleartext-credentials',
        title: `Password sent unencrypted (${dec.cred.protocol})`,
        description: `${this.label(dec.src)} sent a ${dec.cred.detail} to ${this.label(dec.dst)}. Anyone on the network path can read it.`,
        advice: 'Change this password and switch to the encrypted version of the service (HTTPS, SFTP, IMAPS, SSH...).',
        hosts: [dec.src, dec.dst],
      });
    }
    if (dec.tls && dec.src && dec.dst) this.tls(pid, ts, dec, flowId);
    if (dec.dhcp && dec.src && (dec.dhcp.messageType === 'Offer' || dec.dhcp.messageType === 'ACK')) {
      const server = dec.dhcp.serverId ?? dec.src;
      this.dhcpServers.set(server, ts);
      if (this.dhcpServers.size > 1) {
        const servers = [...this.dhcpServers.keys()];
        this.raise('dhcp-multi', ts, pid, flowId, {
          severity: 'high', category: 'security', kind: 'rogue-dhcp',
          title: 'More than one DHCP server on the network',
          description: `Address assignments are coming from ${servers.join(', ')}. A second, unexpected DHCP server can redirect your traffic (a "rogue DHCP" attack) or be a misconfigured router.`,
          advice: 'Identify each server. Only your router (or official DHCP server) should be answering. Disable or remove the other one.',
          hosts: servers,
        });
      }
    }
    if (dec.icmp && dec.src && dec.icmp.origDst && (dec.icmp.type === 3 || (dec.icmp.v6 && dec.icmp.type === 1))) {
      const target = dec.icmp.origDst + (dec.icmp.origPort ? `:${dec.icmp.origPort}` : '');
      this.raise(`unreach|${target}`, ts, pid, flowId, {
        severity: 'low', category: 'performance', kind: 'unreachable',
        title: `Destination unreachable: ${target}`,
        description: `${this.label(dec.src)} reported that ${target} (${dec.icmp.origProto}) could not be reached. Applications trying to use it will fail or time out.`,
        advice: 'Check that the destination host is up, the service is running and no firewall is blocking it.',
        hosts: [dec.src, dec.icmp.origDst],
      });
    }
    if (fr) this.flowLevel(pid, ts, fr);

    const tags = this.touched ? ['alert'] : [];
    if (watched) tags.push('watch');
    return tags;
  }

  // ------------------------------------------------------------------ watchlist

  private watch(pid: number, ts: number, dec: Decoded, flowId: number | undefined, matches: WatchMatch[]): void {
    const src = dec.src ?? '?', dst = dec.dst ?? '?';
    for (const m of matches) {
      const r = m.rule;
      // Who is involved, from the point of view of the watched thing.
      let who: string, phrase: string;
      if (m.via === 'address') {
        const peer = m.matched === src ? dst : src;
        who = peer;
        phrase = r.kind === 'network' ? `exchanged traffic with ${this.label(m.matched)}, inside the watched network ${r.value}` : `exchanged traffic with the watched address ${this.label(m.matched)}`;
      } else if (m.via === 'port') {
        who = src;
        phrase = `sent traffic on ${m.matched} to ${this.label(dst)}`;
      } else if (m.via === 'DNS lookup') {
        who = dec.dns?.response ? dst : src;
        phrase = `looked up the watched host name ${m.matched}`;
      } else {
        who = src;
        phrase = `connected to the watched host ${m.matched} (seen in the ${m.via})`;
      }
      const key = `watch|${r.id}|${who}`;
      const n = (this.watchCounts.get(key) ?? 0) + 1;
      this.watchCounts.set(key, n);
      const name = r.label ? `"${r.label}"` : r.value;
      this.raise(key, ts, pid, flowId, {
        severity: r.severity, category: 'security', kind: 'watchlist',
        title: `Watchlist: ${r.label ?? r.value} - ${who}`,
        description: `${this.label(who)} ${phrase}. This matches your watch rule ${name} (${WATCH_KIND_LABEL[r.kind].toLowerCase()} ${r.value}). ${n} matching packet${n > 1 ? 's' : ''} so far.`,
        advice: 'This alert comes from your Watchlist. Open the evidence to see exactly what was exchanged, or change the rule on the Watchlist tab.',
        hosts: [...new Set([who, m.via === 'address' ? m.matched : dst])].filter((x) => x !== '?'),
      });
    }
  }

  // ------------------------------------------------------------------ databases

  private database(pid: number, ts: number, dec: Decoded, fr: FlowResult): void {
    const f = fr.flow;
    const s = f.db!;
    const p = dec.db;
    const client = f.a, server = f.b;
    const where = `${this.label(server)}${f.bPort ? `:${f.bPort}` : ''}`;

    // Where is the database, relative to who uses it?
    const clientPublic = ipScope(client) === 'public', serverPublic = ipScope(server) === 'public';
    if (clientPublic && !serverPublic) {
      this.raise(`dbexposed|${server}|${f.bPort}`, ts, pid, f.id, {
        severity: 'high', category: 'security', kind: 'db-exposed',
        title: `${s.system} database reachable from the internet`,
        description: `${this.label(client)}, an address on the internet, is talking to the ${s.system} database on ${where}. Databases exposed to the internet are scanned and brute-forced constantly.`,
        advice: `Unless this is intended, block port ${f.bPort} from the internet at your firewall and reach the database through a VPN or SSH tunnel instead.`,
        hosts: [client, server],
      });
    } else if (!clientPublic && serverPublic) {
      this.raise(`dbexternal|${client}|${server}|${f.bPort}`, ts, pid, f.id, {
        severity: 'medium', category: 'security', kind: 'db-external',
        title: `Database traffic leaving your network (${s.system})`,
        description: `${this.label(client)} is using a ${s.system} database on the internet at ${where}. Make sure this is a service you know about, and that the connection is encrypted.`,
        advice: 'Confirm which application connects there. Cloud databases are normal; unknown ones can mean data leaving your network.',
        hosts: [client, server],
      });
    }
    if (!p) return;

    // Logging in without encryption.
    if (p.fromClient && p.event === 'login' && !s.encrypted) {
      this.raise(`dbplain|${client}|${server}|${s.system}`, ts, pid, f.id, {
        severity: 'medium', category: 'security', kind: 'db-unencrypted',
        title: `Unencrypted ${s.system} login${s.user ? ` as "${s.user}"` : ''}`,
        description: `${this.label(client)} logged in to the ${s.system} database on ${where}${s.user ? ` as "${s.user}"` : ''}${s.database ? `, database "${s.database}"` : ''} without encryption. Queries and the data that comes back can be read by anyone on the network path.`,
        advice: DB_TLS_ADVICE[s.system],
        hosts: [client, server],
      });
    }

    // Failed logins, and many of them (brute force).
    if (p.event === 'auth-failed') {
      const key = `${client}>${server}:${f.bPort}`;
      const list = (this.dbFailures.get(key) ?? []).filter((x) => ts - x.ts! <= 300);
      list.push({ ts, pid, flowId: f.id });
      this.dbFailures.set(key, list);
      if (list.length >= 5) {
        this.raise(`dbbrute|${key}`, ts, pid, f.id, {
          severity: 'high', category: 'security', kind: 'db-bruteforce',
          title: `Repeated failed ${s.system} logins from ${client}`,
          description: `${this.label(client)} failed to log in to the ${s.system} database on ${where} ${list.length} times in the last 5 minutes${s.user ? `, trying user "${s.user}"` : ''}. That looks like password guessing.`,
          advice: `If you don't recognise ${client}, block it. Make sure database accounts have strong passwords, disable unused ones (such as default admin accounts) and don't expose the database to untrusted networks.`,
          hosts: [client, server],
        }, list);
      } else {
        this.raise(`dbfail|${key}`, ts, pid, f.id, {
          severity: 'low', category: 'security', kind: 'db-login-failed',
          title: `${s.system} login failed${s.user ? ` for "${s.user}"` : ''}`,
          description: `The ${s.system} database on ${where} rejected a login from ${this.label(client)}: ${p.error ?? 'authentication failed'}.`,
          advice: 'Usually a wrong password or a misconfigured application. Repeated failures from the same client are reported separately as possible password guessing.',
          hosts: [client, server],
        }, list);
      }
    }

    // Dangerous-looking SQL / commands.
    if (p.event === 'query' && p.query) {
      const hit = SUSPICIOUS_SQL.find(([re]) => re.test(p.query!));
      if (hit) {
        this.raise(`sqlsus|${client}|${server}|${hit[1]}`, ts, pid, f.id, {
          severity: 'medium', category: 'security', kind: 'sql-suspicious',
          title: `Suspicious ${s.system} command from ${client}`,
          description: `A query sent to ${where} contains ${hit[1]}: "${p.query.slice(0, 160)}${p.query.length > 160 ? '…' : ''}".`,
          advice: 'Check which application sent it. If it came from a web application, it may be vulnerable to SQL injection; review its logs and parameterise its queries.',
          hosts: [client, server],
        });
      }
    }
  }

  private touched = false;

  private tcp(pid: number, ts: number, dec: Decoded, fr: FlowResult | null): void {
    const t = dec.tcp!;
    const src = dec.src!, dst = dec.dst!;
    const flowId = fr?.flow.id;
    const sus = SUSPICIOUS_PORTS[t.dport];
    if (t.flags.syn && !t.flags.ack) {
      // Vertical scan: many ports on one host.
      const key = `${src}>${dst}`;
      let ports = this.synTargets.get(key);
      if (!ports) this.synTargets.set(key, (ports = new Map()));
      if (!ports.has(t.dport)) ports.set(t.dport, { ts, pid, flowId });
      if (ports.size >= 15) {
        let recent = 0;
        for (const [p, pr] of ports) { if (ts - pr.ts! <= 60) recent++; else ports.delete(p); }
        if (recent >= 15) {
          this.raise(`scan|${key}`, ts, pid, flowId, {
            severity: 'high', category: 'security', kind: 'port-scan',
            title: `Port scan: ${src} → ${dst}`,
            description: `${this.label(src)} tried to connect to ${recent} different ports on ${this.label(dst)} within a minute. That pattern is typical of a port scanner looking for open services.`,
            advice: `If you don't recognize ${src}, block it on your firewall and check that host for malware. If ${dst} is yours, close ports you don't need.`,
            hosts: [src, dst],
          }, [...ports.values()]);
        }
      }
      // Horizontal sweep: one port on many hosts.
      const sk = `${src}|${t.dport}`;
      let hosts = this.sweep.get(sk);
      if (!hosts) this.sweep.set(sk, (hosts = new Map()));
      if (!hosts.has(dst)) hosts.set(dst, { ts, pid, flowId });
      if (hosts.size >= 20) {
        let recent = 0;
        for (const [h, pr] of hosts) { if (ts - pr.ts! <= 60) recent++; else hosts.delete(h); }
        if (recent >= 20) {
          this.raise(`sweep|${sk}`, ts, pid, flowId, {
            severity: 'high', category: 'security', kind: 'network-sweep',
            title: `Network sweep on port ${t.dport} from ${src}`,
            description: `${this.label(src)} contacted ${recent} different hosts on port ${t.dport} within a minute. Worms and attackers do this to find vulnerable machines.`,
            advice: `Investigate ${src}: is it an inventory/monitoring tool you run? If not, isolate it from the network.`,
            hosts: [src],
          }, [...hosts.values()]);
        }
      }
      // SYN flood: lots of SYNs, few completed handshakes.
      const fk = `${dst}:${t.dport}`;
      let sf = this.synFlood.get(fk);
      if (!sf) this.synFlood.set(fk, (sf = { syns: [], done: 0 }));
      sf.syns.push(ts);
      while (sf.syns.length && ts - sf.syns[0] > 10) sf.syns.shift();
      if (sf.syns.length > 200 && sf.done < sf.syns.length * 0.2) {
        this.raise(`synflood|${fk}`, ts, pid, flowId, {
          severity: 'high', category: 'security', kind: 'syn-flood',
          title: `Possible SYN flood against ${fk}`,
          description: `${sf.syns.length} connection requests hit ${fk} in 10 seconds and most never completed. This can exhaust the server and is a common denial-of-service technique.`,
          advice: 'Enable SYN cookies / rate limiting on the server or firewall and identify the sources.',
          hosts: [dst],
        });
      }
      if (sus) {
        this.raise(`susport|${src}|${dst}|${t.dport}`, ts, pid, flowId, {
          severity: 'medium', category: 'security', kind: 'suspicious-port',
          title: `Connection to suspicious port ${t.dport}`,
          description: `${this.label(src)} opened a connection to ${this.label(dst)} on port ${t.dport}, which is ${sus}.`,
          advice: 'Confirm which program made this connection (e.g. `netstat -b` on Windows, `ss -tp` on Linux). Unknown programs should be scanned for malware.',
          hosts: [src, dst],
        });
      }
    }
    if (t.flags.syn && t.flags.ack) {
      const sf = this.synFlood.get(`${src}:${t.sport}`);
      if (sf) sf.done++;
    }
  }

  private arp(pid: number, ts: number, dec: Decoded): void {
    const a = dec.arp!;
    if (a.senderIp === '0.0.0.0') return;
    let entry = this.arpTable.get(a.senderIp);
    if (!entry) {
      entry = { mac: a.senderMac, ts, macs: new Set([a.senderMac]), evidence: [{ pid }] };
      this.arpTable.set(a.senderIp, entry);
      return;
    }
    const prevMac = entry.mac;
    entry.mac = a.senderMac;
    entry.ts = ts;
    if (!entry.macs.has(a.senderMac)) {
      entry.macs.add(a.senderMac);
      entry.evidence.push({ pid });
    }
    if (prevMac !== a.senderMac) {
      const macs = [...entry.macs];
      this.raise(`arp|${a.senderIp}`, ts, pid, undefined, {
        severity: 'high', category: 'security', kind: 'arp-spoofing',
        title: `Possible ARP spoofing for ${a.senderIp}`,
        description: `${macs.length} different hardware (MAC) addresses have claimed to be ${a.senderIp}: ${macs.join(', ')} (latest change: ${prevMac} → ${a.senderMac}). An attacker can do this to put themselves between you and ${a.senderIp} (man-in-the-middle). It can also happen legitimately when a device is replaced or uses failover.`,
        advice: `Find which device owns each of those addresses. If ${a.senderIp} is your gateway and you only expect one, disconnect the unknown device and investigate; consider static ARP entries or switch port security.`,
        hosts: [a.senderIp],
      }, entry.evidence);
    }
  }

  private dns(pid: number, ts: number, dec: Decoded, flowId?: number): void {
    const d = dec.dns!;
    if (d.mdns) return;
    const q = d.questions[0];
    if (q && !d.response) {
      const labels = q.name.split('.');
      const sub = labels.slice(0, -2).join('.');
      const longest = labels.reduce((m, l) => Math.max(m, l.length), 0);
      const base = labels.slice(-2).join('.');
      if (q.name.length > 100 || longest > 50 || (sub.length >= 30 && entropy(sub.replace(/\./g, '')) > 4.0) || q.type === 'TXT' && sub.length > 40) {
        this.raise(`dnstun|${dec.src}|${base}`, ts, pid, flowId, {
          severity: 'medium', category: 'security', kind: 'dns-tunneling',
          title: `Unusual DNS names under ${base}`,
          description: `${this.label(dec.src!)} looked up very long or random-looking names such as "${q.name.slice(0, 80)}${q.name.length > 80 ? '…' : ''}". Malware sometimes hides data inside DNS lookups ("DNS tunneling").`,
          advice: `Check whether ${base} belongs to software you use (some antivirus and CDNs do this legitimately). If not, block the domain and scan ${dec.src}.`,
          hosts: [dec.src!],
        });
      }
    }
    if (d.response && d.rcode === 3 && dec.dst) {
      const list = this.nxdomain.get(dec.dst) ?? [];
      list.push(ts);
      while (list.length && ts - list[0] > 60) list.shift();
      this.nxdomain.set(dec.dst, list);
      if (list.length >= 20) {
        this.raise(`nx|${dec.dst}`, ts, pid, flowId, {
          severity: 'medium', category: 'security', kind: 'nxdomain-burst',
          title: `Many failed DNS lookups from ${dec.dst}`,
          description: `${this.label(dec.dst)} asked for ${list.length} names that don't exist within a minute. This can be a typo-ed configuration, but it is also how some malware searches for its control server (domain generation).`,
          advice: 'Look at the failed names (Troubleshoot tab). Random-looking names are a red flag; misspelled internal names point to a config problem.',
          hosts: [dec.dst],
        });
      }
    }
  }

  private tls(pid: number, ts: number, dec: Decoded, flowId?: number): void {
    const t = dec.tls!;
    if (t.handshake === 'Server Hello' && ['SSL 3.0', 'TLS 1.0', 'TLS 1.1'].includes(t.version)) {
      this.raise(`oldtls|${dec.src}`, ts, pid, flowId, {
        severity: 'low', category: 'security', kind: 'outdated-tls',
        title: `Outdated encryption (${t.version}) used by ${dec.src}`,
        description: `${this.label(dec.src!)} negotiated ${t.version}, which has known weaknesses and is deprecated.`,
        advice: 'Update the server or client so it uses TLS 1.2 or 1.3.',
        hosts: [dec.src!, dec.dst!],
      });
    }
    if (t.alertDesc && t.alertDesc !== 'close notify' && t.contentType === 'Alert') {
      this.raise(`tlsalert|${dec.src}|${dec.dst}`, ts, pid, flowId, {
        severity: 'low', category: 'performance', kind: 'tls-failure',
        title: `Encrypted connection failed: ${t.alertDesc}`,
        description: `${this.label(dec.src!)} aborted a TLS session with ${this.label(dec.dst!)} with the error "${t.alertDesc}". Common causes are expired/invalid certificates, unsupported versions, or interception by a proxy.`,
        advice: 'Check the certificate and the date/time on both machines, and whether a proxy or antivirus is intercepting HTTPS.',
        hosts: [dec.src!, dec.dst!],
      });
    }
  }

  private flowLevel(pid: number, ts: number, fr: FlowResult): void {
    const f = fr.flow;
    // Unencrypted service in use (once per client/server/service).
    if (f.bPort !== undefined && (f.transport === 'TCP' || f.transport === 'UDP')) {
      const svc = service(f.transport, f.bPort);
      // Only once a conversation really happens (not for scan probes).
      const opened = f.transport === 'UDP' ? fr.dir === 'AB' : fr.tags.includes('handshake-done');
      if (svc?.cleartext && opened) {
        const k = `clear|${f.a}|${f.b}|${svc.name}`;
        if (!this.seenOnce.has(k)) {
          this.seenOnce.add(k);
          this.raise(k, ts, pid, f.id, {
            severity: 'info', category: 'security', kind: 'unencrypted-service',
            title: `Unencrypted ${svc.name} to ${f.bName ?? f.b}`,
            description: `${this.label(f.a)} is talking ${svc.name} (${svc.desc}) with ${this.label(f.b)}. Contents of this connection are readable by anyone on the path.`,
            advice: 'Prefer the encrypted alternative when one exists. Avoid logging in over this connection.',
            hosts: [f.a, f.b],
          });
        }
      }
    }
    // Beaconing: connections to the same external service at a very regular interval.
    if (fr.tags.includes('syn') && !fr.tags.includes('retransmission') && ipScope(f.b) === 'public') {
      const k = `${f.a}|${f.b}|${f.bPort}`;
      const probes = this.beacons.get(k) ?? [];
      probes.push({ ts, pid, flowId: f.id });
      if (probes.length > 30) probes.shift();
      this.beacons.set(k, probes);
      if (probes.length >= 6) {
        const times = probes.map((p) => p.ts!);
        const iv = times.slice(1).map((t, i) => t - times[i]);
        const mean = iv.reduce((s, x) => s + x, 0) / iv.length;
        const sd = Math.sqrt(iv.reduce((s, x) => s + (x - mean) ** 2, 0) / iv.length);
        if (mean >= 5 && sd / mean < 0.1) {
          this.raise(`beacon|${k}`, ts, pid, f.id, {
            severity: 'medium', category: 'security', kind: 'beaconing',
            title: `Regular "check-in" connections to ${f.bName ?? f.b}`,
            description: `${this.label(f.a)} connects to ${this.label(f.b)}:${f.bPort} every ${mean.toFixed(1)} s like clockwork (${times.length} times). Update checkers do this, but so does malware calling home ("beaconing").`,
            advice: `Identify the program responsible on ${f.a}. If the destination is unknown to you, look it up and consider blocking it.`,
            hosts: [f.a, f.b],
          }, probes);
        }
      }
    }
    // Large upload to an external host.
    if (isLocal(f.a) && ipScope(f.b) === 'public' && f.bytesAB > 50 * 1024 * 1024 && fr.dir === 'AB') {
      this.raise(`upload|${f.id}`, ts, pid, f.id, {
        severity: 'medium', category: 'security', kind: 'large-upload',
        title: `Large upload to ${f.bName ?? f.b}`,
        description: `${this.label(f.a)} has sent ${formatBytes(f.bytesAB)} to ${this.label(f.b)} in one connection. This is normal for backups or cloud sync, but could also be data being stolen.`,
        advice: 'Confirm which application is uploading and that the destination is expected.',
        hosts: [f.a, f.b],
      });
    }
    // Packet loss on a connection.
    if (f.transport === 'TCP' && fr.tags.includes('retransmission')) {
      const total = f.packetsAB + f.packetsBA;
      if (f.retransmissions >= 8 && f.retransmissions / total > 0.05) {
        this.raise(`loss|${f.id}`, ts, pid, f.id, {
          severity: f.retransmissions / total > 0.15 ? 'medium' : 'low', category: 'performance', kind: 'packet-loss',
          title: `Packet loss talking to ${f.bName ?? f.b}`,
          description: `${f.retransmissions} of ${total} packets (${((f.retransmissions / total) * 100).toFixed(1)}%) on this connection had to be resent. Expect slowness, stutter or timeouts.`,
          advice: 'Check Wi-Fi signal / cabling, look for a congested link, and test against another server to see if the problem is local.',
          hosts: [f.a, f.b],
        });
      }
    }
    if (fr.tags.includes('zero-window')) {
      this.raise(`zwin|${f.id}`, ts, pid, f.id, {
        severity: 'low', category: 'performance', kind: 'zero-window',
        title: `Receiver overwhelmed on ${f.bName ?? f.b}:${f.bPort}`,
        description: `One side of this connection repeatedly ran out of buffer space (${f.zeroWindows} zero-window packets). The bottleneck is the application or machine, not the network.`,
        advice: 'Look at CPU/disk load on the receiving machine and whether the application is stalling.',
        hosts: [f.a, f.b],
      });
    }
  }
}
