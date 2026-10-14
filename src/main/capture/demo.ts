// Demo traffic generator: a scripted but realistic home network so the app
// can be explored without capture privileges. Uses documentation-only
// addresses (RFC 1918 / RFC 5737) and example domains.

import * as B from './builder';
import * as DB from './builder-db';
import { LINKTYPE, type RawFrame } from './pcap';

const ME = { ip: '192.168.1.23', mac: '02:00:00:00:00:23' };
const GW = { ip: '192.168.1.1', mac: '02:00:00:00:00:01' };
const NAS = { ip: '192.168.1.40', mac: '02:00:00:00:00:40' };
const EVIL = { ip: '192.168.1.66', mac: '02:00:00:00:00:66' };
const BCAST = 'ff:ff:ff:ff:ff:ff';

const SITES = [
  { name: 'www.example.com', ip: '93.184.215.14' },
  { name: 'api.example.net', ip: '203.0.113.21' },
  { name: 'cdn.example.org', ip: '198.51.100.35', cname: 'edge-7.cdn.example.org' },
  { name: 'docs.example.com', ip: '203.0.113.45' },
  { name: 'mail.example.net', ip: '198.51.100.60' },
  { name: 'video.example.org', ip: '203.0.113.80' },
];

type Pending = { at: number; data: Uint8Array };

export class DemoSource {
  private queue: Pending[] = [];
  private timer: NodeJS.Timeout | null = null;
  private t0 = 0;
  private nextBrowse = 0;
  private nextPing = 1;
  private nextBeacon = 4;
  private nextQuic = 2;
  private nextMdns = 3;
  private cycleStart = 0;
  private fired = new Set<string>();
  private ephem = 50000;
  private dnsId = 1000;
  private pingSeq = 1;
  private rand: () => number;

  constructor(private onFrame: (f: RawFrame) => void, seed = 42) {
    // Small deterministic PRNG so demo runs look the same each time.
    let s = seed >>> 0;
    this.rand = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296);
  }

  start(): void {
    this.t0 = Date.now() / 1000;
    this.cycleStart = this.t0;
    this.timer = setInterval(() => this.tick(), 50);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Generate `seconds` of traffic instantly (used by tests). */
  generate(seconds: number, startTs = 1_700_000_000): RawFrame[] {
    const out: RawFrame[] = [];
    const saved = this.onFrame;
    this.onFrame = (f) => out.push(f);
    this.t0 = startTs;
    this.cycleStart = startTs;
    for (let t = startTs; t < startTs + seconds; t += 0.05) this.step(t);
    this.flushUntil(Infinity);
    this.onFrame = saved;
    return out;
  }

  private tick(): void {
    this.step(Date.now() / 1000);
  }

  private step(now: number): void {
    const el = now - this.t0;
    if (el >= this.nextBrowse) { this.browse(now); this.nextBrowse = el + 1.2 + this.rand() * 2; }
    if (el >= this.nextPing) { this.ping(now); this.nextPing = el + 3; }
    if (el >= this.nextBeacon) { this.beacon(now); this.nextBeacon = el + 6; }
    if (el >= this.nextQuic) { this.quic(now); this.nextQuic = el + 0.7 + this.rand(); }
    if (el >= this.nextMdns) { this.mdns(now); this.nextMdns = el + 9; }

    // Scripted incidents, repeating every 90 seconds.
    const c = now - this.cycleStart;
    const once = (key: string, at: number, fn: () => void) => {
      if (c >= at && !this.fired.has(key)) { this.fired.add(key); fn(); }
    };
    once('dhcp', 0.2, () => this.dhcp(now));
    once('arp', 0.5, () => this.arpLookup(now));
    once('http', 6, () => this.plainHttp(now));
    once('refused', 10, () => this.refused(now));
    once('scan', 14, () => this.portScan(now));
    once('nx', 20, () => this.nxdomains(now));
    once('spoof', 26, () => this.arpSpoof(now));
    once('tunnel', 32, () => this.dnsTunnel(now));
    once('backdoor', 38, () => this.backdoor(now));
    once('lossy', 44, () => this.lossyDownload(now));
    once('ftp', 50, () => this.ftpLogin(now));
    once('oldtls', 56, () => this.oldTls(now));
    once('unreach', 60, () => this.unreachable(now));
    once('mysql', 64, () => this.mysqlApp(now));
    once('pgbrute', 68, () => this.postgresBruteForce(now));
    once('redis', 72, () => this.cloudRedis(now));
    once('mssql', 76, () => this.exposedSqlServer(now));
    if (c >= 90) { this.cycleStart = now; this.fired.clear(); }

    this.flushUntil(now);
  }

  private flushUntil(now: number): void {
    if (!this.queue.length) return;
    this.queue.sort((a, b) => a.at - b.at);
    let i = 0;
    while (i < this.queue.length && this.queue[i].at <= now) {
      const p = this.queue[i++];
      this.onFrame({ ts: p.at, linkType: LINKTYPE.ETHERNET, data: p.data, origLen: p.data.length });
    }
    this.queue.splice(0, i);
  }

  private emit(at: number, data: Uint8Array): void {
    this.queue.push({ at, data });
  }

  // ------------------------------------------------------------ helpers

  private ip(at: number, srcMac: string, dstMac: string, src: string, dst: string, proto: number, payload: number[], ttl = 64): void {
    this.emit(at, B.ethernet(srcMac, dstMac, 0x0800, B.ipv4(src, dst, proto, payload, ttl, Math.floor(this.rand() * 65535))));
  }

  /** Packet between this machine and a remote IP (always via the gateway's MAC). */
  private out(at: number, dst: string, proto: number, payload: number[]): void {
    this.ip(at, ME.mac, GW.mac, ME.ip, dst, proto, payload);
  }
  private in(at: number, src: string, proto: number, payload: number[], ttl = 56): void {
    this.ip(at, GW.mac, ME.mac, src, ME.ip, proto, payload, ttl);
  }

  private dnsLookup(t: number, name: string, ips: string[], latency: number, rcode = 0, cname?: string, type = 1): number {
    const id = this.dnsId++ & 0xffff;
    const port = this.ephem++;
    this.out(t, GW.ip, 17, B.udp(port, 53, B.dnsQuery(id, name, type)));
    this.in(t + latency, GW.ip, 17, B.udp(53, port, B.dnsResponse(id, name, ips, rcode, cname)), 64);
    return t + latency;
  }

  /** A full TLS connection to `ip`; returns end time. */
  private tlsSession(t: number, ip: string, sni: string, rtt: number, chunks: number, lossEvery = 0): number {
    const sport = this.ephem++;
    let cs = Math.floor(this.rand() * 2 ** 31), ss = Math.floor(this.rand() * 2 ** 31);
    const o = (p: number[]) => B.tcp(ME.ip, ip, sport, 443, cs, ss, { ack: true, psh: p.length > 0 }, p);
    this.out(t, ip, 6, B.tcp(ME.ip, ip, sport, 443, cs, 0, { syn: true }));
    this.in(t + rtt, ip, 6, B.tcp(ip, ME.ip, 443, sport, ss, cs + 1, { syn: true, ack: true }));
    cs++; ss++;
    t += rtt;
    this.out(t + 0.0002, ip, 6, B.tcp(ME.ip, ip, sport, 443, cs, ss, { ack: true }));
    const ch = B.tlsClientHello(sni);
    this.out(t + 0.0005, ip, 6, o(ch));
    cs += ch.length;
    const sh = B.tlsServerHello();
    this.in(t + rtt, ip, 6, B.tcp(ip, ME.ip, 443, sport, ss, cs, { ack: true, psh: true }, sh));
    ss += sh.length;
    t += rtt;
    for (let i = 0; i < chunks; i++) {
      const req = B.tlsAppData(120 + Math.floor(this.rand() * 300));
      this.out(t + 0.001, ip, 6, B.tcp(ME.ip, ip, sport, 443, cs, ss, { ack: true, psh: true }, req));
      cs += req.length;
      const resp = B.tlsAppData(900 + Math.floor(this.rand() * 500));
      this.in(t + rtt, ip, 6, B.tcp(ip, ME.ip, 443, sport, ss, cs, { ack: true, psh: true }, resp));
      if (lossEvery && i % lossEvery === 1) {
        // Original was "lost" - the server resends it after a timeout.
        this.in(t + rtt + 0.2, ip, 6, B.tcp(ip, ME.ip, 443, sport, ss, cs, { ack: true, psh: true }, resp));
        t += 0.2;
      }
      ss += resp.length;
      this.out(t + rtt + 0.0003, ip, 6, B.tcp(ME.ip, ip, sport, 443, cs, ss, { ack: true }));
      t += rtt + 0.01;
    }
    this.out(t + 0.05, ip, 6, B.tcp(ME.ip, ip, sport, 443, cs, ss, { fin: true, ack: true }));
    this.in(t + 0.05 + rtt, ip, 6, B.tcp(ip, ME.ip, 443, sport, ss, cs + 1, { fin: true, ack: true }));
    this.out(t + 0.0502 + rtt, ip, 6, B.tcp(ME.ip, ip, sport, 443, cs + 1, ss + 1, { ack: true }));
    return t + rtt;
  }

  // ------------------------------------------------------------ background traffic

  private browse(t: number): void {
    const site = SITES[Math.floor(this.rand() * SITES.length)];
    const slow = this.rand() < 0.08;
    const t1 = this.dnsLookup(t, site.name, [site.ip], slow ? 0.32 : 0.012 + this.rand() * 0.02, 0, site.cname);
    this.tlsSession(t1 + 0.001, site.ip, site.name, 0.018 + this.rand() * 0.03, 2 + Math.floor(this.rand() * 4));
  }

  private ping(t: number): void {
    const seq = this.pingSeq++;
    this.ip(t, ME.mac, GW.mac, ME.ip, GW.ip, 1, B.icmpEcho(false, 7, seq));
    this.ip(t + 0.0012, GW.mac, ME.mac, GW.ip, ME.ip, 1, B.icmpEcho(true, 7, seq));
  }

  private beacon(t: number): void {
    // Short HTTPS check-in at a fixed interval -> triggers "beaconing".
    const ip = '203.0.113.77';
    if (this.pingSeq < 3) this.dnsLookup(t - 0.02, 'updates.example-telemetry.net', [ip], 0.015);
    this.tlsSession(t, ip, 'updates.example-telemetry.net', 0.04, 1);
  }

  private quic(t: number): void {
    const ip = '203.0.113.80';
    const port = 61000;
    const n = 4 + Math.floor(this.rand() * 6);
    for (let i = 0; i < n; i++) {
      const len = 1200 + Math.floor(this.rand() * 50);
      const payload = [0x40 | (i & 0x3f), ...Array.from({ length: len }, (_, k) => (k * 17 + i) & 0xff)];
      this.in(t + i * 0.002, ip, 17, B.udp(443, port, payload));
    }
    this.out(t + n * 0.002 + 0.001, ip, 17, B.udp(port, 443, [0x41, ...Array.from({ length: 40 }, (_, k) => k)]));
  }

  private mdns(t: number): void {
    this.emit(t, B.ethernet(NAS.mac, '01:00:5e:00:00:fb', 0x0800, B.ipv4(NAS.ip, '224.0.0.251', 17, B.udp(5353, 5353, B.dnsQuery(0, '_printer._tcp.local', 12)), 255)));
  }

  // ------------------------------------------------------------ incidents

  private dhcp(t: number): void {
    const xid = 0x3903f326;
    const b = (src: string, dst: string, srcMac: string, dstMac: string, sp: number, dp: number, p: number[]) =>
      this.emit(t, B.ethernet(srcMac, dstMac, 0x0800, B.ipv4(src, dst, 17, B.udp(sp, dp, p), 64)));
    b('0.0.0.0', '255.255.255.255', ME.mac, BCAST, 68, 67, B.dhcp(1, xid, ME.mac, '0.0.0.0', { hostname: 'demo-laptop' }));
    t += 0.004;
    b(GW.ip, '255.255.255.255', GW.mac, BCAST, 67, 68, B.dhcp(2, xid, ME.mac, ME.ip, { server: GW.ip, router: GW.ip, dns: [GW.ip], lease: 86400 }));
    t += 0.002;
    b('0.0.0.0', '255.255.255.255', ME.mac, BCAST, 68, 67, B.dhcp(3, xid, ME.mac, '0.0.0.0', { server: GW.ip, requested: ME.ip, hostname: 'demo-laptop' }));
    t += 0.003;
    b(GW.ip, '255.255.255.255', GW.mac, BCAST, 67, 68, B.dhcp(5, xid, ME.mac, ME.ip, { server: GW.ip, router: GW.ip, dns: [GW.ip], lease: 86400 }));
  }

  private arpLookup(t: number): void {
    this.emit(t, B.ethernet(ME.mac, BCAST, 0x0806, B.arp(1, ME.mac, ME.ip, '00:00:00:00:00:00', GW.ip)));
    this.emit(t + 0.001, B.ethernet(GW.mac, ME.mac, 0x0806, B.arp(2, GW.mac, GW.ip, ME.mac, ME.ip)));
  }

  private arpSpoof(t: number): void {
    // A device on the LAN starts claiming to be the gateway.
    for (let i = 0; i < 3; i++) {
      this.emit(t + i * 0.5, B.ethernet(EVIL.mac, ME.mac, 0x0806, B.arp(2, EVIL.mac, GW.ip, ME.mac, ME.ip)));
    }
    // ...and the real gateway answers again shortly after, flipping it back.
    this.emit(t + 2, B.ethernet(GW.mac, ME.mac, 0x0806, B.arp(2, GW.mac, GW.ip, ME.mac, ME.ip)));
  }

  private plainHttp(t: number): void {
    const ip = '198.51.100.20';
    const host = 'shop.example.org';
    const t1 = this.dnsLookup(t, host, [ip], 0.018);
    const sport = this.ephem++;
    let cs = 1000, ss = 5000;
    const rtt = 0.03;
    t = t1 + 0.001;
    this.out(t, ip, 6, B.tcp(ME.ip, ip, sport, 80, cs, 0, { syn: true }));
    this.in(t + rtt, ip, 6, B.tcp(ip, ME.ip, 80, sport, ss, cs + 1, { syn: true, ack: true }));
    cs++; ss++;
    t += rtt;
    this.out(t + 0.0002, ip, 6, B.tcp(ME.ip, ip, sport, 80, cs, ss, { ack: true }));
    const auth = Buffer.from('alice:hunter2').toString('base64');
    const req = B.text(`GET /account/orders HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0 (demo)\r\nAuthorization: Basic ${auth}\r\nAccept: */*\r\n\r\n`);
    this.out(t + 0.0004, ip, 6, B.tcp(ME.ip, ip, sport, 80, cs, ss, { ack: true, psh: true }, req));
    cs += req.length;
    const resp = B.text('HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 42\r\n\r\n<html><body>Your orders: none</body></html>');
    this.in(t + rtt, ip, 6, B.tcp(ip, ME.ip, 80, sport, ss, cs, { ack: true, psh: true }, resp));
    ss += resp.length;
    this.out(t + rtt + 0.001, ip, 6, B.tcp(ME.ip, ip, sport, 80, cs, ss, { ack: true, fin: true }));
    this.in(t + 2 * rtt, ip, 6, B.tcp(ip, ME.ip, 80, sport, ss, cs + 1, { ack: true, fin: true }));
    this.out(t + 2 * rtt + 0.001, ip, 6, B.tcp(ME.ip, ip, sport, 80, cs + 1, ss + 1, { ack: true }));
  }

  private refused(t: number): void {
    for (let i = 0; i < 3; i++) {
      const sport = this.ephem++;
      const tt = t + i * 1.0;
      this.ip(tt, ME.mac, NAS.mac, ME.ip, NAS.ip, 6, B.tcp(ME.ip, NAS.ip, sport, 8080, 777, 0, { syn: true }));
      this.ip(tt + 0.0008, NAS.mac, ME.mac, NAS.ip, ME.ip, 6, B.tcp(NAS.ip, ME.ip, 8080, sport, 0, 778, { rst: true, ack: true }));
    }
  }

  private portScan(t: number): void {
    const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 9200];
    ports.forEach((p, i) => {
      const at = t + i * 0.015;
      const sport = 40000 + i;
      this.ip(at, EVIL.mac, ME.mac, EVIL.ip, ME.ip, 6, B.tcp(EVIL.ip, ME.ip, sport, p, 9000 + i, 0, { syn: true }, [], 1024));
      if (p === 445 || p === 3389) {
        this.ip(at + 0.0004, ME.mac, EVIL.mac, ME.ip, EVIL.ip, 6, B.tcp(ME.ip, EVIL.ip, p, sport, 3000, 9001 + i, { syn: true, ack: true }));
        this.ip(at + 0.0008, EVIL.mac, ME.mac, EVIL.ip, ME.ip, 6, B.tcp(EVIL.ip, ME.ip, sport, p, 9001 + i, 0, { rst: true }));
      } else {
        this.ip(at + 0.0004, ME.mac, EVIL.mac, ME.ip, EVIL.ip, 6, B.tcp(ME.ip, EVIL.ip, p, sport, 0, 9001 + i, { rst: true, ack: true }));
      }
    });
  }

  private nxdomains(t: number): void {
    const names = ['intranet.local.example', 'wpad.example.lan', 'printr.example.lan'];
    names.forEach((n, i) => this.dnsLookup(t + i * 0.3, n, [], 0.02, 3));
  }

  private dnsTunnel(t: number): void {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 4; i++) {
      let label = '';
      for (let k = 0; k < 48; k++) label += chars[Math.floor(this.rand() * chars.length)];
      this.dnsLookup(t + i * 0.4, `${label}.q.example-data.net`, [], 0.03, 3, undefined, 16);
    }
  }

  private backdoor(t: number): void {
    const ip = '203.0.113.99';
    const sport = this.ephem++;
    const rtt = 0.09;
    this.out(t, ip, 6, B.tcp(ME.ip, ip, sport, 4444, 100, 0, { syn: true }));
    this.in(t + rtt, ip, 6, B.tcp(ip, ME.ip, 4444, sport, 900, 101, { syn: true, ack: true }));
    this.out(t + rtt + 0.001, ip, 6, B.tcp(ME.ip, ip, sport, 4444, 101, 901, { ack: true }));
    const data = B.text('id\nuid=1000(demo) gid=1000(demo)\n');
    this.in(t + rtt + 0.3, ip, 6, B.tcp(ip, ME.ip, 4444, sport, 901, 101, { ack: true, psh: true }, B.text('id\n')));
    this.out(t + rtt + 0.31, ip, 6, B.tcp(ME.ip, ip, sport, 4444, 101, 904, { ack: true, psh: true }, data));
  }

  private lossyDownload(t: number): void {
    const site = SITES[5];
    const t1 = this.dnsLookup(t, site.name, [site.ip], 0.02);
    this.tlsSession(t1, site.ip, site.name, 0.06, 30, 2);
    // A burst of zero-window from our side: the app stalls reading.
    const sport = this.ephem++;
    const ip = '203.0.113.21';
    this.out(t1 + 1, ip, 6, B.tcp(ME.ip, ip, sport, 443, 10, 20, { syn: true }));
    this.in(t1 + 1.03, ip, 6, B.tcp(ip, ME.ip, 443, sport, 20, 11, { syn: true, ack: true }));
    this.out(t1 + 1.031, ip, 6, B.tcp(ME.ip, ip, sport, 443, 11, 21, { ack: true }));
    let ss = 21;
    for (let i = 0; i < 4; i++) {
      const d = B.tlsAppData(1300);
      this.in(t1 + 1.05 + i * 0.01, ip, 6, B.tcp(ip, ME.ip, 443, sport, ss, 11, { ack: true }, d));
      ss += d.length;
    }
    this.out(t1 + 1.1, ip, 6, B.tcp(ME.ip, ip, sport, 443, 11, ss, { ack: true }, [], 0));
    this.out(t1 + 1.4, ip, 6, B.tcp(ME.ip, ip, sport, 443, 11, ss, { ack: true }, [], 0));
    this.out(t1 + 2.0, ip, 6, B.tcp(ME.ip, ip, sport, 443, 11, ss, { ack: true }, [], 65535));
  }

  private ftpLogin(t: number): void {
    const ip = NAS.ip;
    const sport = this.ephem++;
    let cs = 50, ss = 80;
    const send = (at: number, fromMe: boolean, s: string) => {
      const p = B.text(s);
      if (fromMe) { this.ip(at, ME.mac, NAS.mac, ME.ip, ip, 6, B.tcp(ME.ip, ip, sport, 21, cs, ss, { ack: true, psh: true }, p)); cs += p.length; }
      else { this.ip(at, NAS.mac, ME.mac, ip, ME.ip, 6, B.tcp(ip, ME.ip, 21, sport, ss, cs, { ack: true, psh: true }, p)); ss += p.length; }
    };
    this.ip(t, ME.mac, NAS.mac, ME.ip, ip, 6, B.tcp(ME.ip, ip, sport, 21, cs, 0, { syn: true }));
    this.ip(t + 0.001, NAS.mac, ME.mac, ip, ME.ip, 6, B.tcp(ip, ME.ip, 21, sport, ss, cs + 1, { syn: true, ack: true }));
    cs++; ss++;
    this.ip(t + 0.0012, ME.mac, NAS.mac, ME.ip, ip, 6, B.tcp(ME.ip, ip, sport, 21, cs, ss, { ack: true }));
    send(t + 0.01, false, '220 NAS FTP server ready\r\n');
    send(t + 0.5, true, 'USER backup\r\n');
    send(t + 0.51, false, '331 Password required\r\n');
    send(t + 1.2, true, 'PASS s3cret!\r\n');
    send(t + 1.21, false, '230 Login successful\r\n');
  }

  private oldTls(t: number): void {
    const ip = NAS.ip;
    const sport = this.ephem++;
    this.ip(t, ME.mac, NAS.mac, ME.ip, ip, 6, B.tcp(ME.ip, ip, sport, 443, 1, 0, { syn: true }));
    this.ip(t + 0.001, NAS.mac, ME.mac, ip, ME.ip, 6, B.tcp(ip, ME.ip, 443, sport, 1, 2, { syn: true, ack: true }));
    this.ip(t + 0.0012, ME.mac, NAS.mac, ME.ip, ip, 6, B.tcp(ME.ip, ip, sport, 443, 2, 2, { ack: true }));
    const ch = B.tlsClientHello('nas.example.lan');
    this.ip(t + 0.002, ME.mac, NAS.mac, ME.ip, ip, 6, B.tcp(ME.ip, ip, sport, 443, 2, 2, { ack: true, psh: true }, ch));
    const sh = B.tlsServerHello('TLS 1.0');
    this.ip(t + 0.004, NAS.mac, ME.mac, ip, ME.ip, 6, B.tcp(ip, ME.ip, 443, sport, 2, 2 + ch.length, { ack: true, psh: true }, sh));
  }


  // ------------------------------------------------------------ databases

  /**
   * One TCP conversation: handshake, then each step's payload in order, then FIN.
   * A step is [fromClient, payload, delay-before-it in seconds].
   */
  private tcpTalk(t: number, c: { ip: string; mac: string }, s: { ip: string; mac: string }, sport: number, dport: number, steps: [boolean, number[], number][]): number {
    let cs = 1000 + Math.floor(this.rand() * 100000), ss = 5000 + Math.floor(this.rand() * 100000);
    const send = (at: number, fromClient: boolean, flags: B.TcpFlags, payload: number[] = []) => {
      if (fromClient) this.ip(at, c.mac, s.mac, c.ip, s.ip, 6, B.tcp(c.ip, s.ip, sport, dport, cs, ss, flags, payload));
      else this.ip(at, s.mac, c.mac, s.ip, c.ip, 6, B.tcp(s.ip, c.ip, dport, sport, ss, cs, flags, payload));
    };
    send(t, true, { syn: true }); cs++;
    t += 0.002; send(t, false, { syn: true, ack: true }); ss++;
    t += 0.0002; send(t, true, { ack: true });
    for (const [fromClient, payload, delay] of steps) {
      t += delay;
      send(t, fromClient, { ack: true, psh: true }, payload);
      if (fromClient) cs += payload.length; else ss += payload.length;
    }
    t += 0.01; send(t, true, { fin: true, ack: true }); cs++;
    t += 0.002; send(t, false, { fin: true, ack: true }); ss++;
    send(t + 0.0002, true, { ack: true });
    return t;
  }

  /** The laptop's shop app talks to MySQL on the NAS, unencrypted, and sends one injection-looking query. */
  private mysqlApp(t: number): void {
    this.tcpTalk(t, ME, NAS, this.ephem++, 3306, [
      [false, DB.mysqlGreeting('8.0.36'), 0.001],
      [true, DB.mysqlLogin('shop_app', 'shop'), 0.002],
      [false, DB.mysqlOk(2), 0.002],
      [true, DB.mysqlQuery('SELECT id, name, price FROM products WHERE category = 7 LIMIT 20'), 0.05],
      [false, DB.mysqlOk(1), 0.003],
      [true, DB.mysqlQuery("SELECT name FROM products WHERE id = '1' UNION SELECT password FROM users -- '"), 0.4],
      [false, DB.mysqlOk(1), 0.003],
    ]);
  }

  /** Someone on the LAN guesses the postgres password over and over. */
  private postgresBruteForce(t: number): void {
    for (let i = 0; i < 6; i++) {
      this.tcpTalk(t + i * 0.35, EVIL, NAS, this.ephem++, 5432, [
        [true, DB.pgStartup('postgres', 'postgres', 'pgcrack'), 0.001],
        [false, DB.pgAuthRequest(5), 0.001],
        [true, DB.pgPassword(), 0.001],
        [false, DB.pgError('28P01', 'password authentication failed for user "postgres"'), 0.004],
      ]);
    }
  }

  /** The laptop uses a Redis cache on the internet, with the password in clear text. */
  private cloudRedis(t: number): void {
    const cloud = { ip: '203.0.113.50', mac: GW.mac };
    this.tcpTalk(t, ME, cloud, this.ephem++, 6379, [
      [true, DB.redisCommand('AUTH', 'cache-s3cret'), 0.001],
      [false, DB.redisReply('+OK'), 0.03],
      [true, DB.redisCommand('GET', 'session:4f2a'), 0.01],
      [false, DB.redisReply('$-1'), 0.03],
    ]);
  }

  /** A host on the internet logs in to SQL Server on the NAS (port forwarded by mistake). */
  private exposedSqlServer(t: number): void {
    const outsider = { ip: '198.51.100.77', mac: GW.mac };
    this.tcpTalk(t, outsider, NAS, this.ephem++, 1433, [
      [true, DB.tdsPrelogin(0), 0.001],
      [false, DB.tdsPrelogin(2, [15, 0, 2000]), 0.002],
      [true, DB.tdsLogin7('sa', 'Summer2024', 'master', 'KALI', 'sqlmap'), 0.002],
      [false, DB.tdsLoginFailed('sa'), 0.01],
    ]);
  }

  private unreachable(t: number): void {
    const dst = '198.51.100.250';
    for (let i = 0; i < 3; i++) {
      const port = this.ephem++;
      const q = B.udp(port, 3478, Array.from({ length: 20 }, (_, k) => k));
      const orig = B.ipv4(ME.ip, dst, 17, q);
      this.out(t + i, dst, 17, q);
      this.in(t + i + 0.05, '198.51.100.1', 1, B.icmpUnreachable(1, orig), 250);
    }
  }
}
