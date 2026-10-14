import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as B from '../src/main/capture/builder';
import { LINKTYPE, PcapStreamReader, writePcapng, type RawFrame } from '../src/main/capture/pcap';
import { dissect } from '../src/main/dissect';
import { DemoSource } from '../src/main/capture/demo';
import { Engine } from '../src/main/engine';
import { parseInterfaceList } from '../src/main/capture/live';

const A = { ip: '192.168.1.10', mac: '02:00:00:00:00:0a' };
const S = { ip: '203.0.113.5', mac: '02:00:00:00:00:01' };
const frame = (data: Uint8Array, ts = 1_700_000_000): RawFrame => ({ ts, linkType: LINKTYPE.ETHERNET, data, origLen: data.length });
const ipPkt = (proto: number, payload: number[]) => B.ethernet(A.mac, S.mac, 0x0800, B.ipv4(A.ip, S.ip, proto, payload));

test('pcapng round trip, delivered in tiny chunks', () => {
  const frames = [frame(ipPkt(17, B.udp(5000, 53, B.dnsQuery(1, 'a.example.com')))), frame(ipPkt(1, B.icmpEcho(false, 1, 1)), 1_700_000_000.123456)];
  const file = writePcapng(frames);
  const out: RawFrame[] = [];
  const r = new PcapStreamReader((f) => out.push(f));
  for (let i = 0; i < file.length; i += 7) r.push(file.subarray(i, i + 7));
  assert.equal(out.length, 2);
  assert.deepEqual([...out[1].data], [...frames[1].data]);
  assert.ok(Math.abs(out[1].ts - frames[1].ts) < 1e-6);
});

test('classic pcap (little endian, microseconds)', () => {
  const data = ipPkt(1, B.icmpEcho(false, 1, 1));
  const hdr = Buffer.alloc(24);
  hdr.writeUInt32LE(0xa1b2c3d4, 0); hdr.writeUInt16LE(2, 4); hdr.writeUInt16LE(4, 6);
  hdr.writeUInt32LE(65535, 16); hdr.writeUInt32LE(1, 20);
  const rec = Buffer.alloc(16);
  rec.writeUInt32LE(1_700_000_001, 0); rec.writeUInt32LE(500000, 4);
  rec.writeUInt32LE(data.length, 8); rec.writeUInt32LE(data.length, 12);
  const out: RawFrame[] = [];
  new PcapStreamReader((f) => out.push(f)).push(Buffer.concat([hdr, rec, Buffer.from(data)]));
  assert.equal(out.length, 1);
  assert.equal(out[0].ts, 1_700_000_001.5);
  assert.equal(dissect(out[0]).proto, 'ICMP');
});

test('DNS query and response with CNAME', () => {
  const q = dissect(frame(ipPkt(17, B.udp(5000, 53, B.dnsQuery(0x1234, 'www.example.com')))));
  assert.equal(q.proto, 'DNS');
  assert.equal(q.dns?.questions[0].name, 'www.example.com');
  const r = dissect(frame(ipPkt(17, B.udp(53, 5000, B.dnsResponse(0x1234, 'www.example.com', ['203.0.113.9'], 0, 'edge.example.net')))));
  assert.equal(r.dns?.response, true);
  assert.deepEqual(r.dns?.answers.map((a) => `${a.type} ${a.data}`), ['CNAME edge.example.net', 'A 203.0.113.9']);
});

test('TLS ClientHello SNI and ALPN', () => {
  const d = dissect(frame(ipPkt(6, B.tcp(A.ip, S.ip, 50000, 443, 1, 1, { ack: true, psh: true }, B.tlsClientHello('secure.example.com')))));
  assert.equal(d.proto, 'TLS');
  assert.equal(d.tls?.sni, 'secure.example.com');
  assert.deepEqual(d.tls?.alpn, ['h2', 'http/1.1']);
});

test('HTTP basic auth is detected but password is never shown', () => {
  const auth = Buffer.from('bob:topsecret').toString('base64');
  const d = dissect(frame(ipPkt(6, B.tcp(A.ip, S.ip, 50000, 80, 1, 1, { ack: true, psh: true }, B.text(`GET / HTTP/1.1\r\nHost: x.example\r\nAuthorization: Basic ${auth}\r\n\r\n`)))));
  assert.equal(d.http?.basicAuthUser, 'bob');
  assert.ok(d.cred);
  assert.ok(!JSON.stringify(d).includes('topsecret'));
  assert.ok(!JSON.stringify(d).includes(auth));
});

test('ARP, DHCP and ICMP unreachable', () => {
  const arp = dissect(frame(B.ethernet(A.mac, 'ff:ff:ff:ff:ff:ff', 0x0806, B.arp(1, A.mac, A.ip, '00:00:00:00:00:00', '192.168.1.1'))));
  assert.equal(arp.info, 'Who has 192.168.1.1? Tell 192.168.1.10');
  const dh = dissect(frame(ipPkt(17, B.udp(67, 68, B.dhcp(5, 7, A.mac, A.ip, { server: '192.168.1.1', dns: ['192.168.1.1'], lease: 3600 })))));
  assert.equal(dh.dhcp?.messageType, 'ACK');
  assert.equal(dh.dhcp?.yourIp, A.ip);
  const orig = B.ipv4(A.ip, S.ip, 17, B.udp(4000, 3478, [1, 2, 3, 4]));
  const un = dissect(frame(ipPkt(1, B.icmpUnreachable(3, orig))));
  assert.equal(un.icmp?.origDst, S.ip);
  assert.equal(un.icmp?.origPort, 3478);
});

test('truncated frames are reported, not thrown', () => {
  const full = ipPkt(6, B.tcp(A.ip, S.ip, 1, 2, 3, 4, { syn: true }));
  const d = dissect(frame(full.subarray(0, 30)));
  assert.ok(d.malformed);
});

test('demo scenario end-to-end: flows, health and every expected detector', () => {
  const engine = new Engine();
  const frames = new DemoSource(() => {}).generate(95);
  for (const f of frames) engine.ingest(f);
  const state = engine.fullState();
  const kinds = new Set(state.alerts.map((a) => a.kind));
  for (const k of ['port-scan', 'arp-spoofing', 'cleartext-credentials', 'suspicious-port', 'dns-tunneling', 'beaconing', 'outdated-tls', 'packet-loss', 'zero-window', 'unreachable', 'unencrypted-service']) {
    assert.ok(kinds.has(k), `expected alert kind ${k}, got ${[...kinds].join(', ')}`);
  }
  // Every alert must point to real evidence packets.
  for (const a of state.alerts) {
    assert.ok(a.packetIds.length > 0, `${a.kind} has no evidence`);
    for (const id of a.packetIds) assert.ok(engine.detail(id), `evidence packet ${id} missing`);
  }
  const https = state.flows.find((f) => f.bName === 'www.example.com' && f.state === 'closed');
  assert.ok(https, 'expected a completed HTTPS conversation to www.example.com');
  assert.ok(https.rttMs! > 0);
  const h = state.stats!.health;
  assert.ok(h.dnsQueries > 10);
  assert.ok(h.medianDnsMs !== null);
  assert.ok(h.failedDnsNames.length > 0);
  assert.ok(h.findings.length > 0);
  // Plain-English explanation is produced for every packet type we decoded.
  for (const p of state.packets.slice(0, 300)) {
    const det = engine.detail(p.id)!;
    assert.ok(det.explanation.length > 0, `no explanation for #${p.id} ${p.proto}`);
  }
});

test('interface list parsing for dumpcap (Windows) and tcpdump (Linux)', () => {
  const win = parseInterfaceList(String.raw`1. \Device\NPF_{1F2E3D4C-0000-1111-2222-333344445555} (Wi-Fi)` + '\r\n' + String.raw`2. \Device\NPF_Loopback (Adapter for loopback traffic capture)` + '\r\n', true);
  assert.deepEqual(win.map((i) => [i.id, i.name]), [
    [String.raw`\Device\NPF_{1F2E3D4C-0000-1111-2222-333344445555}`, 'Wi-Fi'],
    [String.raw`\Device\NPF_Loopback`, 'Adapter for loopback traffic capture'],
  ]);
  const lin = parseInterfaceList('1.enp3s0 [Up, Running, Connected]\n2.wlp2s0 (Wireless) [Up, Running]\n3.any (Pseudo-device that captures on all interfaces) [Up, Running]\n4.lo [Up, Running, Loopback]\n', false);
  assert.deepEqual(lin.map((i) => i.id), ['enp3s0', 'wlp2s0', 'any', 'lo']);
  assert.equal(lin[1].name, 'wlp2s0');
});

test('MikroTik TZSP stream is unwrapped to the real traffic', async () => {
  const { unwrapTzsp } = await import('../src/main/capture/tzsp');
  const inner = B.ethernet(A.mac, S.mac, 0x0800, B.ipv4(A.ip, S.ip, 17, B.udp(5000, 53, B.dnsQuery(7, 'router.example.net'))));
  // version 1, type 0 (received), encapsulation 1 (Ethernet), padding, END tag, frame
  const tzsp = [1, 0, 0, 1, 0, 1, ...inner];
  const outer = frame(B.ethernet('02:00:00:00:00:99', A.mac, 0x0800, B.ipv4('192.168.88.1', A.ip, 17, B.udp(50000, 37008, tzsp))));
  const un = unwrapTzsp(outer);
  assert.deepEqual([...un.data], [...inner]);
  assert.equal(un.ts, outer.ts);
  const e = new Engine();
  e.ingest(outer);
  const p = e.fullState().packets[0];
  assert.equal(p.proto, 'DNS');
  assert.equal(p.src, A.ip);
  // Ordinary traffic on other ports is left alone.
  const plain = frame(ipPkt(17, B.udp(5000, 53, B.dnsQuery(1, 'x.example'))));
  assert.equal(unwrapTzsp(plain), plain);
});

test('gzipped tcpdump file and Linux "any" (SLL2) captures import', async () => {
  const { readCaptureFile } = await import('../src/main/capture/file');
  const { gzipSync } = await import('node:zlib');
  const { writeFileSync, mkdtempSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  // Classic pcap, nanosecond magic, LINKTYPE_LINUX_SLL2 (what `tcpdump -i any` writes on modern Linux).
  const ip = B.ipv4(A.ip, S.ip, 1, B.icmpEcho(false, 3, 4));
  const sll2 = Buffer.alloc(20);
  sll2.writeUInt16BE(0x0800, 0); sll2.writeUInt32BE(2, 4); sll2.writeUInt16BE(1, 8); sll2[10] = 4; sll2[11] = 6;
  const data = Buffer.concat([sll2, Buffer.from(ip)]);
  const hdr = Buffer.alloc(24);
  hdr.writeUInt32LE(0xa1b23c4d, 0); hdr.writeUInt16LE(2, 4); hdr.writeUInt16LE(4, 6);
  hdr.writeUInt32LE(262144, 16); hdr.writeUInt32LE(276, 20);
  const rec = Buffer.alloc(16);
  rec.writeUInt32LE(1_700_000_002, 0); rec.writeUInt32LE(250_000_000, 4);
  rec.writeUInt32LE(data.length, 8); rec.writeUInt32LE(data.length, 12);
  const dir = mkdtempSync(join(tmpdir(), 'pi-test-'));
  try {
    const path = join(dir, 'dump.pcap.gz');
    writeFileSync(path, gzipSync(Buffer.concat([hdr, rec, data])));
    const out: RawFrame[] = [];
    await readCaptureFile(path, (f) => out.push(f));
    assert.equal(out.length, 1);
    assert.equal(out[0].ts, 1_700_000_002.25);
    const d = dissect(out[0]);
    assert.equal(d.proto, 'ICMP');
    assert.equal(d.src, A.ip);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('TZSP listener receives a streamed packet over UDP', async () => {
  const { TzspListener } = await import('../src/main/capture/tzsp');
  const { createSocket } = await import('node:dgram');
  const inner = B.ethernet(A.mac, S.mac, 0x0800, B.ipv4(A.ip, S.ip, 1, B.icmpEcho(false, 1, 1)));
  const port = 47000 + Math.floor(Math.random() * 1000);
  const got = await new Promise<RawFrame>((resolve, reject) => {
    const l = new TzspListener((f) => { l.stop(); resolve(f); }, (err) => reject(new Error(err)));
    l.start(port);
    const tx = createSocket('udp4');
    setTimeout(() => tx.send(Buffer.from([1, 0, 0, 1, 1, ...inner]), port, '127.0.0.1', () => tx.close()), 50);
    setTimeout(() => { l.stop(); reject(new Error('timeout')); }, 3000);
  });
  assert.deepEqual([...got.data], [...inner]);
  assert.equal(dissect(got).proto, 'ICMP');
});

test('Windows built-in capture: handshake, token check and pcap streaming', async () => {
  const { WinRawCapture } = await import('../src/main/capture/winraw');
  const { connect } = await import('node:net');
  const ipPacket = B.ipv4(A.ip, S.ip, 1, B.icmpEcho(false, 9, 9));
  // A fake helper speaking the same protocol as pi-capture.exe.
  const fakeHelper = (tokenOverride?: string) => async (_exe: string, args: string[]) => {
    const [port, token] = args;
    const s = connect(Number(port), '127.0.0.1', () => {
      const hdr = Buffer.alloc(24);
      hdr.writeUInt32LE(0xa1b2c3d4, 0); hdr.writeUInt16LE(2, 4); hdr.writeUInt16LE(4, 6); hdr.writeUInt32LE(65535, 16); hdr.writeUInt32LE(101, 20);
      const rec = Buffer.alloc(16);
      rec.writeUInt32LE(1_700_000_000, 0); rec.writeUInt32LE(ipPacket.length, 8); rec.writeUInt32LE(ipPacket.length, 12);
      s.write(Buffer.concat([Buffer.from(`PIH1 ${tokenOverride ?? token}\nOK\n`), hdr, rec, Buffer.from(ipPacket)]));
    });
    s.on('error', () => {});
  };
  const frames: RawFrame[] = [];
  await new Promise<void>((resolve, reject) => {
    const cap = new WinRawCapture((f) => { frames.push(f); cap.stop(); }, (err) => (err ? reject(new Error(err)) : resolve()));
    cap.start({ addresses: [A.ip], exe: 'fake.exe', launch: fakeHelper() });
  });
  assert.equal(frames.length, 1);
  assert.equal(dissect(frames[0]).proto, 'ICMP');
  // A connection that doesn't know the token is rejected.
  const err = await new Promise<string | undefined>((resolve) => {
    const cap = new WinRawCapture(() => {}, resolve);
    cap.start({ addresses: [A.ip], exe: 'fake.exe', launch: fakeHelper('wrong') });
  });
  assert.match(err ?? '', /could not be verified/);
});

test('Windows capture helper reports a clear error when not elevated', { skip: process.platform !== 'win32' }, async () => {
  const { WinRawCapture } = await import('../src/main/capture/winraw');
  const { spawn } = await import('node:child_process');
  const { existsSync } = await import('node:fs');
  const exe = 'dist/helper/pi-capture.exe';
  if (!existsSync(exe)) return; // helper not built in this environment
  const err = await new Promise<string | undefined>((resolve) => {
    const cap = new WinRawCapture(() => {}, resolve);
    // Launch without UAC: the helper connects, then fails to open the raw socket.
    cap.start({ addresses: ['127.0.0.1'], exe, launch: async (e, args) => { spawn(e, args, { windowsHide: true }); } });
  });
  assert.ok(err && /Could not start capture/.test(err), `unexpected: ${err}`);
});
