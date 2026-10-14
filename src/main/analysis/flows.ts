// Conversation tracking: groups packets into bidirectional flows and tracks
// TCP state, handshake timing and loss indicators per flow.

import type { FlowSummary } from '../../shared/types';
import type { Decoded } from '../dissect/types';
import { serverPort, service } from '../dissect/services';

const MAX_IDS_PER_FLOW = 20000;

interface DirState {
  nextSeq?: number;
  lastAck?: number;
  lastWin?: number;
  dupAcks: number;
  fin: boolean;
}

export interface FlowRec extends FlowSummary {
  key: string;
  packetIds: number[];
  synTs?: number;
  synAckTs?: number;
  synAckSeq?: number;
  handshakeDone: boolean;
  /** Redis: an AUTH was sent and its reply hasn't been seen yet. */
  dbAuthPending?: boolean;
  dirs: { AB: DirState; BA: DirState };
}

export interface FlowResult {
  flow: FlowRec;
  dir: 'AB' | 'BA';
  tags: string[];
  notes: string[];
}

const newDir = (): DirState => ({ dupAcks: 0, fin: false });

/** a < b for 32-bit wrapping sequence numbers. */
function seqLt(a: number, b: number): boolean {
  return ((a - b) | 0) < 0;
}

export class FlowTracker {
  private byKey = new Map<string, FlowRec>();
  readonly byId = new Map<number, FlowRec>();
  private nextId = 1;
  readonly dirty = new Set<number>();

  clear(): void {
    this.byKey.clear();
    this.byId.clear();
    this.dirty.clear();
    this.nextId = 1;
  }

  all(): FlowRec[] {
    return [...this.byId.values()];
  }

  /**
   * If this TCP packet belongs to a conversation already known to be a database
   * session, return that (so packets on non-standard ports can still be decoded).
   */
  dbHint(dec: Decoded): { system: NonNullable<FlowRec['db']>['system']; fromClient: boolean } | null {
    if (!dec.tcp || !dec.src || !dec.dst) return null;
    const ep1 = `${dec.src}|${dec.tcp.sport}`, ep2 = `${dec.dst}|${dec.tcp.dport}`;
    const flow = this.byKey.get(`TCP/${dec.ipProto}/${ep1 < ep2 ? ep1 + '/' + ep2 : ep2 + '/' + ep1}`);
    if (!flow?.db) return null;
    return { system: flow.db.system, fromClient: dec.src === flow.a && dec.tcp.sport === flow.aPort };
  }

  process(pid: number, ts: number, len: number, dec: Decoded): FlowResult | null {
    const dbNotes: string[] = [];
    const res0 = () => dbNotes;
    if (!dec.src || !dec.dst || dec.arp || dec.fragment) return null;
    let transport: FlowSummary['transport'];
    let sport: number | undefined, dport: number | undefined;
    if (dec.tcp) { transport = 'TCP'; sport = dec.tcp.sport; dport = dec.tcp.dport; }
    else if (dec.udp) { transport = 'UDP'; sport = dec.udp.sport; dport = dec.udp.dport; }
    else if (dec.icmp) transport = dec.icmp.v6 ? 'ICMPv6' : 'ICMP';
    else if (dec.ipVersion) transport = 'OTHER';
    else return null;

    const ep1 = sport !== undefined ? `${dec.src}|${sport}` : dec.src;
    const ep2 = dport !== undefined ? `${dec.dst}|${dport}` : dec.dst;
    const key = `${transport}/${dec.ipProto}/${ep1 < ep2 ? ep1 + '/' + ep2 : ep2 + '/' + ep1}`;
    let flow = this.byKey.get(key);
    let dir: 'AB' | 'BA';
    if (!flow) {
      const srcIsClient = this.srcIsClient(dec, transport, sport, dport);
      flow = {
        id: this.nextId++, key, transport, app: '',
        a: srcIsClient ? dec.src : dec.dst, aPort: srcIsClient ? sport : dport,
        b: srcIsClient ? dec.dst : dec.src, bPort: srcIsClient ? dport : sport,
        firstTs: ts, lastTs: ts, packetsAB: 0, packetsBA: 0, bytesAB: 0, bytesBA: 0,
        state: transport === 'TCP' ? 'opening' : 'stateless',
        retransmissions: 0, resets: 0, zeroWindows: 0, dupAcks: 0, alertCount: 0,
        packetIds: [], handshakeDone: false, dirs: { AB: newDir(), BA: newDir() },
      };
      flow.app = appName(flow, dec);
      this.byKey.set(key, flow);
      this.byId.set(flow.id, flow);
    }
    dir = dec.src === flow.a && (sport === undefined || sport === flow.aPort) ? 'AB' : 'BA';
    if (dir === 'AB') { flow.packetsAB++; flow.bytesAB += len; } else { flow.packetsBA++; flow.bytesBA += len; }
    flow.lastTs = ts;
    if (flow.packetIds.length < MAX_IDS_PER_FLOW) flow.packetIds.push(pid);
    // Upgrade the app label once we see something more specific.
    if (dec.db || flow.db) this.trackDb(flow, dec, res0());
    else if (dec.proto === 'TLS' && flow.app !== 'HTTPS' && flow.app !== 'TLS') flow.app = flow.bPort === 443 ? 'HTTPS' : 'TLS';
    else if (dec.proto === 'HTTP' && flow.app !== 'HTTP') flow.app = 'HTTP';
    else if (dec.proto === 'SSH') flow.app = 'SSH';
    if (dec.tls?.sni && dir === 'AB') flow.bName = dec.tls.sni;
    if (dec.http?.host && dec.http.request) flow.bName = dec.http.host.split(':')[0];
    this.dirty.add(flow.id);

    const res: FlowResult = { flow, dir, tags: [], notes: dbNotes };
    if (flow.db) res.tags.push('database');
    if (dec.tcp) this.tcpState(flow, dir, ts, dec, res);
    return res;
  }

  private srcIsClient(dec: Decoded, transport: string, sport?: number, dport?: number): boolean {
    if (dec.tcp) {
      if (dec.tcp.flags.syn) return !dec.tcp.flags.ack;
    }
    if (dec.icmp) {
      const t = dec.icmp.type;
      return !(t === 0 || t === 129 || t === 3 || t === 11 || t === 1 || t === 3);
    }
    if (dec.dns) return !dec.dns.response;
    if (dec.dhcp) return dec.udp?.sport === 68;
    if (sport !== undefined && dport !== undefined && (transport === 'TCP' || transport === 'UDP')) {
      return serverPort(transport, sport, dport) === dport;
    }
    return true;
  }

  private tcpState(flow: FlowRec, dir: 'AB' | 'BA', ts: number, dec: Decoded, res: FlowResult): void {
    const t = dec.tcp!;
    const fl = t.flags;
    const me = flow.dirs[dir];
    const peer = flow.dirs[dir === 'AB' ? 'BA' : 'AB'];

    if (fl.syn && !fl.ack) {
      res.tags.push('syn');
      if (flow.synTs !== undefined && me.nextSeq === ((t.seq + 1) >>> 0)) {
        res.tags.push('retransmission');
        flow.retransmissions++;
        res.notes.push('This connection request was sent again because no answer came back in time.');
      } else {
        flow.synTs = ts;
      }
      res.notes.push('TCP handshake step 1 of 3: the client asks to open a connection (SYN).');
    } else if (fl.syn && fl.ack) {
      res.tags.push('syn-ack');
      flow.synAckTs = ts;
      flow.synAckSeq = t.seq;
      if (flow.synTs !== undefined) {
        flow.rttMs = Math.max(0, (ts - flow.synTs) * 1000);
        res.notes.push(`The server answered ${flow.rttMs.toFixed(1)} ms after the request - this is the network round-trip time.`);
      }
      res.notes.push('TCP handshake step 2 of 3: the server agrees to the connection (SYN-ACK).');
      flow.state = 'opening';
    } else if (!flow.handshakeDone && flow.synAckSeq !== undefined && fl.ack && dir === 'AB' && t.ack === ((flow.synAckSeq + 1) >>> 0)) {
      flow.handshakeDone = true;
      flow.state = 'established';
      res.tags.push('handshake-done');
      res.notes.push('TCP handshake step 3 of 3: the client confirms. The connection is now open and data can flow.');
    }
    if (fl.rst) {
      res.tags.push('rst');
      flow.resets++;
      flow.state = 'reset';
      if (!flow.handshakeDone && dir === 'BA') {
        res.notes.push(`${flow.b} refused the connection on port ${flow.bPort}. Usually nothing is listening there, or a firewall rejected it.`);
      } else {
        res.notes.push('The connection was aborted immediately (RST) instead of being closed politely.');
      }
    }
    if (fl.fin) {
      res.tags.push('fin');
      me.fin = true;
      if (flow.state !== 'reset') flow.state = peer.fin ? 'closed' : 'closing';
      res.notes.push(peer.fin ? 'Both sides have now finished: the connection is closed.' : 'This side has finished sending and asks to close the connection (FIN).');
    }
    if (!fl.syn && !fl.rst && !fl.fin && flow.state === 'opening' && t.payloadLen > 0) {
      // Joined mid-stream (capture started after the handshake).
      flow.state = 'established';
    }

    // Retransmission: payload that ends at or before data we already saw.
    const segLen = t.payloadLen + (fl.syn ? 1 : 0) + (fl.fin ? 1 : 0);
    if (!fl.syn && segLen > 0 && me.nextSeq !== undefined) {
      const end = (t.seq + segLen) >>> 0;
      if (t.payloadLen === 1 && ((t.seq + 1) >>> 0) === me.nextSeq) {
        res.tags.push('keep-alive');
        res.notes.push('Keep-alive: a tiny probe checking that the other side is still there.');
      } else if (!seqLt(me.nextSeq, end) && seqLt(t.seq, me.nextSeq)) {
        res.tags.push('retransmission');
        flow.retransmissions++;
        res.notes.push('Retransmission: this data was already sent once. The original (or its acknowledgment) was probably lost - a sign of packet loss or congestion.');
      }
    }
    if (segLen > 0) {
      const end = (t.seq + segLen) >>> 0;
      if (me.nextSeq === undefined || seqLt(me.nextSeq, end)) me.nextSeq = end;
    }

    // Duplicate ACKs: same ack, no payload, no window change -> receiver is missing data.
    if (fl.ack && !fl.syn && !fl.fin && !fl.rst && t.payloadLen === 0) {
      if (me.lastAck === t.ack && me.lastWin === t.window && peer.nextSeq !== undefined && seqLt(t.ack, peer.nextSeq)) {
        me.dupAcks++;
        flow.dupAcks++;
        res.tags.push('dup-ack');
        res.notes.push('Duplicate acknowledgment: the receiver is still waiting for a missing piece of data.');
      } else {
        me.dupAcks = 0;
      }
    }
    if (fl.ack) { me.lastAck = t.ack; me.lastWin = t.window; }

    if (t.window === 0 && !fl.rst && !fl.syn) {
      res.tags.push('zero-window');
      flow.zeroWindows++;
      res.notes.push('Zero window: the receiver\'s buffer is full and it asked the sender to pause. The receiving application is not reading data fast enough.');
    }
  }

  /** Accumulate what we learn about a database session across its packets. */
  private trackDb(flow: FlowRec, dec: Decoded, notes: string[]): void {
    const p = dec.db;
    if (!flow.db) {
      if (!p) return;
      flow.db = { system: p.system, encrypted: false, login: 'unknown', failedLogins: 0, queries: 0 };
      flow.app = p.system;
    }
    const s = flow.db;
    if (dec.tls) {
      if (!s.encrypted) notes.push(`This ${s.system} session has switched to TLS encryption, so its logins and queries can no longer be read on the network.`);
      s.encrypted = true;
      return;
    }
    if (!p) return;
    if (p.version) s.version = p.version;
    if (p.user) s.user = p.user;
    if (p.database) s.database = p.database;
    if (p.application) s.application = p.application;
    if (p.system === 'Redis') {
      if (p.fromClient && p.event === 'login') flow.dbAuthPending = true;
      else if (!p.fromClient && flow.dbAuthPending) {
        flow.dbAuthPending = false;
        if (p.event !== 'auth-failed' && !p.error) s.login = 'ok';
      }
    }
    switch (p.event) {
      case 'auth-ok': s.login = 'ok'; break;
      case 'auth-failed': s.login = 'failed'; s.failedLogins++; if (p.error) s.lastError = p.error; break;
      case 'error': if (p.error) s.lastError = p.error; break;
      case 'query': s.queries++; if (p.query) s.lastQuery = p.query; break;
      case 'ssl-accepted': s.encrypted = true; break;
      default: break;
    }
    if (p.encryption === 'on' || p.encryption === 'required') {
      // SQL Server negotiated encryption during pre-login; the login itself will be inside TLS.
      if (!p.fromClient) s.encrypted = true;
    }
  }

  toSummary(f: FlowRec): FlowSummary {
    const { key: _k, packetIds: _p, synTs: _s, synAckTs: _sa, synAckSeq: _q, handshakeDone: _h, dirs: _d, dbAuthPending: _a, ...rest } = f;
    return rest;
  }
}

function appName(flow: FlowRec, dec: Decoded): string {
  if (flow.transport === 'ICMP' || flow.transport === 'ICMPv6') return flow.transport === 'ICMP' ? 'Ping/ICMP' : 'ICMPv6';
  if (dec.dns) return dec.dns.mdns ? dec.proto : 'DNS';
  if (dec.dhcp) return 'DHCP';
  if (dec.quic) return 'QUIC';
  if ((flow.transport === 'TCP' || flow.transport === 'UDP') && flow.bPort !== undefined) {
    const s = service(flow.transport, flow.bPort) ?? (flow.aPort !== undefined ? service(flow.transport, flow.aPort) : undefined);
    if (s) return s.name;
  }
  return flow.transport;
}
