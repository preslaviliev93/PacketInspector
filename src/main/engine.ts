// The analysis engine: receives raw frames from any source, dissects them,
// updates flows/stats/detectors, and hands batched updates to the UI.

import type { Alert, CaptureStatus, EngineUpdate, PacketDetail, PacketSummary } from '../shared/types';
import type { RawFrame } from './capture/pcap';
import { unwrapTzsp } from './capture/tzsp';
import { dissect } from './dissect';
import type { Decoded } from './dissect/types';
import { FlowTracker } from './analysis/flows';
import { Detectors } from './analysis/detectors';
import { Stats } from './analysis/stats';
import { explain } from './analysis/explain';
import { dissectDb } from './dissect/db';
import { WatchMatcher, type WatchMatch } from '../shared/watch';
import type { WatchRule } from '../shared/types';

/** Packets whose raw bytes are retained for detail view / export. Analysis continues beyond this. */
export const MAX_STORED_PACKETS = 300_000;

export class Engine {
  private frames: RawFrame[] = [];
  private summaries: PacketSummary[] = [];
  private notes = new Map<number, string[]>();
  private names = new Map<string, string>();
  private nextId = 1;
  readonly flows = new FlowTracker();
  readonly stats = new Stats();
  readonly detectors = new Detectors((ip) => this.names.get(ip));

  private pendingPackets: PacketSummary[] = [];
  private pendingStatus: CaptureStatus | undefined;
  private pendingReset = false;
  private storageFullNotified = false;
  private tzspNotified = false;
  private pendingToast: string | undefined;

  nameOf = (ip: string): string | undefined => this.names.get(ip);
  private watcher = new WatchMatcher();
  private watchHits: Record<string, number> = {};

  /** Replace the active watch rules. Applies to packets from now on. */
  setWatchRules(rules: WatchRule[]): void {
    this.watcher.set(rules);
    const keep = new Set(rules.map((r) => r.id));
    for (const id of Object.keys(this.watchHits)) if (!keep.has(id)) delete this.watchHits[id];
  }

  /** Decode a frame, using conversation context for databases on non-standard ports. */
  private decode(frame: RawFrame): Decoded {
    const dec = dissect(frame);
    if (!dec.db && dec.tcp && dec.tcp.payloadLen > 0 && !dec.tls) {
      const hint = this.flows.dbHint(dec);
      if (hint) {
        const t = dec.tcp;
        dissectDb(dec, frame.data, t.payloadOffset, t.payloadOffset + t.payloadLen, hint.system, hint.fromClient);
      }
    }
    return dec;
  }

  private watchMatches(dec: Decoded, sport?: number, dport?: number): WatchMatch[] {
    if (this.watcher.empty) return [];
    const hostNames: { name: string; via: string }[] = [];
    for (const q of dec.dns?.questions ?? []) hostNames.push({ name: q.name.toLowerCase(), via: 'DNS lookup' });
    if (dec.tls?.sni) hostNames.push({ name: dec.tls.sni.toLowerCase(), via: 'TLS server name' });
    if (dec.http?.host) hostNames.push({ name: dec.http.host.split(':')[0].toLowerCase(), via: 'HTTP Host header' });
    for (const ip of [dec.src, dec.dst]) {
      const n = ip ? this.names.get(ip) : undefined;
      if (n) hostNames.push({ name: n.toLowerCase(), via: 'resolved name' });
    }
    const ip = dec.ipVersion !== undefined;
    const matches = this.watcher.match({ src: ip ? dec.src : undefined, dst: ip ? dec.dst : undefined, sport, dport, hostNames });
    for (const m of matches) this.watchHits[m.rule.id] = (this.watchHits[m.rule.id] ?? 0) + 1;
    return matches;
  }

  reset(): void {
    this.frames = [];
    this.summaries = [];
    this.notes.clear();
    this.names.clear();
    this.nextId = 1;
    this.flows.clear();
    this.stats.clear();
    this.detectors.clear();
    for (const k of Object.keys(this.watchHits)) delete this.watchHits[k];
    this.pendingPackets = [];
    this.pendingReset = true;
    this.storageFullNotified = false;
    this.tzspNotified = false;
  }

  setStatus(s: CaptureStatus): void {
    this.pendingStatus = s;
  }

  get packetCount(): number {
    return this.nextId - 1;
  }

  ingest(raw: RawFrame): void {
    // MikroTik streams (TZSP) are unwrapped so the real traffic is analysed.
    const frame = unwrapTzsp(raw);
    const fromStream = frame !== raw;
    if (fromStream && !this.tzspNotified) {
      this.tzspNotified = true;
      this.pendingToast = ('MikroTik stream detected: its packets are unwrapped, so you see the router\'s real traffic (not UDP 37008). Filter them with "From MikroTik stream".');
    }
    const id = this.nextId++;
    const dec = this.decode(frame);
    const len = frame.origLen || frame.data.length;
    this.learnNames(dec);

    const fr = this.flows.process(id, frame.ts, len, dec);
    const tags = fr ? [...fr.tags] : [];
    const sp = dec.tcp?.sport ?? dec.udp?.sport, dp = dec.tcp?.dport ?? dec.udp?.dport;
    const alertTags = this.detectors.inspect(id, frame.ts, dec, fr, this.watchMatches(dec, sp, dp));
    tags.push(...alertTags);
    if (dec.cred) tags.push('credentials');
    if (fromStream) tags.push('mikrotik');
    if (dec.dns?.response && dec.dns.rcode !== 0) tags.push('dns-error');
    if (dec.malformed) tags.push('malformed');
    if (fr && alertTags.length) fr.flow.alertCount = this.detectors.all().filter((a) => a.flowIds.includes(fr.flow.id)).length;

    const statNotes = this.stats.add(id, frame.ts, len, dec);
    if (fr?.notes.length) this.addNote(id, ...fr.notes);
    for (const [pid, n] of statNotes) this.addNote(pid, n);

    const summary: PacketSummary = {
      id, ts: frame.ts, len,
      src: dec.src ?? dec.linkSrc ?? '?',
      dst: dec.dst ?? dec.linkDst ?? '?',
      proto: dec.proto,
      info: dec.info,
      tags,
    };
    if (dec.tcp) { summary.sport = dec.tcp.sport; summary.dport = dec.tcp.dport; }
    else if (dec.udp) { summary.sport = dec.udp.sport; summary.dport = dec.udp.dport; }
    if (fr) summary.flowId = fr.flow.id;
    if (tags.includes('retransmission')) summary.info = `[Retransmission] ${summary.info}`;
    else if (tags.includes('dup-ack')) summary.info = `[Dup ACK] ${summary.info}`;
    else if (tags.includes('zero-window')) summary.info = `[Zero window] ${summary.info}`;

    if (this.frames.length < MAX_STORED_PACKETS) {
      this.frames.push(frame);
      this.summaries.push(summary);
      this.pendingPackets.push(summary);
    } else if (!this.storageFullNotified) {
      this.storageFullNotified = true;
      this.pendingStatus = {
        state: this.pendingStatus?.state ?? 'capturing',
        source: this.pendingStatus?.source ?? '',
        message: `Packet list is full (${MAX_STORED_PACKETS.toLocaleString()} packets). Statistics, connections and alerts keep updating; save and clear to keep the packet list going.`,
      };
    }
  }

  private addNote(pid: number, ...n: string[]): void {
    const cur = this.notes.get(pid);
    if (cur) cur.push(...n); else this.notes.set(pid, [...n]);
  }

  private learnNames(dec: Decoded): void {
    if (dec.dns?.response && dec.dns.rcode === 0) {
      const asked = dec.dns.questions[0]?.name;
      for (const a of dec.dns.answers) {
        if ((a.type === 'A' || a.type === 'AAAA') && a.data) this.names.set(a.data, asked && !dec.dns.mdns ? asked : a.name);
      }
    }
    if (dec.tls?.sni && dec.dst && !this.names.has(dec.dst)) this.names.set(dec.dst, dec.tls.sni);
    if (dec.http?.request && dec.http.host && dec.dst && !this.names.has(dec.dst)) this.names.set(dec.dst, dec.http.host.split(':')[0]);
    if (dec.dhcp?.hostname && dec.dhcp.requestedIp) this.names.set(dec.dhcp.requestedIp, dec.dhcp.hostname);
  }

  /** Drain pending changes into an update for the renderer. */
  flush(includeStats: boolean): EngineUpdate | null {
    const flows = [...this.flows.dirty].map((id) => this.flows.toSummary(this.flows.byId.get(id)!));
    this.flows.dirty.clear();
    const alerts: Alert[] = [...this.detectors.changed].map((a) => ({ ...a, packetIds: [...a.packetIds], flowIds: [...a.flowIds] }));
    this.detectors.changed.clear();
    for (const f of flows) {
      if (!f.bName) { const n = this.names.get(f.b); if (n) f.bName = n; }
    }
    const u: EngineUpdate = { packets: this.pendingPackets, flows, alerts };
    this.pendingPackets = [];
    if (includeStats) u.stats = { ...this.stats.snapshot(this.flows.all(), this.nameOf), watchHits: { ...this.watchHits } };
    if (this.pendingStatus) { u.status = this.pendingStatus; this.pendingStatus = undefined; }
    if (this.pendingReset) { u.reset = true; this.pendingReset = false; }
    if (this.pendingToast) { u.toast = this.pendingToast; this.pendingToast = undefined; }
    if (!u.packets.length && !flows.length && !alerts.length && !u.status && !u.reset && !u.toast && !includeStats) return null;
    return u;
  }

  /** Full state, for when a renderer (re)loads. */
  fullState(): EngineUpdate {
    return {
      reset: true,
      packets: this.summaries,
      flows: this.flows.all().map((f) => {
        const s = this.flows.toSummary(f);
        if (!s.bName) s.bName = this.names.get(s.b);
        return s;
      }),
      alerts: this.detectors.all(),
      stats: { ...this.stats.snapshot(this.flows.all(), this.nameOf), watchHits: { ...this.watchHits } },
    };
  }

  detail(id: number): PacketDetail | null {
    const frame = this.frames[id - 1];
    const summary = this.summaries[id - 1];
    if (!frame || !summary) return null;
    const dec = this.decode(frame);
    return {
      summary,
      layers: dec.layers,
      explanation: explain(dec, this.nameOf, this.notes.get(id) ?? []),
      bytes: frame.data,
      linkType: frame.linkType,
    };
  }

  flowPackets(flowId: number): PacketSummary[] {
    const f = this.flows.byId.get(flowId);
    if (!f) return [];
    return f.packetIds.map((id) => this.summaries[id - 1]).filter(Boolean);
  }

  framesFor(ids?: number[]): RawFrame[] {
    if (!ids) return this.frames;
    return ids.map((id) => this.frames[id - 1]).filter(Boolean);
  }

  allSummaries(): PacketSummary[] {
    return this.summaries;
  }
}
