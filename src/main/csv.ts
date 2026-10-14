import type { Engine } from './engine';

function cell(v: unknown): string {
  const s = v === undefined || v === null ? '' : String(v);
  // Quote when needed; neutralise spreadsheet formula injection.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

function rows(header: string[], data: unknown[][]): string {
  return [header, ...data].map((r) => r.map(cell).join(',')).join('\r\n') + '\r\n';
}

const iso = (ts: number) => new Date(ts * 1000).toISOString();

export function toCsv(kind: 'flows' | 'alerts' | 'packets', engine: Engine): string {
  if (kind === 'flows') {
    return rows(
      ['id', 'transport', 'app', 'client', 'client_port', 'server', 'server_port', 'server_name', 'first_seen', 'last_seen', 'packets_out', 'packets_in', 'bytes_out', 'bytes_in', 'state', 'rtt_ms', 'retransmissions', 'resets', 'zero_windows', 'alerts'],
      engine.flows.all().map((f) => [f.id, f.transport, f.app, f.a, f.aPort, f.b, f.bPort, f.bName ?? engine.nameOf(f.b), iso(f.firstTs), iso(f.lastTs), f.packetsAB, f.packetsBA, f.bytesAB, f.bytesBA, f.state, f.rttMs?.toFixed(2), f.retransmissions, f.resets, f.zeroWindows, f.alertCount]),
    );
  }
  if (kind === 'alerts') {
    return rows(
      ['id', 'time', 'severity', 'category', 'kind', 'title', 'description', 'advice', 'hosts', 'evidence_packets'],
      engine.detectors.all().map((a) => [a.id, iso(a.ts), a.severity, a.category, a.kind, a.title, a.description, a.advice, a.hosts.join(' '), a.packetIds.join(' ')]),
    );
  }
  return rows(
    ['no', 'time', 'source', 'src_port', 'destination', 'dst_port', 'protocol', 'length', 'info', 'connection', 'tags'],
    engine.allSummaries().map((p) => [p.id, iso(p.ts), p.src, p.sport, p.dst, p.dport, p.proto, p.len, p.info, p.flowId, p.tags.join(' ')]),
  );
}
