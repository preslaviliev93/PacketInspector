// Renderer-side state, fed by batched engine updates.

import type { Alert, CaptureStatus, EngineUpdate, FlowSummary, PacketInspectorApi, PacketSummary, StatsSnapshot } from '../shared/types';

declare global {
  interface Window {
    pi: PacketInspectorApi & { getFullState(): Promise<EngineUpdate & { status: CaptureStatus }> };
  }
}

export type Listener = (u: EngineUpdate) => void;

export class Store {
  packets: PacketSummary[] = [];
  flows = new Map<number, FlowSummary>();
  alerts = new Map<number, Alert>();
  stats: StatsSnapshot | null = null;
  status: CaptureStatus = { state: 'idle', source: '' };
  /** Resolved names learned from flows (server side). */
  names = new Map<string, string>();
  private listeners: Listener[] = [];

  subscribe(l: Listener): void {
    this.listeners.push(l);
  }

  apply(u: EngineUpdate): void {
    if (u.reset) {
      this.packets = [];
      this.flows.clear();
      this.alerts.clear();
      this.names.clear();
      this.stats = null;
    }
    if (u.packets.length) {
      for (const p of u.packets) this.packets.push(p);
    }
    for (const f of u.flows) {
      this.flows.set(f.id, f);
      if (f.bName) this.names.set(f.b, f.bName);
    }
    for (const a of u.alerts) this.alerts.set(a.id, a);
    if (u.stats) {
      this.stats = u.stats;
      for (const t of [...u.stats.topTalkers, ...u.stats.topDestinations]) if (t.label) this.names.set(t.key, t.label);
    }
    if (u.status) this.status = u.status;
    for (const l of this.listeners) l(u);
  }

  nameOf(ip: string): string | undefined {
    return this.names.get(ip);
  }

  alertsBySeverity(): Record<Alert['severity'], number> {
    const c = { high: 0, medium: 0, low: 0, info: 0 };
    for (const a of this.alerts.values()) c[a.severity]++;
    return c;
  }
}

export const store = new Store();
