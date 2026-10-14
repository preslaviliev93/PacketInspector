import type { EngineUpdate, WatchKind } from '../shared/types';

export type ViewName = 'dashboard' | 'packets' | 'flows' | 'alerts' | 'health' | 'databases' | 'watch';

/** Cross-view navigation: every number in the UI can be traced to packets. */
export interface Ctx {
  go(view: ViewName): void;
  showPackets(filter: string, selectId?: number): void;
  showFlow(flowId: number): void;
  showAlerts(search?: string): void;
  /** Open the Connections tab with a search (used instead of packets in Simple mode). */
  showConnections(search: string): void;
  /** Add an address/network/host/port to the Watchlist. */
  addWatch(kind: WatchKind, value: string, label?: string): void;
}

export interface View {
  /** Called on every engine update while the view is visible. */
  update(u: EngineUpdate): void;
  /** Called when the view becomes visible (full re-render). */
  show(): void;
}

/** Fixed protocol -> categorical slot mapping (color follows the protocol family, never its rank). */
const FAMILY: Record<string, number> = {
  TLS: 1, HTTPS: 1, HTTP: 1, QUIC: 1, 'HTTP-Alt': 1, 'HTTPS-Alt': 1,
  DNS: 2, mDNS: 2, LLMNR: 2, NBNS: 2,
  TCP: 3,
  UDP: 4, NTP: 4, SSDP: 4, STUN: 4, Syslog: 4, SNMP: 4,
  ICMP: 5, ICMPv6: 5, 'Ping/ICMP': 5,
  ARP: 6, DHCP: 6,
  SSH: 7, FTP: 7, SMTP: 7, IMAP: 7, POP3: 7, Telnet: 7, RDP: 7, SMB: 7,
  MySQL: 8, PostgreSQL: 8, MSSQL: 8, MongoDB: 8, Redis: 8, Oracle: 8,
};

export function protoColor(proto: string): string {
  const slot = FAMILY[proto];
  return slot ? `var(--s${slot})` : 'var(--muted)';
}

export const FAMILY_LEGEND: { label: string; slot: number }[] = [
  { label: 'Web / TLS / QUIC', slot: 1 },
  { label: 'DNS', slot: 2 },
  { label: 'TCP (other)', slot: 3 },
  { label: 'UDP (other)', slot: 4 },
  { label: 'ICMP', slot: 5 },
  { label: 'ARP / DHCP', slot: 6 },
  { label: 'Remote / mail / files', slot: 7 },
  { label: 'Databases', slot: 8 },
];
