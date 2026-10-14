// Types shared between the Electron main process (capture + analysis engine)
// and the renderer (UI). Everything here must be structured-clone friendly.

export type Severity = 'info' | 'low' | 'medium' | 'high';
export type AlertCategory = 'security' | 'performance';

/** Compact per-packet row shown in the packet list. Full detail is fetched on demand. */
export interface PacketSummary {
  id: number;
  /** Seconds since epoch (fractional). */
  ts: number;
  len: number;
  src: string;
  dst: string;
  sport?: number;
  dport?: number;
  /** Highest decoded protocol, e.g. "DNS", "TLS", "TCP". */
  proto: string;
  /** One-line, Wireshark-style info column. */
  info: string;
  flowId?: number;
  /** Markers such as "retransmission", "rst", "syn", "alert", "dup-ack", "zero-window". */
  tags: string[];
}

export interface Field {
  label: string;
  value: string;
  /** Byte offset into the frame, for hex highlighting. */
  offset?: number;
  length?: number;
  children?: Field[];
}

export interface Layer {
  name: string;
  summary: string;
  offset: number;
  length: number;
  fields: Field[];
}

export interface PacketDetail {
  summary: PacketSummary;
  layers: Layer[];
  /** Plain-English sentences describing what this packet is doing. */
  explanation: string[];
  /** Raw frame bytes. */
  bytes: Uint8Array;
  linkType: number;
}

export type FlowState = 'opening' | 'established' | 'closing' | 'closed' | 'reset' | 'stateless';

export interface FlowSummary {
  id: number;
  transport: 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' | 'ARP' | 'OTHER';
  /** Application protocol guess: "HTTPS", "DNS", ... */
  app: string;
  /** Client / initiator side. */
  a: string;
  aPort?: number;
  b: string;
  bPort?: number;
  /** Friendly name for the server side when known (DNS answer / TLS SNI / HTTP Host). */
  bName?: string;
  firstTs: number;
  lastTs: number;
  packetsAB: number;
  packetsBA: number;
  bytesAB: number;
  bytesBA: number;
  state: FlowState;
  /** Handshake round-trip time in ms (SYN -> SYN/ACK). */
  rttMs?: number;
  retransmissions: number;
  resets: number;
  zeroWindows: number;
  dupAcks: number;
  alertCount: number;
  /** Present when this conversation is a database session. */
  db?: DbSession;
}

export type DbSystem = 'MySQL' | 'PostgreSQL' | 'MSSQL' | 'MongoDB' | 'Redis' | 'Oracle';

export interface DbSession {
  system: DbSystem;
  /** Server software version, from the server's greeting when visible. */
  version?: string;
  user?: string;
  database?: string;
  /** Client application name, when the protocol carries one. */
  application?: string;
  /** True once the session switched to TLS (contents no longer visible). */
  encrypted: boolean;
  login: 'unknown' | 'ok' | 'failed';
  failedLogins: number;
  queries: number;
  lastQuery?: string;
  lastError?: string;
}

export interface Alert {
  id: number;
  ts: number;
  severity: Severity;
  category: AlertCategory;
  /** Stable detector identifier, e.g. "port-scan". */
  kind: string;
  title: string;
  /** What happened, in plain language. */
  description: string;
  /** What the user could do about it. */
  advice: string;
  /** Packets that triggered this alert ("evidence"). */
  packetIds: number[];
  flowIds: number[];
  hosts: string[];
}

export interface CountItem {
  key: string;
  label?: string;
  packets: number;
  bytes: number;
}

export interface StatsSnapshot {
  totalPackets: number;
  totalBytes: number;
  startTs: number | null;
  lastTs: number | null;
  /** Per-second throughput timeline: newest last. */
  timeline: { t: number; packets: number; bytes: number }[];
  protocols: CountItem[];
  topTalkers: CountItem[];
  topDestinations: CountItem[];
  health: HealthReport;
  /** Number of packets that matched each watch rule, by rule id. */
  watchHits: Record<string, number>;
}

export interface HealthReport {
  tcpFlows: number;
  tcpRetransmissionRate: number; // 0..1 of TCP data packets
  tcpResets: number;
  medianRttMs: number | null;
  dnsQueries: number;
  dnsFailures: number;
  dnsTimeouts: number;
  medianDnsMs: number | null;
  slowDnsNames: { name: string; ms: number }[];
  failedDnsNames: { name: string; rcode: string }[];
  unreachable: number;
  findings: HealthFinding[];
}

export interface HealthFinding {
  status: 'good' | 'warning' | 'serious' | 'critical';
  title: string;
  detail: string;
  /** Everyday wording for Simple mode. */
  plainTitle: string;
  plainDetail: string;
}

export type InterfaceKind = 'Ethernet' | 'Wi-Fi' | 'VPN' | 'Virtual' | 'Loopback' | 'Bluetooth' | 'All interfaces' | 'Other';

export interface CaptureInterface {
  id: string;
  name: string;
  description?: string;
  addresses?: string[];
  mac?: string;
  kind?: InterfaceKind;
  /** False when the adapter exists but no capture tool is installed to capture on it. */
  available?: boolean;
}

/** dumpcap/tcpdump: full link-layer capture. windows: built-in raw sockets (IP level, needs admin approval). */
export type CaptureBackend = 'dumpcap' | 'tcpdump' | 'windows';

export interface CaptureToolInfo {
  backend: CaptureBackend | null;
  path: string | null;
  /** Human-readable setup instructions when capture is unavailable. */
  help: string;
  platform: string;
}

export interface CaptureStatus {
  state: 'idle' | 'capturing' | 'reading' | 'stopped' | 'error';
  source: string;
  message?: string;
  /** A persistent, non-error notice for the banner, optionally with a fix-it button. */
  notice?: { text: string; action?: 'allow-firewall' };
}

export interface EngineUpdate {
  packets: PacketSummary[];
  flows: FlowSummary[];
  alerts: Alert[];
  stats?: StatsSnapshot;
  status?: CaptureStatus;
  reset?: boolean;
  /** A one-off message to show briefly. */
  toast?: string;
}

export interface StartCaptureOptions {
  interfaceId: string;
  captureFilter?: string;
}

/** API exposed to the renderer via the preload script. */
export type WatchKind = 'ip' | 'network' | 'host' | 'port';

/** A user-defined rule: alert whenever traffic involves this address, network, host name or port. */
export interface WatchRule {
  id: string;
  kind: WatchKind;
  value: string;
  label?: string;
  severity: Severity;
  enabled: boolean;
  created: number;
}

export interface PacketInspectorApi {
  getToolInfo(): Promise<CaptureToolInfo>;
  getVersion(): Promise<string>;
  listInterfaces(): Promise<CaptureInterface[]>;
  startCapture(opts: StartCaptureOptions): Promise<void>;
  startDemo(): Promise<void>;
  stopCapture(): Promise<void>;
  openFile(): Promise<boolean>;
  /** Import a file dropped onto the window. */
  importFile(file: File): Promise<boolean>;
  saveCapture(packetIds?: number[]): Promise<string | null>;
  exportCsv(kind: 'flows' | 'alerts' | 'packets'): Promise<string | null>;
  clear(): Promise<void>;
  getPacketDetail(id: number): Promise<PacketDetail | null>;
  getFlowPackets(flowId: number): Promise<PacketSummary[]>;
  getWatchRules(): Promise<WatchRule[]>;
  /** Windows: add the inbound UDP 37008 firewall rule for the MikroTik stream (one admin prompt). */
  allowStreamFirewall(): Promise<{ ok: boolean; error?: string }>;
  /** Replace the whole rule list; returns the saved list. */
  saveWatchRules(rules: WatchRule[]): Promise<WatchRule[]>;
  onUpdate(cb: (u: EngineUpdate) => void): () => void;
}
