import type { Layer } from '../../shared/types';

export interface TcpInfo {
  sport: number;
  dport: number;
  seq: number;
  ack: number;
  flags: { syn: boolean; ack: boolean; fin: boolean; rst: boolean; psh: boolean; urg: boolean };
  window: number;
  payloadOffset: number;
  payloadLen: number;
  mss?: number;
  wscale?: number;
}

export interface UdpInfo {
  sport: number;
  dport: number;
  payloadOffset: number;
  payloadLen: number;
}

export interface DnsRecord {
  name: string;
  type: string;
  ttl?: number;
  data?: string;
}

export interface DnsInfo {
  id: number;
  response: boolean;
  rcode: number;
  rcodeName: string;
  questions: DnsRecord[];
  answers: DnsRecord[];
  mdns: boolean;
}

export interface HttpInfo {
  request: boolean;
  method?: string;
  uri?: string;
  status?: number;
  reason?: string;
  host?: string;
  userAgent?: string;
  contentType?: string;
  server?: string;
  basicAuthUser?: string;
}

export interface TlsInfo {
  version: string;
  contentType: string;
  handshake?: string;
  sni?: string;
  alpn?: string[];
  alertDesc?: string;
}

export interface DhcpInfo {
  messageType: string;
  clientMac: string;
  xid: number;
  yourIp?: string;
  requestedIp?: string;
  serverId?: string;
  hostname?: string;
  router?: string;
  dns?: string[];
  leaseSecs?: number;
}

export interface ArpInfo {
  op: 'request' | 'reply' | 'other';
  senderMac: string;
  senderIp: string;
  targetMac: string;
  targetIp: string;
}

export interface IcmpInfo {
  v6: boolean;
  type: number;
  code: number;
  typeName: string;
  echoId?: number;
  echoSeq?: number;
  /** For "destination unreachable"/"time exceeded": the original packet's destination. */
  origDst?: string;
  origProto?: string;
  origPort?: number;
  ndpTarget?: string;
}

export interface CleartextCred {
  protocol: string;
  /** What was seen, with secrets masked. */
  detail: string;
}

export interface Decoded {
  layers: Layer[];
  linkSrc?: string;
  linkDst?: string;
  ipVersion?: 4 | 6;
  src?: string;
  dst?: string;
  ttl?: number;
  ipProto?: number;
  fragment?: boolean;
  tcp?: TcpInfo;
  udp?: UdpInfo;
  icmp?: IcmpInfo;
  arp?: ArpInfo;
  dns?: DnsInfo;
  http?: HttpInfo;
  tls?: TlsInfo;
  dhcp?: DhcpInfo;
  quic?: { longHeader: boolean; version?: string };
  ssh?: { banner: string };
  cred?: CleartextCred;
  db?: import('./db').DbPacket;
  /** Highest protocol name, e.g. "DNS". */
  proto: string;
  info: string;
  malformed?: string;
}
