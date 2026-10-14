// Well-known ports -> service names and short, friendly descriptions.

interface Service {
  name: string;
  desc: string;
  /** Traffic on this port is unencrypted and may expose credentials/content. */
  cleartext?: boolean;
}

const TCP: Record<number, Service> = {
  20: { name: 'FTP-DATA', desc: 'file transfer data', cleartext: true },
  21: { name: 'FTP', desc: 'file transfer (unencrypted)', cleartext: true },
  22: { name: 'SSH', desc: 'secure remote shell' },
  23: { name: 'Telnet', desc: 'remote terminal (unencrypted)', cleartext: true },
  25: { name: 'SMTP', desc: 'email delivery', cleartext: true },
  53: { name: 'DNS', desc: 'name lookup' },
  80: { name: 'HTTP', desc: 'web (unencrypted)', cleartext: true },
  110: { name: 'POP3', desc: 'email retrieval (unencrypted)', cleartext: true },
  135: { name: 'MS-RPC', desc: 'Windows RPC' },
  139: { name: 'NetBIOS', desc: 'Windows file sharing (legacy)' },
  143: { name: 'IMAP', desc: 'email retrieval (unencrypted)', cleartext: true },
  389: { name: 'LDAP', desc: 'directory service', cleartext: true },
  443: { name: 'HTTPS', desc: 'secure web' },
  445: { name: 'SMB', desc: 'Windows file sharing' },
  465: { name: 'SMTPS', desc: 'secure email delivery' },
  587: { name: 'SMTP', desc: 'email submission' },
  636: { name: 'LDAPS', desc: 'secure directory service' },
  853: { name: 'DoT', desc: 'DNS over TLS' },
  993: { name: 'IMAPS', desc: 'secure email retrieval' },
  995: { name: 'POP3S', desc: 'secure email retrieval' },
  1433: { name: 'MSSQL', desc: 'Microsoft SQL Server' },
  1883: { name: 'MQTT', desc: 'IoT messaging (unencrypted)', cleartext: true },
  3306: { name: 'MySQL', desc: 'MySQL database' },
  3389: { name: 'RDP', desc: 'Windows Remote Desktop' },
  5222: { name: 'XMPP', desc: 'chat messaging' },
  5432: { name: 'PostgreSQL', desc: 'PostgreSQL database' },
  5900: { name: 'VNC', desc: 'remote desktop (VNC)' },
  6379: { name: 'Redis', desc: 'Redis database' },
  6667: { name: 'IRC', desc: 'IRC chat' },
  8080: { name: 'HTTP-Alt', desc: 'web (alternate port)', cleartext: true },
  8443: { name: 'HTTPS-Alt', desc: 'secure web (alternate port)' },
  9200: { name: 'Elasticsearch', desc: 'search database' },
  27017: { name: 'MongoDB', desc: 'MongoDB database' },
};

const UDP: Record<number, Service> = {
  53: { name: 'DNS', desc: 'name lookup' },
  67: { name: 'DHCP', desc: 'automatic IP configuration' },
  68: { name: 'DHCP', desc: 'automatic IP configuration' },
  69: { name: 'TFTP', desc: 'trivial file transfer', cleartext: true },
  123: { name: 'NTP', desc: 'clock synchronization' },
  137: { name: 'NBNS', desc: 'NetBIOS name service' },
  138: { name: 'NetBIOS-DGM', desc: 'NetBIOS datagrams' },
  161: { name: 'SNMP', desc: 'device management', cleartext: true },
  443: { name: 'QUIC', desc: 'secure web over QUIC/HTTP3' },
  500: { name: 'IKE', desc: 'VPN key exchange' },
  514: { name: 'Syslog', desc: 'system logging' },
  1900: { name: 'SSDP', desc: 'device discovery (UPnP)' },
  3478: { name: 'STUN', desc: 'NAT traversal (calls/video)' },
  4500: { name: 'IPsec-NAT', desc: 'VPN traffic' },
  5353: { name: 'mDNS', desc: 'local device discovery' },
  5355: { name: 'LLMNR', desc: 'local name resolution' },
  51820: { name: 'WireGuard', desc: 'VPN traffic' },
};

/** Ports commonly associated with malware, backdoors or attack tooling. */
export const SUSPICIOUS_PORTS: Record<number, string> = {
  1337: 'often used by backdoors and hacking tools',
  4444: 'default port of Metasploit reverse shells',
  5555: 'Android debug bridge / common backdoor port',
  6666: 'IRC / commonly used by botnets',
  6667: 'IRC, frequently used for botnet command & control',
  12345: 'NetBus trojan default port',
  31337: 'classic "elite" backdoor port (Back Orifice)',
  9001: 'Tor relay traffic',
  9050: 'Tor SOCKS proxy',
};

export function service(transport: 'TCP' | 'UDP', port: number): Service | undefined {
  return (transport === 'TCP' ? TCP : UDP)[port];
}

/** Choose the server port of a pair: the well-known one, otherwise the lower one. */
export function serverPort(transport: 'TCP' | 'UDP', a: number, b: number): number {
  const sa = service(transport, a), sb = service(transport, b);
  if (sa && !sb) return a;
  if (sb && !sa) return b;
  return Math.min(a, b);
}

export function portLabel(transport: 'TCP' | 'UDP', port: number): string {
  const s = service(transport, port);
  return s ? `${port} (${s.name})` : String(port);
}
