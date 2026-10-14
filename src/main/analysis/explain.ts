// Turns a decoded packet into a few plain-English sentences.

import type { Decoded } from '../dissect/types';
import { service } from '../dissect/services';
import { ipScope } from '../dissect/util';

export function explain(dec: Decoded, nameOf: (ip: string) => string | undefined, notes: string[]): string[] {
  const out: string[] = [];
  const who = (ip?: string) => {
    if (!ip) return 'an unknown host';
    const n = nameOf(ip);
    const scope = ipScope(ip);
    const tag = scope === 'private' ? 'a device on your network' : scope === 'loopback' ? 'this computer' : scope === 'multicast' ? 'a multicast group' : scope === 'broadcast' ? 'everyone on the local network' : '';
    return n ? `${ip} (${n})` : tag ? `${ip} (${tag})` : ip;
  };
  const src = who(dec.src), dst = who(dec.dst);

  if (dec.malformed) out.push(`⚠ Part of this packet could not be decoded (${dec.malformed}). It may be truncated by the capture or genuinely malformed.`);

  if (dec.arp) {
    const a = dec.arp;
    if (a.op === 'request' && a.senderIp === a.targetIp) out.push(`${a.senderIp} is announcing to the whole local network that it uses hardware address ${a.senderMac} ("gratuitous ARP"). Devices do this when they join the network or change addresses.`);
    else if (a.op === 'request') out.push(`${a.senderIp} is asking every device on the local network: "Who has ${a.targetIp}? Tell me your hardware (MAC) address." This is how devices find each other on a LAN before they can talk.`);
    else out.push(`Answer to an ARP question: "${a.senderIp} is at hardware address ${a.senderMac}."`);
  } else if (dec.dns) {
    const d = dec.dns;
    const q = d.questions[0];
    const kind = q?.type === 'A' ? 'IPv4 address' : q?.type === 'AAAA' ? 'IPv6 address' : q?.type === 'PTR' ? 'name belonging to an address' : `${q?.type} record`;
    if (!d.response) {
      out.push(d.mdns
        ? `${src} is asking devices on the local network about "${q?.name}" (${dec.proto} - used for printers, speakers and other local discovery).`
        : `${src} is asking the DNS server ${dst}: "What is the ${kind} of ${q?.name}?" - this is the phone-book lookup that happens before connecting to a website or service.`);
    } else if (d.rcode !== 0) {
      out.push(`The DNS server ${src} answered that the lookup for "${q?.name}" failed: ${d.rcodeName}.`);
      if (d.rcode === 3) out.push('The name does not exist. Typos, removed websites, or software probing for names cause this.');
      if (d.rcode === 2) out.push('The DNS server itself had a problem - name resolution may be broken for everyone using it.');
    } else if (d.answers.length) {
      const addrs = d.answers.filter((a) => a.type === 'A' || a.type === 'AAAA').map((a) => a.data);
      const cname = d.answers.find((a) => a.type === 'CNAME');
      out.push(`The DNS server ${src} answered: "${q?.name}" ${addrs.length ? `is at ${addrs.slice(0, 4).join(', ')}${addrs.length > 4 ? '…' : ''}` : `→ ${d.answers.map((a) => `${a.type} ${a.data}`).slice(0, 3).join(', ')}`}.`);
      if (cname) out.push(`It is an alias (CNAME) for ${cname.data}, which is common for sites hosted on content delivery networks.`);
    } else {
      out.push(`The DNS server ${src} answered the lookup for "${q?.name}" but returned no ${kind}.`);
    }
  } else if (dec.dhcp) {
    const h = dec.dhcp;
    const m: Record<string, string> = {
      Discover: `A device (${h.clientMac}${h.hostname ? `, "${h.hostname}"` : ''}) has just joined the network and is shouting "Is there a DHCP server? I need an IP address."`,
      Offer: `The DHCP server ${dec.src} offers the address ${h.yourIp} to device ${h.clientMac}.`,
      Request: `Device ${h.clientMac} asks to use ${h.requestedIp ?? 'the offered address'}.`,
      ACK: `The DHCP server ${dec.src} confirms: device ${h.clientMac} may use ${h.yourIp}${h.leaseSecs ? ` for ${Math.round(h.leaseSecs / 60)} minutes` : ''}${h.router ? `, gateway ${h.router}` : ''}${h.dns?.length ? `, DNS ${h.dns.join(', ')}` : ''}.`,
      NAK: `The DHCP server refused the request from ${h.clientMac}. The device must start over.`,
      Release: `Device ${h.clientMac} gives back its IP address.`,
    };
    out.push(m[h.messageType] ?? `DHCP ${h.messageType} message for ${h.clientMac}.`);
  } else if (dec.tls) {
    const t = dec.tls;
    if (t.handshake === 'Client Hello') out.push(`${src} starts an encrypted (TLS) session with ${dst}${t.sni ? ` and says it wants to reach "${t.sni}"` : ''}. The content that follows will be unreadable to anyone in between - only the name above is visible.`);
    else if (t.handshake === 'Server Hello') out.push(`${src} accepts the encrypted session and picks ${t.version}.`);
    else if (t.contentType === 'Application Data') out.push(`Encrypted data between ${src} and ${dst}. The contents are protected by ${t.version === 'TLS 1.2' || t.version === 'TLS 1.3' ? 'modern' : t.version} encryption and cannot be inspected.`);
    else if (t.contentType === 'Alert') out.push(`A TLS alert: ${t.alertDesc}. ${t.alertDesc === 'close notify' ? 'This is just a polite goodbye.' : 'The encrypted session ran into an error.'}`);
    else out.push(`Part of the encryption setup (${t.handshake ?? t.contentType}) between ${src} and ${dst}.`);
  } else if (dec.http) {
    const h = dec.http;
    if (h.request) out.push(`${src} asks the web server ${h.host ?? dst} for "${h.uri}" (${h.method}). This is plain, unencrypted HTTP - anyone on the path can read and modify it.`);
    else out.push(`The web server ${src} answered with status ${h.status} ${h.reason ?? ''}${h.status && h.status >= 400 ? ' - an error' : ''}${h.contentType ? `, sending ${h.contentType}` : ''}.`);
  } else if (dec.ssh) {
    out.push(`${src} announces it speaks SSH (${dec.ssh.banner}). Everything after this is encrypted.`);
  } else if (dec.db) {
    const p = dec.db;
    const db = p.system === 'MSSQL' ? 'SQL Server' : p.system;
    const client = p.fromClient ? src : dst, server = p.fromClient ? dst : src;
    const m: Record<string, string> = {
      greeting: `The ${db} server ${server} greets the client and announces its version${p.version ? ` (${p.version})` : ''}. Version strings like this help attackers pick exploits, so keep the server patched.`,
      'ssl-request': `${client} asks the ${db} server to switch to TLS before logging in. Good: the login and queries that follow will be encrypted.`,
      'ssl-accepted': `The ${db} server agrees to encrypt the session. From here on, contents are not readable.`,
      'ssl-refused': `The ${db} server refused to encrypt the session, so the login and queries that follow travel in clear text.`,
      login: `${client} logs in to the ${db} database on ${server}${p.user ? ` as "${p.user}"` : ''}${p.database ? `, using database "${p.database}"` : ''}${p.application ? ` from ${p.application}` : ''}.`,
      'auth-challenge': `The ${db} server asks ${client} to prove who it is (send a password or password hash).`,
      password: `${client} answers the password request. The password itself is hidden here.`,
      'auth-ok': `The ${db} server accepted the login${p.version ? `; it runs version ${p.version}` : ''}.`,
      'auth-failed': `The ${db} server rejected the login: ${p.error ?? 'authentication failed'}. Many of these in a row can mean someone is guessing passwords.`,
      query: `${client} runs a ${db} ${p.system === 'Redis' || p.system === 'MongoDB' ? 'command' : 'query'}: ${p.query}`,
      error: `The ${db} server returned an error: ${p.error}.`,
      quit: `${client} ends its ${db} session.`,
    };
    out.push(m[p.event] ?? `${db} traffic between ${client} and ${server}.`);
    if (['login', 'query'].includes(p.event)) out.push('Because this is readable in the capture, the session is not encrypted.');
  } else if (dec.quic) {
    out.push(`QUIC traffic between ${src} and ${dst} - the encrypted, UDP-based transport used by HTTP/3 (YouTube, Google and many CDNs).`);
  } else if (dec.icmp) {
    const i = dec.icmp;
    if (i.typeName === 'Echo request') out.push(`${src} is "pinging" ${dst}: "Are you there?"`);
    else if (i.typeName === 'Echo reply') out.push(`${src} answers the ping: "Yes, I'm here."`);
    else if (i.typeName === 'Destination unreachable') out.push(`${src} reports that ${i.origDst ?? 'a destination'}${i.origPort ? ` port ${i.origPort}` : ''} cannot be reached. The original packet was dropped.`);
    else if (i.typeName === 'Time exceeded') out.push(`${src} dropped a packet because it travelled through too many routers (TTL reached zero). Traceroute uses this on purpose; otherwise it hints at a routing loop.`);
    else if (i.typeName === 'Neighbor solicitation') out.push(`IPv6 neighbor discovery: asking who has ${i.ndpTarget} (the IPv6 equivalent of an ARP request).`);
    else if (i.typeName === 'Neighbor advertisement') out.push(`IPv6 neighbor discovery: ${i.ndpTarget} announces its hardware address.`);
    else if (i.typeName === 'Router advertisement') out.push(`An IPv6 router (${dec.src}) announces itself and the network settings devices should use.`);
    else out.push(`${dec.proto} control message: ${i.typeName}.`);
  } else if (dec.cred || ['FTP', 'POP3', 'IMAP', 'SMTP', 'Telnet'].includes(dec.proto)) {
    out.push(`${dec.proto} command/response between ${src} and ${dst}: "${dec.info}". This protocol is unencrypted.`);
  } else if (dec.tcp) {
    const t = dec.tcp;
    const svc = service('TCP', t.dport) ?? service('TCP', t.sport);
    const svcTxt = svc ? ` (${svc.name} - ${svc.desc})` : '';
    if (t.payloadLen > 0) out.push(`${src} sends ${t.payloadLen} bytes of data to ${dst} on port ${t.dport}${svcTxt}.`);
    else if (!t.flags.syn && !t.flags.fin && !t.flags.rst) out.push(`${src} acknowledges data received from ${dst} ("got it, up to byte ${t.ack}").`);
    else if (t.flags.syn && !t.flags.ack) out.push(`${src} wants to open a connection to ${dst} on port ${t.dport}${svcTxt}.`);
  } else if (dec.udp) {
    const u = dec.udp;
    const svc = service('UDP', u.dport) ?? service('UDP', u.sport);
    out.push(`${src} sends a ${u.payloadLen}-byte UDP datagram to ${dst} port ${u.dport}${svc ? ` (${svc.name} - ${svc.desc})` : ''}. UDP is "fire and forget": no connection, no delivery guarantee.`);
  } else if (dec.ipVersion) {
    out.push(`IP packet from ${src} to ${dst} carrying ${dec.proto}.`);
  } else {
    out.push(`Link-layer frame (${dec.proto}). ${dec.info}`);
  }

  if (dec.cred) out.push(`⚠ Credentials exposed: ${dec.cred.detail}.`);
  if (dec.ttl !== undefined && dec.ttl <= 2 && !dec.icmp) out.push(`Its time-to-live is only ${dec.ttl}, so it can cross at most ${dec.ttl} more router(s).`);
  out.push(...notes);
  return out;
}
