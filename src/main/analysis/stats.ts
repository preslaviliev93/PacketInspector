// Aggregate statistics and the network "health" report.

import type { CountItem, HealthFinding, HealthReport, StatsSnapshot } from '../../shared/types';
import type { Decoded } from '../dissect/types';
import type { FlowRec } from './flows';
import { ipScope } from '../dissect/util';

const TIMELINE_SECONDS = 300;
const DNS_TIMEOUT_S = 5;

interface Counter { packets: number; bytes: number }

interface PendingDns { ts: number; pid: number; name: string }

function median(xs: number[]): number | null {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function top(map: Map<string, Counter>, n: number, label?: (k: string) => string | undefined): CountItem[] {
  return [...map.entries()]
    .sort((a, b) => b[1].bytes - a[1].bytes)
    .slice(0, n)
    .map(([key, c]) => ({ key, label: label?.(key), packets: c.packets, bytes: c.bytes }));
}

export class Stats {
  totalPackets = 0;
  totalBytes = 0;
  startTs: number | null = null;
  lastTs: number | null = null;
  private seconds = new Map<string, Counter>();
  private protocols = new Map<string, Counter>();
  private talkers = new Map<string, Counter>();
  private destinations = new Map<string, Counter>();
  private dnsPending = new Map<string, PendingDns>();
  private dnsTimes: number[] = [];
  private dnsSlow: { name: string; ms: number }[] = [];
  private dnsFailed = new Map<string, string>();
  dnsQueries = 0;
  dnsFailures = 0;
  unreachable = 0;

  clear(): void {
    Object.assign(this, new Stats());
  }

  private bump(map: Map<string, Counter>, key: string, len: number): void {
    const c = map.get(key);
    if (c) { c.packets++; c.bytes += len; } else map.set(key, { packets: 1, bytes: len });
  }

  /**
   * Account for one packet. Returns extra explanation notes (e.g. DNS timing)
   * keyed by packet id, so the engine can attach them to the right packet.
   */
  add(pid: number, ts: number, len: number, dec: Decoded): Map<number, string> {
    const notes = new Map<number, string>();
    this.totalPackets++;
    this.totalBytes += len;
    if (this.startTs === null) this.startTs = ts;
    this.lastTs = ts;
    const sec = Math.floor(ts);
    this.bump(this.seconds, String(sec), len);
    if (this.seconds.size > TIMELINE_SECONDS * 2) {
      const cutoff = sec - TIMELINE_SECONDS;
      for (const k of this.seconds.keys()) if (Number(k) < cutoff) this.seconds.delete(k);
    }
    this.bump(this.protocols, dec.proto, len);
    if (dec.src && dec.ipVersion) this.bump(this.talkers, dec.src, len);
    if (dec.dst && dec.ipVersion) this.bump(this.talkers, dec.dst, len);
    if (dec.dst && dec.ipVersion && ipScope(dec.dst) === 'public') this.bump(this.destinations, dec.dst, len);
    if (dec.icmp && (dec.icmp.typeName === 'Destination unreachable')) this.unreachable++;

    const dns = dec.dns;
    if (dns && !dns.mdns && dns.questions[0]) {
      const q = dns.questions[0].name;
      if (!dns.response) {
        this.dnsQueries++;
        this.dnsPending.set(`${dec.src}|${dns.id}|${q}`, { ts, pid, name: q });
      } else {
        const k = `${dec.dst}|${dns.id}|${q}`;
        const p = this.dnsPending.get(k);
        if (p) {
          this.dnsPending.delete(k);
          const ms = (ts - p.ts) * 1000;
          this.dnsTimes.push(ms);
          if (this.dnsTimes.length > 5000) this.dnsTimes.shift();
          notes.set(pid, `This answer arrived ${ms.toFixed(1)} ms after the question (packet #${p.pid}).${ms > 200 ? ' That is slow - web pages will feel sluggish to start loading.' : ''}`);
          notes.set(p.pid, `The answer arrived ${ms.toFixed(1)} ms later in packet #${pid}.`);
          if (ms > 200) {
            this.dnsSlow.push({ name: q, ms });
            this.dnsSlow.sort((a, b) => b.ms - a.ms);
            this.dnsSlow.length = Math.min(this.dnsSlow.length, 10);
          }
        }
        if (dns.rcode !== 0) {
          this.dnsFailures++;
          this.dnsFailed.set(q, dns.rcodeName);
          if (this.dnsFailed.size > 50) this.dnsFailed.delete(this.dnsFailed.keys().next().value!);
        }
      }
    }
    return notes;
  }

  snapshot(flows: FlowRec[], nameOf: (ip: string) => string | undefined): Omit<StatsSnapshot, 'watchHits'> {
    const timeline: StatsSnapshot['timeline'] = [];
    if (this.lastTs !== null) {
      const end = Math.floor(this.lastTs);
      const start = Math.max(end - 119, Math.floor(this.startTs ?? end));
      for (let t = start; t <= end; t++) {
        const c = this.seconds.get(String(t));
        timeline.push({ t, packets: c?.packets ?? 0, bytes: c?.bytes ?? 0 });
      }
    }
    return {
      totalPackets: this.totalPackets,
      totalBytes: this.totalBytes,
      startTs: this.startTs,
      lastTs: this.lastTs,
      timeline,
      protocols: top(this.protocols, 30),
      topTalkers: top(this.talkers, 10, nameOf),
      topDestinations: top(this.destinations, 10, nameOf),
      health: this.health(flows),
    };
  }

  private health(flows: FlowRec[]): HealthReport {
    const tcp = flows.filter((f) => f.transport === 'TCP');
    let dataPkts = 0, retrans = 0, resets = 0;
    const rtts: number[] = [];
    let refused = 0;
    for (const f of tcp) {
      dataPkts += f.packetsAB + f.packetsBA;
      retrans += f.retransmissions;
      resets += f.resets;
      if (f.rttMs !== undefined) rtts.push(f.rttMs);
      if (f.state === 'reset' && !f.handshakeDone) refused++;
    }
    const now = this.lastTs ?? 0;
    let timeouts = 0;
    const timedOut: string[] = [];
    for (const p of this.dnsPending.values()) {
      if (now - p.ts > DNS_TIMEOUT_S) { timeouts++; if (timedOut.length < 10) timedOut.push(p.name); }
    }
    const rate = dataPkts ? retrans / dataPkts : 0;
    const medRtt = median(rtts);
    const medDns = median(this.dnsTimes);
    const findings: HealthFinding[] = [];

    if (dataPkts > 50) {
      if (rate > 0.05) findings.push({ status: 'critical', title: 'Heavy packet loss', detail: `${(rate * 100).toFixed(1)}% of TCP packets were retransmitted. Connections will be slow and unreliable. Check cabling, Wi-Fi signal and link congestion.`, plainTitle: 'Your connection is losing a lot of data', plainDetail: `About ${Math.round(rate * 100)} in every 100 pieces of data had to be sent again. Expect slow pages, buffering and dropped calls. Try moving closer to the Wi-Fi router, using a cable, or restarting the router.` });
      else if (rate > 0.02) findings.push({ status: 'serious', title: 'Noticeable packet loss', detail: `${(rate * 100).toFixed(1)}% of TCP packets were retransmitted (healthy networks stay below ~1%).`, plainTitle: 'Some data is getting lost', plainDetail: 'More data than usual had to be sent twice. Things may feel sluggish now and then. A weak Wi-Fi signal or a busy network is the usual cause.' });
      else if (rate > 0.01) findings.push({ status: 'warning', title: 'Some packet loss', detail: `${(rate * 100).toFixed(1)}% retransmissions - slightly above normal.`, plainTitle: 'A little data is getting lost', plainDetail: 'Slightly more data than normal had to be resent. Probably not noticeable yet.' });
      else findings.push({ status: 'good', title: 'No significant packet loss', detail: `Only ${(rate * 100).toFixed(2)}% of TCP packets were retransmitted.`, plainTitle: 'Your connection is reliable', plainDetail: 'Data is arriving the first time, with almost nothing having to be resent.' });
    }
    if (medRtt !== null) {
      if (medRtt > 250) findings.push({ status: 'serious', title: 'High latency', detail: `Median connection setup time is ${medRtt.toFixed(0)} ms. Interactive apps and calls will feel laggy.`, plainTitle: 'Responses are slow', plainDetail: `Servers take about ${medRtt.toFixed(0)} ms to answer, which makes games and video calls feel laggy.` });
      else if (medRtt > 100) findings.push({ status: 'warning', title: 'Moderate latency', detail: `Median connection setup time is ${medRtt.toFixed(0)} ms.`, plainTitle: 'Responses are a bit slow', plainDetail: `Servers take about ${medRtt.toFixed(0)} ms to answer. Fine for browsing, a little laggy for games and calls.` });
      else findings.push({ status: 'good', title: 'Latency looks healthy', detail: `Median connection setup time is ${medRtt.toFixed(0)} ms.`, plainTitle: 'Responses are quick', plainDetail: `Servers answer in about ${medRtt.toFixed(0)} ms. That feels instant.` });
    }
    if (this.dnsQueries > 0) {
      if (timeouts > 0 && timeouts / this.dnsQueries > 0.1) findings.push({ status: 'critical', title: 'DNS server not answering', detail: `${timeouts} lookups never got an answer (${timedOut.slice(0, 3).join(', ')}…). Websites will fail to load. Try another DNS server (e.g. your router's or a public resolver).`, plainTitle: 'Websites can\'t be found', plainDetail: 'The service that turns website names into addresses (DNS) is not answering, so pages will fail to open. Restart the router, or set a different DNS server in your network settings.' });
      if (medDns !== null && medDns > 150) findings.push({ status: 'warning', title: 'Slow DNS', detail: `Median name lookup takes ${medDns.toFixed(0)} ms. Every new website waits this long before it can even start loading.`, plainTitle: 'Websites are slow to start loading', plainDetail: `Finding each website's address takes about ${medDns.toFixed(0)} ms before the page can even begin. A different DNS server may help.` });
      else if (medDns !== null) findings.push({ status: 'good', title: 'DNS responds quickly', detail: `Median lookup time ${medDns.toFixed(0)} ms over ${this.dnsTimes.length} answered queries.`, plainTitle: 'Websites are found quickly', plainDetail: `Looking up website addresses takes about ${medDns.toFixed(0)} ms.` });
      if (this.dnsFailures > 0) findings.push({ status: this.dnsFailures / this.dnsQueries > 0.2 ? 'serious' : 'warning', title: 'Failed DNS lookups', detail: `${this.dnsFailures} lookups failed (name not found or server error). See the list below.`, plainTitle: 'Some website names could not be found', plainDetail: `${this.dnsFailures} names did not exist or could not be looked up. Often a typo or a removed site; random-looking names can be a sign of malware. The list is below.` });
    }
    if (refused >= 3) findings.push({ status: 'warning', title: 'Refused connections', detail: `${refused} connection attempts were refused (RST before the connection opened). A service may be down, or a firewall is rejecting traffic.`, plainTitle: 'Some connections were refused', plainDetail: `${refused} times a device tried to connect and was turned away. A service may be switched off, or a firewall is blocking it.` });
    if (this.unreachable >= 3) findings.push({ status: 'warning', title: 'Unreachable destinations', detail: `${this.unreachable} "destination unreachable" messages were seen. Some hosts or ports cannot be reached.`, plainTitle: 'Some places could not be reached', plainDetail: `${this.unreachable} times the network reported that a destination could not be reached. It may be offline.` });

    return {
      tcpFlows: tcp.length,
      tcpRetransmissionRate: rate,
      tcpResets: resets,
      medianRttMs: medRtt,
      dnsQueries: this.dnsQueries,
      dnsFailures: this.dnsFailures,
      dnsTimeouts: timeouts,
      medianDnsMs: medDns,
      slowDnsNames: this.dnsSlow,
      failedDnsNames: [...this.dnsFailed.entries()].slice(-15).reverse().map(([name, rcode]) => ({ name, rcode })),
      unreachable: this.unreachable,
      findings,
    };
  }
}
