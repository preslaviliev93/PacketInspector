import type { EngineUpdate, FlowSummary } from '../../shared/types';
import { h, clear, fmtBytes, statusChip } from '../dom';
import { store } from '../store';
import type { Ctx, View } from '../ctx';
import { isSimple, t } from '../mode';

const STATUS_LABEL = { good: 'Good', warning: 'Warning', serious: 'Problem', critical: 'Critical' } as const;

export class HealthView implements View {
  constructor(private root: HTMLElement, private ctx: Ctx) {}

  show(): void { this.render(); }

  update(u: EngineUpdate): void {
    if (u.stats || u.reset) this.render();
  }

  private render(): void {
    clear(this.root);
    const hr = store.stats?.health;
    this.root.appendChild(h('div', { style: 'max-width: 1200px' },
      h('h2', { style: 'margin: 0 0 4px; font-size: 16px' }, t('Network troubleshooting', 'How healthy is the network?')),
      h('p', { class: 'muted', style: 'margin: 0 0 14px' }, t('Automatic checks for the most common causes of a "slow" or "broken" network: packet loss, latency, DNS problems and refused connections. Every item links to the packets behind it.', 'The usual reasons the internet feels slow or broken, checked automatically while you capture.'))));
    const wrap = this.root.firstChild as HTMLElement;
    if (!hr || (!hr.tcpFlows && !hr.dnsQueries)) {
      wrap.appendChild(h('div', { class: 'empty' }, h('h3', null, 'Not enough traffic yet'), h('div', null, 'Browse a few websites while capturing - the checks fill in as TCP connections and DNS lookups are observed.')));
      return;
    }

    const findings = h('div', { class: 'findings' });
    const order = { critical: 0, serious: 1, warning: 2, good: 3 };
    for (const f of [...hr.findings].sort((a, b) => order[a.status] - order[b.status])) {
      findings.appendChild(h('div', { class: 'finding' }, statusChip(f.status, STATUS_LABEL[f.status]), h('span', { class: 't' }, isSimple() ? f.plainTitle : f.title), h('span', { class: 'd' }, isSimple() ? f.plainDetail : f.detail)));
    }

    const tile = (label: string, value: string, hint: string, filter?: string) => {
      const el = h('div', { class: `tile${filter ? ' clickable' : ''}`, role: filter ? 'button' : undefined, tabindex: filter ? 0 : undefined },
        h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'hint' }, hint));
      if (filter !== undefined && !isSimple()) el.onclick = () => this.ctx.showPackets(filter);
      else { el.classList.remove('clickable'); el.removeAttribute('role'); el.removeAttribute('tabindex'); }
      return el;
    };
    const tiles = h('div', { class: 'tiles', style: 'margin-top: 12px' },
      tile(t('Packet loss (TCP)', 'Data sent twice'), `${(hr.tcpRetransmissionRate * 100).toFixed(2)}%`, t('healthy: under 1% · click for retransmissions', 'lost and resent; healthy is under 1%'), 'tag:retransmission'),
      tile(t('Connection setup time', 'Server response time'), hr.medianRttMs !== null ? `${hr.medianRttMs.toFixed(0)} ms` : '-', t('median round-trip, SYN → SYN-ACK', 'typical wait before a server answers'), 'tag:syn-ack'),
      tile(t('DNS lookup time', 'Website lookup time'), hr.medianDnsMs !== null ? `${hr.medianDnsMs.toFixed(0)} ms` : '-', t(`median over ${hr.dnsQueries} lookups`, 'finding a website\'s address (DNS)'), 'proto:dns'),
      tile(t('Failed lookups', 'Failed website lookups'), `${hr.dnsFailures + hr.dnsTimeouts}`, t(`${hr.dnsFailures} errors · ${hr.dnsTimeouts} unanswered`, 'names that could not be found'), 'tag:dns-error'),
      tile(t('Resets', 'Dropped connections'), `${hr.tcpResets}`, 'connections aborted or refused', 'tag:rst'),
      tile('Unreachable', `${hr.unreachable}`, t('ICMP "can\'t get there" messages', 'places that could not be reached'), 'unreachable'),
    );

    const list = (title: string, sub: string, items: { label: string; value: string; filter: string }[], empty: string) => {
      const ul = h('ul', { class: 'list' });
      for (const it of items) {
        const li = h('li', null, h('span', { class: 'grow mono', title: it.label }, it.label), h('span', { class: 'muted' }, it.value), isSimple() ? null : h('button', { class: 'small', onclick: () => this.ctx.showPackets(it.filter) }, 'Packets'));
        ul.appendChild(li);
      }
      return h('div', { class: 'card' }, h('h2', null, title), h('p', { class: 'sub' }, sub), items.length ? ul : h('div', { class: 'muted' }, empty));
    };

    const flows = [...store.flows.values()];
    const problem = flows
      .filter((f) => f.retransmissions || f.resets || f.zeroWindows)
      .sort((a, b) => score(b) - score(a))
      .slice(0, 12);
    const slowSetup = flows.filter((f) => f.rttMs !== undefined).sort((a, b) => b.rttMs! - a.rttMs!).slice(0, 8);

    const flowList = (title: string, sub: string, items: FlowSummary[], value: (f: FlowSummary) => string, empty: string) => {
      const ul = h('ul', { class: 'list' });
      for (const f of items) {
        const name = f.bName ?? store.nameOf(f.b) ?? f.b;
        ul.appendChild(h('li', null,
          h('span', { class: 'grow', title: `${f.a} → ${f.b}:${f.bPort ?? ''}` }, `${name}${f.bPort !== undefined ? ':' + f.bPort : ''}`, h('span', { class: 'muted' }, ` · ${f.app} · ${fmtBytes(f.bytesAB + f.bytesBA)}`)),
          h('span', { class: 'muted' }, value(f)),
          h('button', { class: 'small', onclick: () => this.ctx.showFlow(f.id) }, t('Trace', 'View'))));
      }
      return h('div', { class: 'card' }, h('h2', null, title), h('p', { class: 'sub' }, sub), items.length ? ul : h('div', { class: 'muted' }, empty));
    };

    wrap.append(
      findings,
      tiles,
      h('div', { class: 'two-col' },
        flowList('Connections with problems', t('Loss, resets or stalled receivers - the usual suspects when "the app is slow".', 'Connections that dropped data, were refused or stalled. Usually the reason an app feels slow.'), problem,
          (f) => (isSimple()
            ? [f.retransmissions && 'data resent', f.resets && 'refused or cut off', f.zeroWindows && 'stalled']
            : [f.retransmissions && `${f.retransmissions} retx`, f.resets && 'reset', f.zeroWindows && `${f.zeroWindows} zero-win`]).filter(Boolean).join(' · '),
          'No troubled connections.'),
        flowList('Slowest servers to respond', t('Longest connection setup times. Far-away or overloaded servers show up here.', 'Websites and services that took longest to answer.'), slowSetup,
          (f) => `${f.rttMs!.toFixed(0)} ms`, 'No TCP handshakes observed yet.'),
        list('Slow DNS lookups', 'Answers that took more than 200 ms.', hr.slowDnsNames.map((d) => ({ label: d.name, value: `${d.ms.toFixed(0)} ms`, filter: d.name })), 'All lookups were fast.'),
        list('Failed DNS lookups', 'Names that could not be resolved. Random-looking names can indicate malware.', hr.failedDnsNames.map((d) => ({ label: d.name, value: d.rcode, filter: d.name })), 'No failed lookups.'),
      ));
  }
}

function score(f: FlowSummary): number {
  return f.retransmissions * 2 + f.resets * 3 + f.zeroWindows;
}
