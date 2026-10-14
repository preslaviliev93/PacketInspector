import type { Alert, EngineUpdate } from '../../shared/types';
import { h, clear, fmtTime, icon, statusChip, severityKind, toast } from '../dom';
import { isSimple, t, severityLabel } from '../mode';
import { store } from '../store';
import type { Ctx, View } from '../ctx';

const RANK = { high: 3, medium: 2, low: 1, info: 0 };

export class AlertsView implements View {
  private search = h('input', { type: 'search', placeholder: 'Search alerts, hosts…', 'aria-label': 'Search alerts', style: 'width: 260px' });
  private listHost = h('div', { class: 'alert-list' });
  private count = h('span', { class: 'muted' });
  private sev: 'all' | Alert['severity'] = 'all';
  private cat: 'all' | Alert['category'] = 'all';
  private sevBtns: HTMLButtonElement[] = [];
  private catBtns: HTMLButtonElement[] = [];

  constructor(root: HTMLElement, private ctx: Ctx) {
    const seg = <T extends string>(opts: [T, string][], cur: () => T, set: (v: T) => void, store: HTMLButtonElement[]) =>
      h('div', { class: 'seg' }, ...opts.map(([v, label]) => {
        const b = h('button', { class: cur() === v ? 'on' : '' }, label);
        b.onclick = () => { set(v); store.forEach((x) => x.classList.toggle('on', x === b)); this.render(); };
        store.push(b);
        return b;
      }));
    root.append(
      h('div', { class: 'toolbar-row' },
        seg<'all' | Alert['severity']>([['all', 'All'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']], () => this.sev, (v) => (this.sev = v), this.sevBtns),
        seg<'all' | Alert['category']>([['all', 'Everything'], ['security', 'Security'], ['performance', 'Performance']], () => this.cat, (v) => (this.cat = v), this.catBtns),
        this.search, h('span', { class: 'grow' }), this.count),
      this.listHost);
    this.search.addEventListener('input', () => this.render());
  }

  setSearch(q: string): void {
    this.search.value = q;
    this.sev = 'all';
    this.cat = 'all';
    this.sevBtns.forEach((b, i) => b.classList.toggle('on', i === 0));
    this.catBtns.forEach((b, i) => b.classList.toggle('on', i === 0));
  }

  show(): void { this.render(); }

  /** Severity buttons follow the mode's wording ("High" vs "Needs attention"). */
  private relabel(): void {
    const order = ['high', 'medium', 'low', 'info'] as const;
    order.forEach((s, i) => { if (this.sevBtns[i + 1]) this.sevBtns[i + 1].textContent = severityLabel(s); });
  }

  update(u: EngineUpdate): void {
    if (u.alerts.length || u.reset) this.render();
  }

  private render(): void {
    this.relabel();
    clear(this.listHost);
    const q = this.search.value.trim().toLowerCase();
    const all = [...store.alerts.values()];
    const alerts = all
      .filter((a) => this.sev === 'all' || a.severity === this.sev)
      .filter((a) => this.cat === 'all' || a.category === this.cat)
      .filter((a) => !q || `${a.title} ${a.description} ${a.hosts.join(' ')} ${a.kind}`.toLowerCase().includes(q))
      .sort((a, b) => RANK[b.severity] - RANK[a.severity] || b.ts - a.ts);
    this.count.textContent = `${alerts.length} of ${all.length} alerts`;
    if (!all.length) {
      this.listHost.appendChild(h('div', { class: 'empty' },
        h('h3', null, 'No alerts'),
        h('div', null, 'Packet Inspector watches for port scans, ARP spoofing, passwords sent in clear text, suspicious ports, DNS tunneling, "beaconing" malware check-ins, rogue DHCP servers, outdated encryption, large uploads, packet loss and more.')));
      return;
    }
    for (const a of alerts) this.listHost.appendChild(this.card(a));
  }

  private card(a: Alert): HTMLElement {
    const hosts = a.hosts.map((ip) => {
      const n = store.nameOf(ip);
      return h('button', { class: 'small', title: isSimple() ? `Show connections for ${ip}` : `Show packets for ${ip}`, onclick: () => (isSimple() ? this.ctx.showConnections(ip) : this.ctx.showPackets(`host:${ip}`)) }, n ? `${ip} (${n})` : ip);
    });
    const actions = h('div', { class: 'actions' },
      isSimple() ? null : h('button', { class: 'small primary', onclick: () => this.ctx.showPackets(`id:${a.packetIds.join(',')}`, a.packetIds[0]) },
        icon('link'), `Show evidence (${a.packetIds.length} packet${a.packetIds.length > 1 ? 's' : ''})`),
      a.flowIds.length ? h('button', { class: `small${isSimple() ? ' primary' : ''}`, onclick: () => this.ctx.showFlow(a.flowIds[0]) }, icon('flows'), isSimple() ? 'View the connection' : a.flowIds.length > 1 ? `Trace first of ${a.flowIds.length} connections` : 'Trace connection') : null,
      isSimple() ? null : h('button', { class: 'small', onclick: async () => {
        const p = await window.pi.saveCapture(a.packetIds);
        if (p) toast(`Evidence saved to ${p}`);
      } }, icon('save'), 'Save evidence'),
      h('span', { class: 'muted', style: 'margin-left:6px' }, t('Hosts:', 'Devices involved:')), ...hosts);
    return h('div', { class: `alert-card sev-${a.severity}` },
      h('div', { class: 'top' },
        statusChip(severityKind(a.severity), severityLabel(a.severity)),
        h('span', { class: 'chip' }, icon(a.category === 'security' ? 'shield' : 'gauge'), a.category === 'security' ? 'Security' : 'Performance'),
        h('span', { class: 'title' }, a.title),
        h('span', { class: 'when' }, `first seen ${fmtTime(a.ts)}`)),
      h('p', null, a.description),
      h('p', { class: 'advice' }, h('b', null, 'What to do: '), a.advice),
      actions);
  }
}
