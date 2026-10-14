// Watchlist (Expert): user-defined rules that raise an alert whenever traffic
// involves a given address, network, host name or port.

import type { EngineUpdate, Severity, WatchKind, WatchRule } from '../../shared/types';
import { normalizeRuleValue, WATCH_KIND_LABEL } from '../../shared/watch';
import { h, clear, icon, statusChip, severityKind, toast } from '../dom';
import { severityLabel } from '../mode';
import { store } from '../store';
import type { Ctx, View } from '../ctx';

const PLACEHOLDER: Record<WatchKind, string> = {
  ip: 'e.g. 203.0.113.7 or 2001:db8::5',
  network: 'e.g. 10.20.0.0/16 or 2001:db8::/32',
  host: 'e.g. example.com (covers sub-domains too)',
  port: 'e.g. 3389',
};

const EXAMPLES: { kind: WatchKind; value: string; label: string; why: string }[] = [
  { kind: 'ip', value: '203.0.113.7', label: 'Old file server', why: 'one machine' },
  { kind: 'network', value: '10.20.0.0/16', label: 'Payroll VLAN', why: 'a whole subnet' },
  { kind: 'host', value: 'example.com', label: 'Competitor', why: 'a domain and its sub-domains' },
  { kind: 'port', value: '3389', label: 'Remote Desktop', why: 'a service anywhere' },
];

export class WatchView implements View {
  private rules: WatchRule[] = [];
  private loaded = false;
  private kind = h('select', { 'aria-label': 'Rule type' }, ...(Object.keys(WATCH_KIND_LABEL) as WatchKind[]).map((k) => h('option', { value: k }, WATCH_KIND_LABEL[k])));
  private value = h('input', { type: 'text', class: 'mono', spellcheck: 'false', 'aria-label': 'Value', style: 'width: 280px' });
  private label = h('input', { type: 'text', placeholder: 'Label (optional), e.g. "Payroll VLAN"', 'aria-label': 'Label', style: 'width: 240px' });
  private severity = h('select', { 'aria-label': 'Severity' }, ...(['high', 'medium', 'low', 'info'] as Severity[]).map((s) => h('option', { value: s, selected: s === 'medium' }, severityLabel(s))));
  private error = h('div', { class: 'form-error', role: 'alert' });
  private listHost = h('div');

  constructor(root: HTMLElement, private ctx: Ctx) {
    this.kind.onchange = () => { this.value.placeholder = PLACEHOLDER[this.kind.value as WatchKind]; this.error.textContent = ''; };
    this.value.placeholder = PLACEHOLDER.ip;
    const submit = (e: Event) => { e.preventDefault(); this.add(this.kind.value as WatchKind, this.value.value, this.label.value, this.severity.value as Severity); };
    const form = h('form', { class: 'watch-form', onsubmit: submit },
      this.kind, this.value, this.label, this.severity, h('button', { class: 'primary', type: 'submit' }, icon('eye'), 'Add rule'));
    root.append(h('div', { style: 'max-width: 1200px' },
      h('h2', { style: 'margin: 0 0 4px; font-size: 16px' }, 'Watchlist'),
      h('p', { class: 'muted', style: 'margin: 0 0 14px' }, 'Get an alert whenever traffic involves something you care about: a specific machine, a whole network, a website or service, or a port. Matches are tagged so you can filter on tag:watch, and every alert links to the packets that triggered it. Rules are saved and apply to new traffic from the moment you add them.'),
      h('div', { class: 'card' }, form, this.error,
        h('div', { class: 'examples' }, h('span', { class: 'muted small' }, 'Examples:'),
          ...EXAMPLES.map((x) => h('button', { type: 'button', class: 'small', title: `Watch ${x.why}`, onclick: () => { this.kind.value = x.kind; this.value.value = x.value; this.label.value = x.label; this.value.placeholder = PLACEHOLDER[x.kind]; this.value.focus(); } }, `${WATCH_KIND_LABEL[x.kind]}: ${x.value}`)))),
      this.listHost));
  }

  async show(): Promise<void> {
    if (!this.loaded) {
      this.rules = await window.pi.getWatchRules();
      this.loaded = true;
    }
    this.severity.querySelectorAll('option').forEach((o) => { o.textContent = severityLabel(o.value as Severity); });
    this.renderList();
  }

  update(u: EngineUpdate): void {
    if (u.stats && this.loaded) this.renderList();
  }

  /** Add a rule (also used by "Watch" buttons elsewhere in the app). */
  async add(kind: WatchKind, raw: string, label: string, severity: Severity): Promise<boolean> {
    const n = normalizeRuleValue(kind, raw);
    if ('error' in n) { this.error.textContent = n.error; return false; }
    if (!this.loaded) { this.rules = await window.pi.getWatchRules(); this.loaded = true; }
    if (this.rules.some((r) => r.kind === kind && r.value === n.value)) {
      this.error.textContent = `${WATCH_KIND_LABEL[kind]} ${n.value} is already on the watchlist.`;
      return false;
    }
    this.error.textContent = '';
    const rule: WatchRule = { id: Math.random().toString(36).slice(2, 10), kind, value: n.value, label: label.trim() || undefined, severity, enabled: true, created: Date.now() };
    await this.save([...this.rules, rule]);
    this.value.value = '';
    this.label.value = '';
    toast(`Watching ${WATCH_KIND_LABEL[kind].toLowerCase()} ${n.value}. You'll get an alert when it shows up in the traffic.`);
    return true;
  }

  private async save(rules: WatchRule[]): Promise<void> {
    this.rules = await window.pi.saveWatchRules(rules);
    this.renderList();
  }

  private filterFor(r: WatchRule): string {
    return r.kind === 'network' ? `net:${r.value}` : r.kind === 'port' ? `port:${r.value}` : `host:${r.value}`;
  }

  private renderList(): void {
    clear(this.listHost);
    const hits = store.stats?.watchHits ?? {};
    if (!this.rules.length) {
      this.listHost.appendChild(h('div', { class: 'empty' }, h('h3', null, 'No rules yet'), h('div', null, 'Add an address, network, host name or port above. You can also click "Watch" next to a host in the packet details or on the Databases tab.')));
      return;
    }
    const t = h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, ...['On', 'Type', 'Value', 'Label', 'Severity', 'Matches', ''].map((x, i) => h('th', { class: i === 5 ? 'num' : '' }, x)))));
    const tb = h('tbody');
    for (const r of this.rules) {
      const on = h('input', { type: 'checkbox', checked: r.enabled, 'aria-label': `Enable rule ${r.value}` });
      on.onchange = () => this.save(this.rules.map((x) => (x.id === r.id ? { ...x, enabled: on.checked } : x)));
      const n = hits[r.id] ?? 0;
      tb.appendChild(h('tr', { class: r.enabled ? '' : 'muted' },
        h('td', null, on),
        h('td', null, WATCH_KIND_LABEL[r.kind]),
        h('td', { class: 'mono' }, r.value),
        h('td', null, r.label ?? h('span', { class: 'muted' }, '-')),
        h('td', null, statusChip(severityKind(r.severity), severityLabel(r.severity))),
        h('td', { class: 'num' }, n ? n.toLocaleString() : h('span', { class: 'muted' }, '0')),
        h('td', { style: 'text-align: right' },
          h('button', { class: 'small', disabled: !n, onclick: () => this.ctx.showPackets(this.filterFor(r)) }, 'Packets'),
          ' ',
          h('button', { class: 'small', disabled: !n, onclick: () => this.ctx.showAlerts(r.label ?? r.value) }, 'Alerts'),
          ' ',
          h('button', { class: 'small', title: 'Delete rule', onclick: () => this.save(this.rules.filter((x) => x.id !== r.id)) }, icon('clear')))));
    }
    t.appendChild(tb);
    this.listHost.append(h('div', { class: 'section-title', style: 'margin-top: 18px' }, `${this.rules.length} rule${this.rules.length > 1 ? 's' : ''}`), h('div', { class: 'card', style: 'padding: 0; overflow: auto' }, t));
  }
}
