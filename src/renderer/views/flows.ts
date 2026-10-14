import type { EngineUpdate, FlowSummary, PacketSummary } from '../../shared/types';
import { h, s, clear, fmtBytes, fmtDuration, fmtTime, icon, statusChip, toast, showTip, hideTip } from '../dom';
import { store } from '../store';
import { protoColor, type Ctx, type View } from '../ctx';
import { isSimple, t } from '../mode';

type SortKey = 'first' | 'last' | 'client' | 'server' | 'app' | 'packets' | 'bytes' | 'duration' | 'rtt' | 'issues';
const MAX_ROWS = 1500;
const LADDER_MAX = 400;

const STATE_LABEL: Record<FlowSummary['state'], string> = {
  opening: 'Opening', established: 'Open', closing: 'Closing', closed: 'Closed', reset: 'Reset', stateless: '-',
};

/** One plain-language verdict for a connection (Simple mode). */
function plainStatus(f: FlowSummary): { kind: 'good' | 'warning' | 'serious' | 'critical' | 'info'; label: string; detail: string } {
  const total = f.packetsAB + f.packetsBA;
  if (f.alertCount) return { kind: 'critical', label: 'Flagged', detail: 'Something about this connection raised an alert. See the Alerts tab for what and why.' };
  if (f.state === 'reset' && f.packetsBA <= 1 && f.transport === 'TCP') return { kind: 'warning', label: 'Refused', detail: 'The other side refused the connection. The service may be down, or a firewall blocked it.' };
  if (f.retransmissions && f.retransmissions / Math.max(1, total) > 0.05) return { kind: 'serious', label: 'Unreliable', detail: `Some data had to be sent again (${f.retransmissions} times). That usually means a weak Wi-Fi signal, a bad cable or a busy network.` };
  if (f.zeroWindows) return { kind: 'warning', label: 'Stalled', detail: 'One side could not keep up and asked the other to pause. The bottleneck is a slow app or computer, not the network.' };
  if (f.state === 'reset') return { kind: 'info', label: 'Cut off', detail: 'The connection ended abruptly instead of closing normally. Often harmless (apps do this when you close a tab).' };
  if (f.state === 'opening' && f.transport === 'TCP') return { kind: 'info', label: 'Connecting', detail: 'The connection is being set up.' };
  if (f.state === 'closed') return { kind: 'good', label: 'Finished', detail: 'This connection worked normally and has finished.' };
  return { kind: 'good', label: 'OK', detail: 'This connection looks normal.' };
}

function issues(f: FlowSummary): number {
  return f.retransmissions + f.resets * 2 + f.zeroWindows + f.alertCount * 5;
}

export class FlowsView implements View {
  private input = h('input', { type: 'search', placeholder: 'Search connections', 'aria-label': 'Search connections', spellcheck: 'false' });
  private count = h('span', { class: 'count' });
  private tableHost = h('div', { class: 'flow-table' });
  private detailHost = h('div', { class: 'flow-detail' });
  private sortKey: SortKey = 'last';
  private sortDesc = true;
  private only: 'all' | 'tcp' | 'udp' | 'db' | 'problems' | 'alerts' = 'all';
  private selected: number | null = null;
  private lastRender = 0;
  private pending = false;
  private quickBtns: HTMLButtonElement[] = [];

  constructor(root: HTMLElement, private ctx: Ctx) {
    root.classList.add('split');
    const quick = (label: string, v: typeof this.only) => {
      const b = h('button', { class: `small${v === 'all' ? ' primary' : ''}`, onclick: () => {
        this.only = v;
        this.quickBtns.forEach((x) => x.classList.toggle('primary', x === b));
        this.render();
      } }, label);
      this.quickBtns.push(b);
      return b;
    };
    const expertOnly = (b: HTMLButtonElement) => { b.classList.add('expert-only'); return b; };
    root.append(
      h('div', { class: 'filterbar' }, icon('filter'), this.input,
        h('span', { class: 'quick' }, quick('All', 'all'), expertOnly(quick('TCP', 'tcp')), expertOnly(quick('UDP', 'udp')), quick('Databases', 'db'), quick('With problems', 'problems'), quick('With alerts', 'alerts')),
        this.count),
      this.tableHost, this.detailHost);
    this.input.addEventListener('input', () => this.render());
    this.renderDetailEmpty();
  }

  show(): void {
    this.render();
    if (this.selected !== null) this.renderDetail(this.selected);
  }

  update(u: EngineUpdate): void {
    if (u.reset) { this.selected = null; this.renderDetailEmpty(); }
    if (!u.flows.length && !u.reset) return;
    // Large tables: re-render at most once a second.
    const now = performance.now();
    if (now - this.lastRender > 1000) this.render();
    else if (!this.pending) {
      this.pending = true;
      setTimeout(() => { this.pending = false; this.render(); }, 1000);
    }
    if (this.selected !== null && u.flows.some((f) => f.id === this.selected)) this.renderSummary(this.selected);
  }

  setSearch(q: string): void {
    this.input.value = q;
    this.render();
  }

  select(id: number): void {
    this.selected = id;
    this.render();
    this.renderDetail(id);
    requestAnimationFrame(() => this.tableHost.querySelector('tr.sel')?.scrollIntoView({ block: 'nearest' }));
  }

  private filtered(): FlowSummary[] {
    const q = this.input.value.trim().toLowerCase();
    const terms = q.split(/\s+/).filter(Boolean);
    let flows = [...store.flows.values()];
    if (this.only === 'tcp') flows = flows.filter((f) => f.transport === 'TCP');
    else if (this.only === 'udp') flows = flows.filter((f) => f.transport === 'UDP');
    else if (this.only === 'problems') flows = flows.filter((f) => f.retransmissions || f.resets || f.zeroWindows || f.dupAcks);
    else if (this.only === 'alerts') flows = flows.filter((f) => f.alertCount > 0);
    else if (this.only === 'db') flows = flows.filter((f) => f.db);
    if (terms.length) {
      flows = flows.filter((f) => {
        const hay = `${f.a} ${f.aPort ?? ''} ${f.b} ${f.bPort ?? ''} ${f.bName ?? store.nameOf(f.b) ?? ''} ${store.nameOf(f.a) ?? ''} ${f.app} ${f.transport} #${f.id} ${f.db ? `${f.db.system} ${f.db.user ?? ''} ${f.db.database ?? ''}` : ''}`.toLowerCase();
        return terms.every((t) => hay.includes(t));
      });
    }
    const dir = this.sortDesc ? -1 : 1;
    const key = (f: FlowSummary): number | string => {
      switch (this.sortKey) {
        case 'first': return f.firstTs;
        case 'last': return f.lastTs;
        case 'client': return f.a;
        case 'server': return f.bName ?? f.b;
        case 'app': return f.app;
        case 'packets': return f.packetsAB + f.packetsBA;
        case 'bytes': return f.bytesAB + f.bytesBA;
        case 'duration': return f.lastTs - f.firstTs;
        case 'rtt': return f.rttMs ?? -1;
        case 'issues': return issues(f);
      }
    };
    return flows.sort((a, b) => {
      const ka = key(a), kb = key(b);
      return (ka < kb ? -1 : ka > kb ? 1 : 0) * dir;
    });
  }

  private render(): void {
    this.lastRender = performance.now();
    const flows = this.filtered();
    this.count.textContent = `${flows.length.toLocaleString()} of ${store.flows.size.toLocaleString()} ${'connections'}`;
    this.input.placeholder = t('Search connections (address, name, port, app, database)', 'Search connections (website, device or address)');
    const scroll = this.tableHost.scrollTop;
    clear(this.tableHost);
    if (!store.flows.size) {
      this.tableHost.appendChild(h('div', { class: 'empty' }, h('h3', null, 'No connections yet'), h('div', null, t('Every connection between two endpoints shows up here, with its state, timing and problems.', 'Every time a device talks to a website or another device, it shows up here.'))));
      return;
    }
    const th = (label: string, key: SortKey, num = false) => {
      const el = h('th', { class: num ? 'num' : '', 'aria-sort': this.sortKey === key ? (this.sortDesc ? 'descending' : 'ascending') : undefined },
        label, this.sortKey === key ? h('span', { class: 'arrow' }, this.sortDesc ? '▼' : '▲') : null);
      el.onclick = () => {
        if (this.sortKey === key) this.sortDesc = !this.sortDesc;
        else { this.sortKey = key; this.sortDesc = !['client', 'server', 'app'].includes(key); }
        this.render();
      };
      return el;
    };
    const simple = isSimple();
    const table = h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, ...(simple
        ? [th('Device', 'client'), th('Website or service', 'server'), th('Type', 'app'), th('Data', 'bytes', true), th('Duration', 'duration', true), th('Status', 'issues')]
        : [th('Client', 'client'), th('Server', 'server'), th('App', 'app'), th('Packets', 'packets', true),
          th('Data', 'bytes', true), th('Duration', 'duration', true), h('th', null, 'State'), th('RTT', 'rtt', true), th('Issues', 'issues', true)]))));
    const tb = h('tbody');
    for (const f of flows.slice(0, MAX_ROWS)) {
      const app = h('span', { class: 'proto' }, f.app);
      app.style.setProperty('--pc', protoColor(f.app));
      const iss: string[] = [];
      if (f.alertCount) iss.push(`${f.alertCount} alert${f.alertCount > 1 ? 's' : ''}`);
      if (f.retransmissions) iss.push(`${f.retransmissions} retx`);
      if (f.resets) iss.push('reset');
      if (f.zeroWindows) iss.push('zero-win');
      const name = f.bName ?? store.nameOf(f.b);
      if (simple) {
        const st = plainStatus(f);
        const tr = h('tr', { class: `row${f.id === this.selected ? ' sel' : ''}` },
          h('td', { title: f.a }, store.nameOf(f.a) ?? f.a),
          h('td', { title: `${f.b}${name ? ` (${name})` : ''}` }, name ?? f.b),
          h('td', null, app),
          h('td', { class: 'num' }, fmtBytes(f.bytesAB + f.bytesBA)),
          h('td', { class: 'num' }, fmtDuration(f.lastTs - f.firstTs)),
          h('td', null, statusChip(st.kind, st.label)));
        tr.onclick = () => this.select(f.id);
        tb.appendChild(tr);
        continue;
      }
      const tr = h('tr', { class: `row${f.id === this.selected ? ' sel' : ''}` },
        h('td', { title: f.a }, `${store.nameOf(f.a) ?? f.a}${f.aPort !== undefined ? ':' + f.aPort : ''}`),
        h('td', { title: `${f.b}${name ? ` (${name})` : ''}` }, `${name ?? f.b}${f.bPort !== undefined ? ':' + f.bPort : ''}`),
        h('td', null, app),
        h('td', { class: 'num' }, (f.packetsAB + f.packetsBA).toLocaleString()),
        h('td', { class: 'num' }, fmtBytes(f.bytesAB + f.bytesBA)),
        h('td', { class: 'num' }, fmtDuration(f.lastTs - f.firstTs)),
        h('td', null, STATE_LABEL[f.state]),
        h('td', { class: 'num' }, f.rttMs !== undefined ? `${f.rttMs.toFixed(1)} ms` : ''),
        h('td', { class: 'num' }, iss.length ? statusChip(f.alertCount ? 'critical' : f.resets && !f.retransmissions ? 'warning' : 'serious', iss.join(', ')) : ''));
      tr.onclick = () => this.select(f.id);
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    this.tableHost.appendChild(table);
    if (flows.length > MAX_ROWS) this.tableHost.appendChild(h('div', { class: 'muted', style: 'padding:10px' }, `Showing the first ${MAX_ROWS.toLocaleString()} - narrow the search to see others.`));
    this.tableHost.scrollTop = scroll;
  }

  private renderDetailEmpty(): void {
    clear(this.detailHost);
    this.detailHost.appendChild(h('div', { class: 'empty' }, h('h3', null, 'Pick a connection'), h('div', null, t('You will see a step-by-step diagram of who said what and when - handshakes, data, retransmissions and resets - with every arrow linked to its packet.', 'You will see who it was between, how much data it used, and whether anything went wrong.'))));
  }

  private summaryHost = h('div');
  private ladderHost = h('div', { class: 'ladder' });

  private async renderDetail(id: number): Promise<void> {
    clear(this.detailHost);
    this.summaryHost = h('div');
    this.ladderHost = h('div', { class: 'ladder' });
    this.detailHost.append(this.summaryHost);
    this.renderSummary(id);
    if (isSimple()) return; // the packet-by-packet diagram is an Expert view
    this.detailHost.append(h('div', { class: 'section-title' }, 'Connection trace'), this.ladderHost);
    const pkts = await window.pi.getFlowPackets(id);
    if (this.selected !== id) return;
    this.renderLadder(store.flows.get(id)!, pkts);
  }

  private renderSummary(id: number): void {
    const f = store.flows.get(id);
    if (!f) return;
    clear(this.summaryHost);
    const name = f.bName ?? store.nameOf(f.b);
    const alerts = [...store.alerts.values()].filter((a) => a.flowIds.includes(id));
    const kv = (k: string, v: string | Node) => [h('div', { class: 'k' }, k), h('div', null, v)];
    if (isSimple()) {
      const st = plainStatus(f);
      this.summaryHost.append(
        h('h2', { style: 'margin:0;font-size:15px' }, `${store.nameOf(f.a) ?? f.a} and ${name ?? f.b}`),
        h('div', { class: 'muted' }, `${f.app} connection`),
        h('div', { class: 'explain', style: 'margin-top:12px' }, h('p', null, statusChip(st.kind, st.label), ' ', st.detail)),
        h('div', { class: 'kv' },
          ...kv('Device', `${store.nameOf(f.a) ?? ''} ${f.a}`.trim()),
          ...kv('Talking to', name ? `${name} (${f.b})` : f.b),
          ...kv('When', `${fmtTime(f.firstTs)}, lasted ${fmtDuration(f.lastTs - f.firstTs)}`),
          ...kv('Data sent', fmtBytes(f.bytesAB)),
          ...kv('Data received', fmtBytes(f.bytesBA)),
          ...(f.rttMs !== undefined ? kv('Response time', `${f.rttMs.toFixed(0)} ms${f.rttMs > 150 ? ' (slow)' : f.rttMs < 50 ? ' (fast)' : ''}`) : []),
          ...(alerts.length ? kv('Alerts', h('div', null, ...alerts.map((a) => h('div', null, h('button', { class: 'link', onclick: () => this.ctx.showAlerts(a.title) }, a.title))))) : []),
        ));
      return;
    }
    this.summaryHost.append(
      h('div', { class: 'card-head' },
        h('div', { class: 'grow' },
          h('h2', { style: 'margin:0;font-size:15px' }, `${f.app} connection #${f.id}`),
          h('div', { class: 'muted' }, `${f.a}${f.aPort !== undefined ? ':' + f.aPort : ''} → ${name ? `${name} (${f.b})` : f.b}${f.bPort !== undefined ? ':' + f.bPort : ''}`)),
        h('button', { class: 'small', onclick: () => this.ctx.showPackets(`flow:${f.id}`) }, icon('packets'), 'Show packets'),
        h('button', { class: 'small', title: `Add ${f.b} to the Watchlist`, onclick: () => this.ctx.addWatch('ip', f.b, name ?? undefined) }, icon('eye'), 'Watch server'),
        h('button', { class: 'small', onclick: async () => {
          const pk = await window.pi.getFlowPackets(f.id);
          const path = await window.pi.saveCapture(pk.map((p) => p.id));
          if (path) toast(`Saved ${pk.length} packets to ${path}`);
        } }, icon('save'), 'Save')),
      h('div', { class: 'kv' },
        ...kv('State', STATE_LABEL[f.state] + (f.state === 'reset' ? ' - aborted with RST' : '')),
        ...kv('Started', `${fmtTime(f.firstTs)} · lasted ${fmtDuration(f.lastTs - f.firstTs)}`),
        ...kv('Client → server', `${(f.packetsAB).toLocaleString()} packets · ${fmtBytes(f.bytesAB)}`),
        ...kv('Server → client', `${(f.packetsBA).toLocaleString()} packets · ${fmtBytes(f.bytesBA)}`),
        ...(f.rttMs !== undefined ? kv('Round-trip time', `${f.rttMs.toFixed(1)} ms (time for the server to answer the connection request)`) : []),
        ...(f.transport === 'TCP' ? kv('Reliability', `${f.retransmissions} retransmissions · ${f.dupAcks} duplicate ACKs · ${f.zeroWindows} zero-window · ${f.resets} resets`) : []),
        ...(alerts.length ? kv('Alerts', h('div', null, ...alerts.map((a) => h('div', null, h('button', { class: 'link', onclick: () => this.ctx.showAlerts(a.title) }, a.title))))) : []),
      ));
  }

  private renderLadder(f: FlowSummary, pkts: PacketSummary[]): void {
    clear(this.ladderHost);
    if (!pkts.length) { this.ladderHost.appendChild(h('div', { class: 'muted' }, 'Packets for this connection are no longer stored.')); return; }
    const shown = pkts.slice(0, LADDER_MAX);
    const W = Math.max(380, this.detailHost.clientWidth - 28);
    const timeW = 70, laneL = timeW + 70, laneR = W - 80;
    const rowH = 24, headH = 42;
    const t0 = shown[0].ts;
    // Insert "gap" rows when nothing happens for a while, so timing is visible.
    type Row = { kind: 'msg'; p: PacketSummary } | { kind: 'gap'; secs: number };
    const rows: Row[] = [];
    shown.forEach((p, i) => {
      if (i > 0 && p.ts - shown[i - 1].ts > 1) rows.push({ kind: 'gap', secs: p.ts - shown[i - 1].ts });
      rows.push({ kind: 'msg', p });
    });
    const H = headH + rows.length * rowH + 12;
    const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, height: H, role: 'img', 'aria-label': `Sequence diagram of connection ${f.id}` });
    const name = f.bName ?? store.nameOf(f.b);
    svg.append(
      s('text', { x: laneL, y: 14, 'text-anchor': 'middle', class: 'lane-label' }, 'Client'),
      s('text', { x: laneL, y: 28, 'text-anchor': 'middle', class: 'lane-sub' }, `${f.a}${f.aPort !== undefined ? ':' + f.aPort : ''}`),
      s('text', { x: laneR, y: 14, 'text-anchor': 'middle', class: 'lane-label' }, name ? (name.length > 26 ? name.slice(0, 25) + '…' : name) : 'Server'),
      s('text', { x: laneR, y: 28, 'text-anchor': 'middle', class: 'lane-sub' }, `${f.b}${f.bPort !== undefined ? ':' + f.bPort : ''}`),
      s('line', { x1: laneL, x2: laneL, y1: headH - 6, y2: H, class: 'life' }),
      s('line', { x1: laneR, x2: laneR, y1: headH - 6, y2: H, class: 'life' }),
      s('text', { x: 0, y: 28, class: 'lane-sub' }, 'Time'),
    );
    rows.forEach((r, i) => {
      const y = headH + i * rowH + rowH / 2;
      if (r.kind === 'gap') {
        const g = s('g', { class: 'gap' });
        g.append(s('text', { x: (laneL + laneR) / 2, y: y + 4, 'text-anchor': 'middle' }, `… ${fmtDuration(r.secs)} of silence …`));
        svg.append(g);
        return;
      }
      const p = r.p;
      const ab = p.src === f.a && (p.sport === undefined || p.sport === f.aPort);
      const x1 = ab ? laneL : laneR, x2 = ab ? laneR : laneL;
      const problem = p.tags.some((t) => ['retransmission', 'rst', 'dup-ack', 'zero-window'].includes(t)) || p.tags.includes('alert');
      const g = s('g', { class: `msg ${ab ? 'ab' : 'ba'}${problem ? ' problem' : ''}`, tabindex: 0, role: 'button' });
      const arrow = ab ? `M${x2 - 7},${y - 4}L${x2},${y}L${x2 - 7},${y + 4}` : `M${x2 + 7},${y - 4}L${x2},${y}L${x2 + 7},${y + 4}`;
      g.append(
        s('rect', { x: 0, y: y - rowH / 2, width: W, height: rowH, class: 'hit' }),
        s('text', { x: 0, y: y + 4, class: 't' }, `+${((p.ts - t0) * 1000).toFixed(p.ts - t0 < 10 ? 1 : 0)} ms`),
        s('line', { x1, x2, y1: y, y2: y }),
        s('path', { d: arrow, fill: 'none', stroke: ab ? 'var(--s1)' : 'var(--s3)', 'stroke-width': 1.5 }),
        s('text', { x: (laneL + laneR) / 2, y: y - 4, 'text-anchor': 'middle', class: 'lbl' }, ladderLabel(p, problem)),
      );
      g.addEventListener('click', () => this.ctx.showPackets(`flow:${f.id}`, p.id));
      g.addEventListener('keydown', (e) => { if ((e as KeyboardEvent).key === 'Enter') this.ctx.showPackets(`flow:${f.id}`, p.id); });
      g.addEventListener('mousemove', (e) => showTip((e as MouseEvent).clientX, (e as MouseEvent).clientY, `#${p.id} · ${p.proto} · ${p.len} bytes\n${p.info}\nClick to open the packet`));
      g.addEventListener('mouseleave', hideTip);
      svg.append(g);
    });
    this.ladderHost.appendChild(svg);
    const legend = h('div', { class: 'legend' },
      h('span', null, h('i', { style: 'background: var(--s1)' }), 'Client → server'),
      h('span', null, h('i', { style: 'background: var(--s3)' }), 'Server → client'),
      h('span', null, '⚠ marks retransmissions, resets and alert evidence'));
    this.ladderHost.appendChild(legend);
    if (pkts.length > LADDER_MAX) this.ladderHost.appendChild(h('div', { class: 'muted' }, `Showing the first ${LADDER_MAX} of ${pkts.length} packets. Use “Show packets” for the full list.`));
  }
}

function ladderLabel(p: PacketSummary, problem: boolean): string {
  let label = p.info.replace(/^\[[^\]]+\]\s*/, '');
  if (p.proto === 'TCP') {
    const m = /\[([^\]]+)\].*Len=(\d+)/.exec(p.info);
    if (m) label = `${m[1]}${m[2] !== '0' ? ` · ${m[2]} bytes` : ''}`;
  }
  const prefix = p.tags.includes('retransmission') ? '⚠ Retransmission: ' : p.tags.includes('rst') ? '⚠ ' : p.tags.includes('dup-ack') ? '⚠ Dup ACK: ' : p.tags.includes('zero-window') ? '⚠ Zero window: ' : problem ? '⚠ ' : '';
  const full = `${prefix}${p.proto !== 'TCP' && p.proto !== 'UDP' ? p.proto + ': ' : ''}${label}`;
  return full.length > 64 ? full.slice(0, 62) + '…' : full;
}
