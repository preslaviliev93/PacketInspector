import type { EngineUpdate } from '../../shared/types';
import { h, clear, fmtBytes, fmtNum, fmtRate, statusChip, severityKind, icon } from '../dom';
import { areaChart, barList } from '../charts';
import { store } from '../store';
import { protoColor, FAMILY_LEGEND, type Ctx, type View } from '../ctx';
import { isSimple, t, severityLabel } from '../mode';

export class DashboardView implements View {
  private tiles = h('div', { class: 'tiles' });
  private chartHost = h('div', { class: 'chart' });
  private protoHost = h('div');
  private talkHost = h('div');
  private destHost = h('div');
  private recentHost = h('div');
  private emptyHost = h('div');
  private grid: HTMLElement;
  private mode: 'bits' | 'packets' = 'bits';
  private protoMode: 'packets' | 'bytes' = 'packets';
  private segBits = h('button', { class: 'on' }, 'Bits/s');
  private segPkts = h('button', null, 'Packets/s');
  private segPP = h('button', { class: 'on' }, 'Packets');
  private segPB = h('button', null, 'Bytes');
  // Headings whose wording depends on the mode.
  private hThroughput = h('h2');
  private sThroughput = h('p', { class: 'sub' });
  private hTalkers = h('h2');
  private sTalkers = h('p', { class: 'sub' });
  private hDest = h('h2');
  private sDest = h('p', { class: 'sub' });
  private hRecent = h('h2');
  private sRecent = h('p', { class: 'sub' });

  constructor(private root: HTMLElement, private ctx: Ctx, start: HTMLElement) {
    this.segBits.onclick = () => { this.mode = 'bits'; this.segBits.classList.add('on'); this.segPkts.classList.remove('on'); this.renderChart(); };
    this.segPkts.onclick = () => { this.mode = 'packets'; this.segPkts.classList.add('on'); this.segBits.classList.remove('on'); this.renderChart(); };
    this.segPP.onclick = () => { this.protoMode = 'packets'; this.segPP.classList.add('on'); this.segPB.classList.remove('on'); this.renderProtocols(); };
    this.segPB.onclick = () => { this.protoMode = 'bytes'; this.segPB.classList.add('on'); this.segPP.classList.remove('on'); this.renderProtocols(); };

    this.emptyHost.appendChild(start);

    const legend = h('div', { class: 'legend' }, FAMILY_LEGEND.map((f) => h('span', null, h('i', { style: `background: var(--s${f.slot})` }), f.label)));
    this.grid = h('div', { class: 'dash-grid' },
      h('div', { class: 'card' },
        h('div', { class: 'card-head' },
          h('div', { class: 'grow' }, this.hThroughput, this.sThroughput),
          h('div', { class: 'seg expert-only' }, this.segBits, this.segPkts)),
        this.chartHost),
      h('div', { class: 'card expert-only' },
        h('div', { class: 'card-head' },
          h('div', { class: 'grow' }, h('h2', null, 'Protocols'), h('p', { class: 'sub' }, 'Click a protocol to see its packets.')),
          h('div', { class: 'seg' }, this.segPP, this.segPB)),
        this.protoHost, legend),
      h('div', { class: 'card' }, this.hTalkers, this.sTalkers, this.talkHost),
      h('div', { class: 'card' }, this.hDest, this.sDest, this.destHost),
      h('div', { class: 'card wide' }, this.hRecent, this.sRecent, this.recentHost),
    );
    root.append(this.tiles, this.emptyHost, this.grid);
    new ResizeObserver(() => { if (this.root.classList.contains('active')) this.renderChart(); }).observe(this.chartHost);
  }

  show(): void {
    this.render();
  }

  update(u: EngineUpdate): void {
    if (u.stats || u.reset || u.alerts.length || u.status) this.render();
  }

  private render(): void {
    const st = store.stats;
    const hasData = !!st && st.totalPackets > 0;
    const active = hasData || store.status.state === 'capturing' || store.status.state === 'reading';
    this.emptyHost.style.display = active ? 'none' : '';
    this.grid.style.display = active ? '' : 'none';
    this.tiles.style.display = active ? '' : 'none';
    this.renderTiles();
    if (!hasData && store.status.state !== 'capturing') return;
    this.hThroughput.textContent = t('Throughput', 'Network activity');
    this.sThroughput.textContent = t('Traffic per second over the last two minutes. Hover for exact values.', 'How busy the network has been over the last two minutes.');
    this.hTalkers.textContent = t('Top talkers', 'Busiest devices');
    this.sTalkers.textContent = t('Addresses sending or receiving the most data. Click to trace.', 'Which machines are using the most data. Click one to see its connections.');
    this.hDest.textContent = t('Top internet destinations', 'Most-used websites and services');
    this.sDest.textContent = t('Public servers receiving traffic, with names learned from DNS / TLS.', 'Where your data is going on the internet.');
    this.hRecent.textContent = t('Latest alerts', 'Things worth knowing');
    this.sRecent.textContent = t('Suspicious activity and network problems, most severe first.', 'Anything suspicious or broken, most important first.');
    const open = (k: string) => (isSimple() ? this.ctx.showConnections(k) : this.ctx.showPackets(`host:${k}`));
    this.renderChart();
    this.renderProtocols();
    const nameOf = (ip: string) => store.nameOf(ip);
    barList(this.talkHost, (st?.topTalkers ?? []).slice(0, 8).map((t) => ({
      key: t.key,
      label: t.label ?? nameOf(t.key) ?? t.key,
      title: t.key,
      value: t.bytes,
      valueLabel: fmtBytes(t.bytes),
      tip: `${t.key}${t.label ? ` (${t.label})` : ''}\n${fmtBytes(t.bytes)}${isSimple() ? '' : ` in ${t.packets.toLocaleString()} packets`}`,
    })), open);
    barList(this.destHost, (st?.topDestinations ?? []).slice(0, 8).map((t) => ({
      key: t.key,
      label: t.label ?? nameOf(t.key) ?? t.key,
      title: t.key,
      value: t.bytes,
      valueLabel: fmtBytes(t.bytes),
      tip: `${t.key}${t.label ? ` (${t.label})` : ''}\n${fmtBytes(t.bytes)} sent`,
    })), open, 'No internet destinations seen yet');
    this.renderRecent();
  }

  private renderTiles(): void {
    clear(this.tiles);
    const st = store.stats;
    const last = st?.timeline.length ? st.timeline[st.timeline.length - (st.timeline.length > 1 ? 2 : 1)] : null;
    const sev = store.alertsBySeverity();
    const totalAlerts = sev.high + sev.medium + sev.low;
    const worst = st?.health.findings.reduce<string | null>((w, f) => {
      const rank = { good: 0, warning: 1, serious: 2, critical: 3 };
      return !w || rank[f.status] > rank[w as keyof typeof rank] ? f.status : w;
    }, null);
    const tile = (label: string, value: string | Node, hint: string, onClick?: () => void) => {
      const el = h('div', { class: `tile${onClick ? ' clickable' : ''}`, role: onClick ? 'button' : undefined, tabindex: onClick ? 0 : undefined },
        h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'hint' }, hint));
      if (onClick) { el.onclick = onClick; el.onkeydown = (e) => { if (e.key === 'Enter') onClick(); }; }
      return el;
    };
    const simple = isSimple();
    const since = st?.startTs ? `since ${new Date(st.startTs * 1000).toLocaleTimeString()}` : 'no capture yet';
    const counts = simple
      ? [sev.high && `${sev.high} need attention`, sev.medium && `${sev.medium} worth a look`, sev.low && `${sev.low} minor`].filter(Boolean).join(' · ')
      : `${sev.high} high · ${sev.medium} medium · ${sev.low} low`;
    this.tiles.append(
      ...(simple ? [] : [tile('Packets', fmtNum(st?.totalPackets ?? 0), since, () => this.ctx.showPackets(''))]),
      tile(t('Data', 'Data used'), fmtBytes(st?.totalBytes ?? 0), simple ? since : 'total on the wire'),
      tile(t('Right now', 'Speed right now'), last ? fmtRate(last.bytes) : '-', last ? (simple ? 'current network speed' : `${last.packets} packets/s`) : 'throughput'),
      tile('Connections', fmtNum(store.flows.size), t('click to trace them', 'click to see them'), () => this.ctx.go('flows')),
      tile('Alerts', totalAlerts ? String(totalAlerts) : '0',
        totalAlerts ? counts : sev.info ? `${sev.info} informational` : 'nothing suspicious', () => this.ctx.go('alerts')),
      tile('Network health', worst ? statusChip(worst as 'good', worst === 'good' ? 'Healthy' : worst === 'warning' ? 'Minor issues' : worst === 'serious' ? 'Problems' : 'Critical') : '-',
        t('loss, latency, DNS', 'speed, reliability, lookups'), () => this.ctx.go('health')),
    );
  }

  private renderChart(): void {
    const tl = store.stats?.timeline ?? [];
    // Drop the still-filling current second so the line doesn't dip at the end.
    const pts = (tl.length > 2 ? tl.slice(0, -1) : tl).map((p) => ({ t: p.t, v: this.mode === 'bits' ? p.bytes * 8 : p.packets, b: p.bytes, p: p.packets }));
    areaChart(this.chartHost, pts, {
      height: 290,
      fmtY: (v) => (this.mode === 'bits' ? fmtRate(v / 8).replace('bit/s', '') : fmtNum(v)),
      fmtTip: (p) => `${fmtRate(p.b)} · ${p.p.toLocaleString()} packets`,
    });
  }

  private renderProtocols(): void {
    const protos = store.stats?.protocols ?? [];
    const metric = (x: { packets: number; bytes: number }) => (this.protoMode === 'packets' ? x.packets : x.bytes);
    const sorted = [...protos].sort((a, b) => metric(b) - metric(a));
    const topN = sorted.slice(0, 8);
    const rest = sorted.slice(8);
    const total = sorted.reduce((s, x) => s + metric(x), 0) || 1;
    const items = topN.map((p) => ({
      key: p.key,
      label: p.key,
      value: metric(p),
      valueLabel: `${((metric(p) / total) * 100).toFixed(1)}%`,
      tip: `${p.key}: ${p.packets.toLocaleString()} packets, ${fmtBytes(p.bytes)}`,
      color: protoColor(p.key),
    }));
    if (rest.length) {
      const o = rest.reduce((s, x) => ({ packets: s.packets + x.packets, bytes: s.bytes + x.bytes }), { packets: 0, bytes: 0 });
      items.push({ key: rest.map((r) => r.key.toLowerCase()).join(','), label: `Other (${rest.length})`, value: metric(o), valueLabel: `${((metric(o) / total) * 100).toFixed(1)}%`, tip: rest.map((r) => r.key).join(', '), color: 'var(--muted)' });
    }
    barList(this.protoHost, items, (k) => this.ctx.showPackets(`proto:${k.toLowerCase()}`));
  }

  private renderRecent(): void {
    clear(this.recentHost);
    const rank = { high: 3, medium: 2, low: 1, info: 0 };
    const alerts = [...store.alerts.values()].sort((a, b) => rank[b.severity] - rank[a.severity] || b.ts - a.ts).slice(0, 6);
    if (!alerts.length) {
      this.recentHost.appendChild(h('div', { class: 'muted' }, statusChip('good', 'Clear'), '  Nothing suspicious detected so far.'));
      return;
    }
    const ul = h('ul', { class: 'list' });
    for (const a of alerts) {
      ul.appendChild(h('li', null,
        statusChip(severityKind(a.severity), severityLabel(a.severity)),
        h('span', { class: 'grow' }, a.title),
        h('button', { class: 'small', onclick: () => this.ctx.showAlerts(a.title) }, 'Details'),
        isSimple() ? null : h('button', { class: 'small', onclick: () => this.ctx.showPackets(`id:${a.packetIds.join(',')}`, a.packetIds[0]) }, icon('link'), `${a.packetIds.length} packet${a.packetIds.length > 1 ? 's' : ''}`)));
    }
    this.recentHost.appendChild(ul);
  }
}
