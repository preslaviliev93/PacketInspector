import type { EngineUpdate, Field, PacketDetail, PacketSummary } from '../../shared/types';
import { h, clear, fmtTime, icon, toast } from '../dom';
import { compileFilter, type CompiledFilter } from '../filter';
import { FilterBar } from '../filterbar';
import { store } from '../store';
import { protoColor, type Ctx, type View } from '../ctx';

const ROW_H = 24;
const PROBLEM = ['retransmission', 'rst', 'dup-ack', 'zero-window', 'malformed', 'dns-error'];
const TAG_LABEL: Record<string, string> = {
  retransmission: 'Retransmission', rst: 'Reset', 'dup-ack': 'Duplicate ACK', 'zero-window': 'Zero window',
  syn: 'Connection request', 'syn-ack': 'Connection accepted', 'handshake-done': 'Connection open', fin: 'Closing',
  alert: 'Evidence for an alert', credentials: 'Credentials exposed', malformed: 'Malformed', 'keep-alive': 'Keep-alive', 'dns-error': 'Failed lookup', watch: 'Matches your Watchlist', database: 'Database traffic', mikrotik: 'From MikroTik stream',
};

export class PacketsView implements View {
  private count = h('span', { class: 'count' });
  private follow = h('button', { class: 'small', title: 'Keep the newest packet in view' }, 'Auto-scroll');
  private list = h('div', { class: 'vlist', tabindex: 0, role: 'grid', 'aria-label': 'Packet list' });
  private spacer = h('div');
  private rowsHost = h('div');
  private detailLeft = h('div', { class: 'left' });
  private detailRight = h('div');
  private filter: CompiledFilter = compileFilter('', () => undefined);
  private bar!: FilterBar;
  private visible: PacketSummary[] = [];
  private selectedId: number | null = null;
  private autoScroll = true;
  private renderQueued = false;
  private hexBytes: HTMLElement[] = [];
  private hexAscii: HTMLElement[] = [];

  constructor(root: HTMLElement, private ctx: Ctx) {
    root.classList.add('split');
    this.bar = new FilterBar(() => this.applyFilter(), [this.count, this.follow]);
    const bar = this.bar.el;
    const head = h('div', { class: 'head', role: 'row' },
      ...['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'].map((c, i) => h('div', { class: i === 0 || i === 5 ? 'num' : '', role: 'columnheader' }, c)));
    this.list.append(head, this.spacer);
    this.spacer.appendChild(this.rowsHost);
    this.spacer.style.position = 'relative';
    const splitter = h('div', { class: 'splitter', role: 'separator', 'aria-orientation': 'horizontal' });
    const detail = h('div', { class: 'detail' }, this.detailLeft, this.detailRight);
    root.append(bar, this.list, splitter, detail);
    this.renderDetailEmpty();

    this.follow.onclick = () => this.setAutoScroll(!this.autoScroll);
    this.setAutoScroll(true);
    this.list.addEventListener('scroll', () => {
      const atBottom = this.list.scrollTop + this.list.clientHeight >= this.list.scrollHeight - ROW_H * 2;
      if (!atBottom && this.autoScroll && this.userScrolled) this.setAutoScroll(false);
      this.userScrolled = true;
      this.queueRender();
    });
    this.list.addEventListener('wheel', () => { this.userScrolled = true; }, { passive: true });
    this.list.addEventListener('keydown', (e) => this.onKey(e));
    new ResizeObserver(() => this.queueRender()).observe(this.list);

    // Drag to resize the detail pane.
    splitter.addEventListener('mousedown', (e) => {
      e.preventDefault();
      const rect = root.getBoundingClientRect();
      const move = (ev: MouseEvent) => {
        const pct = Math.min(80, Math.max(15, ((rect.bottom - ev.clientY) / rect.height) * 100));
        root.style.setProperty('--detail-h', `${pct}%`);
      };
      const up = () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); };
      window.addEventListener('mousemove', move);
      window.addEventListener('mouseup', up);
    });
  }

  private userScrolled = false;

  private setAutoScroll(on: boolean): void {
    this.autoScroll = on;
    this.follow.classList.toggle('primary', on);
    this.follow.setAttribute('aria-pressed', String(on));
    if (on) this.scrollToBottom();
  }

  setFilter(q: string, selectId?: number): void {
    this.bar.setQuery(q);
    this.applyFilter();
    if (selectId !== undefined) {
      this.setAutoScroll(false);
      this.select(selectId, true);
    }
  }

  private applyFilter(): void {
    this.filter = compileFilter(this.bar.query(), (ip) => store.nameOf(ip), (id) => store.flows.get(id)?.db?.system);
    this.bar.setError(this.filter.error);
    this.visible = this.filter.empty ? store.packets.slice() : store.packets.filter(this.filter.test);
    this.updateCount();
    this.layout();
    if (this.autoScroll) this.scrollToBottom();
    else if (this.selectedId !== null) this.scrollToId(this.selectedId);
  }

  show(): void {
    this.applyFilter();
  }

  update(u: EngineUpdate): void {
    if (u.reset) {
      this.selectedId = null;
      this.renderDetailEmpty();
      this.applyFilter();
      return;
    }
    if (u.packets.length) {
      for (const p of u.packets) if (this.filter.empty || this.filter.test(p)) this.visible.push(p);
      this.updateCount();
      this.layout();
      if (this.autoScroll) this.scrollToBottom();
    }
  }

  private updateCount(): void {
    const total = store.packets.length;
    this.count.textContent = this.filter.empty
      ? `${total.toLocaleString()} packets`
      : `${this.visible.length.toLocaleString()} of ${total.toLocaleString()}`;
  }

  private layout(): void {
    this.spacer.style.height = `${this.visible.length * ROW_H}px`;
    this.queueRender();
  }

  private scrollToBottom(): void {
    this.userScrolled = false;
    this.list.scrollTop = this.list.scrollHeight;
  }

  private scrollToId(id: number): void {
    const idx = this.visible.findIndex((p) => p.id === id);
    if (idx < 0) return;
    const y = idx * ROW_H;
    const headH = ROW_H;
    if (y < this.list.scrollTop || y + ROW_H * 2 > this.list.scrollTop + this.list.clientHeight - headH) {
      this.userScrolled = false;
      this.list.scrollTop = Math.max(0, y - this.list.clientHeight / 3);
    }
  }

  private queueRender(): void {
    if (this.renderQueued) return;
    this.renderQueued = true;
    requestAnimationFrame(() => {
      this.renderQueued = false;
      this.renderRows();
    });
  }

  private renderRows(): void {
    const top = Math.max(0, this.list.scrollTop - ROW_H);
    const first = Math.max(0, Math.floor(top / ROW_H) - 5);
    const count = Math.ceil(this.list.clientHeight / ROW_H) + 12;
    const last = Math.min(this.visible.length, first + count);
    clear(this.rowsHost);
    const frag = document.createDocumentFragment();
    for (let i = first; i < last; i++) {
      const p = this.visible[i];
      const cls = ['prow'];
      if (p.tags.includes('alert') || p.tags.includes('credentials')) cls.push('alert');
      else if (p.tags.some((t) => PROBLEM.includes(t))) cls.push('problem');
      if (p.id === this.selectedId) cls.push('sel');
      const srcName = store.nameOf(p.src);
      const dstName = store.nameOf(p.dst);
      const proto = h('span', { class: 'proto' }, p.proto);
      proto.style.setProperty('--pc', protoColor(p.proto));
      const row = h('div', { class: cls.join(' '), role: 'row', 'aria-selected': String(p.id === this.selectedId) },
        h('div', { class: 'num' }, p.id),
        h('div', null, fmtTime(p.ts)),
        h('div', { title: srcName ? `${p.src} (${srcName})` : p.src }, srcName ?? p.src),
        h('div', { title: dstName ? `${p.dst} (${dstName})` : p.dst }, dstName ?? p.dst),
        h('div', null, proto),
        h('div', { class: 'num' }, p.len),
        h('div', { title: p.info }, p.info));
      row.style.top = `${i * ROW_H}px`;
      row.addEventListener('click', () => { this.setAutoScroll(false); this.select(p.id, false); });
      row.addEventListener('dblclick', () => { if (p.flowId) this.ctx.showFlow(p.flowId); });
      frag.appendChild(row);
    }
    this.rowsHost.appendChild(frag);
  }

  private onKey(e: KeyboardEvent): void {
    if (!['ArrowDown', 'ArrowUp', 'PageDown', 'PageUp', 'Home', 'End'].includes(e.key)) return;
    e.preventDefault();
    if (!this.visible.length) return;
    let idx = this.selectedId === null ? -1 : this.visible.findIndex((p) => p.id === this.selectedId);
    const page = Math.floor(this.list.clientHeight / ROW_H) - 2;
    if (e.key === 'ArrowDown') idx++;
    else if (e.key === 'ArrowUp') idx--;
    else if (e.key === 'PageDown') idx += page;
    else if (e.key === 'PageUp') idx -= page;
    else if (e.key === 'Home') idx = 0;
    else idx = this.visible.length - 1;
    idx = Math.max(0, Math.min(this.visible.length - 1, idx));
    this.setAutoScroll(false);
    this.select(this.visible[idx].id, true);
  }

  async select(id: number, scroll: boolean): Promise<void> {
    this.selectedId = id;
    if (scroll) this.scrollToId(id);
    this.queueRender();
    const d = await window.pi.getPacketDetail(id);
    if (this.selectedId !== id) return;
    if (d) this.renderDetail(d);
    else {
      clear(this.detailLeft);
      this.detailLeft.appendChild(h('div', { class: 'muted' }, 'Packet bytes are no longer stored.'));
    }
  }

  private renderDetailEmpty(): void {
    clear(this.detailLeft);
    clear(this.detailRight);
    this.detailLeft.appendChild(h('div', { class: 'empty' }, h('h3', null, 'Select a packet'), h('div', null, 'You will get a plain-English explanation, every decoded field, and the raw bytes. Use ↑/↓ to step through packets; double-click to open its connection.')));
  }

  private renderDetail(d: PacketDetail): void {
    clear(this.detailLeft);
    clear(this.detailRight);
    const p = d.summary;
    const flow = p.flowId ? store.flows.get(p.flowId) : undefined;
    const alerts = [...store.alerts.values()].filter((a) => a.packetIds.includes(p.id));
    const actions = h('div', { class: 'actions' });
    if (p.flowId) actions.append(h('button', { class: 'small', onclick: () => this.ctx.showFlow(p.flowId!) }, icon('flows'), 'Trace connection'));
    if (p.flowId) actions.append(h('button', { class: 'small', onclick: () => this.setFilter(`flow:${p.flowId}`, p.id) }, 'Only this connection'));
    actions.append(h('button', { class: 'small', onclick: () => this.setFilter(`host:${p.src}`, p.id) }, `Host ${p.src}`));
    if (p.dst !== p.src) actions.append(h('button', { class: 'small', onclick: () => this.setFilter(`host:${p.dst}`, p.id) }, `Host ${p.dst}`));
    // Offer to watch the "interesting" side: the internet address if there is one, else the destination.
    const isIp = (a: string) => /^[\d.]+$|:/.test(a) && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(a);
    const priv = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|fe80:|f[cd])/i;
    const target = [p.dst, p.src].find((a) => isIp(a) && !priv.test(a)) ?? (isIp(p.dst) ? p.dst : undefined);
    if (target) actions.append(h('button', { class: 'small', title: `Add ${target} to the Watchlist`, onclick: () => this.ctx.addWatch('ip', target) }, icon('eye'), `Watch ${target}`));
    for (const a of alerts.slice(0, 3)) actions.append(h('button', { class: 'small', onclick: () => this.ctx.showAlerts(a.title) }, icon('alerts'), a.title));

    const tags = p.tags.filter((t) => TAG_LABEL[t]).map((t) => h('span', { class: `tag${PROBLEM.includes(t) ? ' problem' : t === 'alert' || t === 'credentials' ? ' alert' : ''}` }, TAG_LABEL[t]));
    this.detailLeft.appendChild(h('div', { class: 'explain' },
      h('h3', null, `Packet #${p.id} - what is happening?`),
      ...d.explanation.map((s) => h('p', null, s)),
      tags.length ? h('div', null, ...tags) : null,
      flow ? h('p', { class: 'muted' }, `Part of connection #${flow.id}: ${flow.a}${flow.aPort ? ':' + flow.aPort : ''} ⇄ ${flow.bName ?? flow.b}${flow.bPort ? ':' + flow.bPort : ''} (${flow.app}), ${flow.packetsAB + flow.packetsBA} packets.`) : null,
      actions));

    const tree = h('div', { class: 'tree' });
    d.layers.forEach((layer, i) => {
      const det = h('details', i > 0 ? { open: true } : null);
      const sum = h('summary', null, layer.name, h('span', { class: 's' }, layer.summary));
      sum.addEventListener('mouseenter', () => this.highlight(layer.offset, layer.length, 'layer'));
      sum.addEventListener('mouseleave', () => this.highlight(0, 0, 'layer'));
      det.appendChild(sum);
      for (const f of layer.fields) det.appendChild(this.fieldEl(f));
      tree.appendChild(det);
    });
    this.detailLeft.append(h('div', { class: 'section-title' }, 'Decoded layers'), tree);
    this.renderHex(d.bytes);
  }

  private fieldEl(f: Field): HTMLElement {
    const row = h('div', { class: 'fld', title: f.offset !== undefined ? `bytes ${f.offset}–${f.offset + (f.length ?? 1) - 1}` : '' },
      h('span', { class: 'k' }, f.label), h('span', { class: 'v' }, f.value));
    row.addEventListener('click', () => {
      this.detailLeft.querySelectorAll('.fld.sel').forEach((e) => e.classList.remove('sel'));
      row.classList.add('sel');
      if (f.offset !== undefined) this.highlight(f.offset, f.length ?? 1, 'hl', true);
    });
    if (!f.children?.length) return row;
    return h('div', null, row, h('div', { class: 'kids' }, ...f.children.map((c) => this.fieldEl(c))));
  }

  private renderHex(bytes: Uint8Array): void {
    this.hexBytes = [];
    this.hexAscii = [];
    const pre = h('div', { class: 'hex' });
    for (let off = 0; off < bytes.length; off += 16) {
      const line = h('div');
      line.appendChild(h('span', { class: 'off' }, off.toString(16).padStart(4, '0') + '  '));
      for (let i = 0; i < 16; i++) {
        const b = bytes[off + i];
        const el = h('span', { class: 'b' }, b === undefined ? '  ' : b.toString(16).padStart(2, '0'));
        if (b !== undefined) this.hexBytes.push(el);
        line.append(el, i === 7 ? '  ' : ' ');
      }
      line.append(' ');
      for (let i = 0; i < 16 && off + i < bytes.length; i++) {
        const b = bytes[off + i];
        const el = h('span', { class: 'a' }, b >= 32 && b < 127 ? String.fromCharCode(b) : '·');
        this.hexAscii.push(el);
        line.append(el);
      }
      pre.appendChild(line);
    }
    const copy = h('button', { class: 'small', onclick: () => {
      const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
      navigator.clipboard.writeText(hex).then(() => toast('Packet bytes copied as hex'));
    } }, 'Copy hex');
    this.detailRight.append(h('div', { class: 'toolbar-row' }, h('div', { class: 'section-title grow' }, `Raw bytes (${bytes.length})`), copy), pre);
  }

  private highlight(offset: number, length: number, cls: 'hl' | 'layer', scroll = false): void {
    for (const arr of [this.hexBytes, this.hexAscii]) {
      arr.forEach((el, i) => el.classList.toggle(cls, i >= offset && i < offset + length));
    }
    if (scroll && this.hexBytes[offset]) this.hexBytes[offset].scrollIntoView({ block: 'nearest' });
  }
}
