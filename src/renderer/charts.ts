// Lightweight SVG/HTML charts following the app's data-viz rules:
// 2px lines with a 10% wash, hairline solid gridlines, one axis,
// crosshair + tooltip on hover, bars capped at 14px with 4px rounded ends.

import { h, s, clear, showTip, hideTip } from './dom';

function niceStep(max: number, ticks: number): number {
  const raw = max / ticks;
  const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
  const n = raw / mag;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * mag;
}

export interface Point { t: number; v: number; [extra: string]: number }

export function areaChart(host: HTMLElement, pts: Point[], opts: { height?: number; fmtY: (v: number) => string; fmtTip: (p: Point) => string; empty?: string }): void {
  clear(host);
  const W = Math.max(200, host.clientWidth || 600);
  const H = opts.height ?? 200;
  const padL = 64, padR = 12, padT = 8, padB = 22;
  const iw = W - padL - padR, ih = H - padT - padB;
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, height: H, role: 'img' });
  host.appendChild(svg);
  if (pts.length < 2) {
    svg.append(s('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle', class: 'tick' }, opts.empty ?? 'Waiting for traffic…'));
    return;
  }
  const maxV = Math.max(1, ...pts.map((p) => p.v));
  const step = niceStep(maxV, 4);
  const top = Math.ceil(maxV / step) * step;
  const t0 = pts[0].t, t1 = pts[pts.length - 1].t;
  const x = (t: number) => padL + ((t - t0) / Math.max(1, t1 - t0)) * iw;
  const y = (v: number) => padT + ih - (v / top) * ih;

  for (let v = 0; v <= top + 1e-9; v += step) {
    svg.append(s('line', { x1: padL, x2: W - padR, y1: y(v), y2: y(v), class: v === 0 ? 'baseline' : 'gridline' }));
    svg.append(s('text', { x: padL - 8, y: y(v) + 4, 'text-anchor': 'end', class: 'tick' }, opts.fmtY(v)));
  }
  const span = t1 - t0;
  const tickEvery = span > 240 ? 60 : span > 100 ? 30 : span > 40 ? 15 : 5;
  for (let t = Math.ceil(t0 / tickEvery) * tickEvery; t <= t1; t += tickEvery) {
    const d = new Date(t * 1000);
    svg.append(s('text', { x: x(t), y: H - 4, 'text-anchor': 'middle', class: 'tick' }, d.toLocaleTimeString(undefined, { hour12: false })));
  }
  const line = pts.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join('');
  svg.append(s('path', { d: `${line}L${x(t1)},${y(0)}L${x(t0)},${y(0)}Z`, class: 'area' }));
  svg.append(s('path', { d: line, class: 'line' }));
  const last = pts[pts.length - 1];
  svg.append(s('circle', { cx: x(last.t), cy: y(last.v), r: 4, class: 'dot' }));

  // Hover layer: crosshair + tooltip, hit area is the whole plot.
  const cross = s('line', { y1: padT, y2: padT + ih, class: 'cross', visibility: 'hidden' });
  const hov = s('circle', { r: 4, class: 'dot', visibility: 'hidden' });
  const hit = s('rect', { x: padL, y: padT, width: iw, height: ih, fill: 'transparent' });
  svg.append(cross, hov, hit);
  hit.addEventListener('mousemove', (e) => {
    const r = svg.getBoundingClientRect();
    const mx = ((e.clientX - r.left) / r.width) * W;
    const t = t0 + ((mx - padL) / iw) * (t1 - t0);
    let best = pts[0];
    for (const p of pts) if (Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
    cross.setAttribute('x1', String(x(best.t)));
    cross.setAttribute('x2', String(x(best.t)));
    hov.setAttribute('cx', String(x(best.t)));
    hov.setAttribute('cy', String(y(best.v)));
    cross.setAttribute('visibility', 'visible');
    hov.setAttribute('visibility', 'visible');
    showTip(e.clientX, e.clientY, h('div', null, h('b', null, new Date(best.t * 1000).toLocaleTimeString(undefined, { hour12: false })), h('br'), opts.fmtTip(best)));
  });
  hit.addEventListener('mouseleave', () => {
    cross.setAttribute('visibility', 'hidden');
    hov.setAttribute('visibility', 'hidden');
    hideTip();
  });
}

export interface BarItem {
  key: string;
  label: string;
  value: number;
  valueLabel: string;
  tip: string;
  color?: string;
  title?: string;
}

export function barList(host: HTMLElement, items: BarItem[], onClick: (key: string) => void, empty = 'No data yet'): void {
  clear(host);
  if (!items.length) {
    host.appendChild(h('div', { class: 'muted' }, empty));
    return;
  }
  const max = Math.max(...items.map((i) => i.value), 1);
  const wrap = h('div', { class: 'bars' });
  for (const it of items) {
    const fill = h('div', { class: 'bar-fill' });
    fill.style.width = `${(it.value / max) * 100}%`;
    if (it.color) fill.style.setProperty('--bc', it.color);
    const row = h('div', { class: 'bar-row', tabindex: 0, role: 'button', 'aria-label': `${it.label}: ${it.valueLabel}` },
      h('div', { class: 'name', title: it.title ?? it.label }, it.label),
      h('div', { class: 'bar-track' }, fill),
      h('div', { class: 'val' }, it.valueLabel));
    row.addEventListener('click', () => onClick(it.key));
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter') onClick(it.key); });
    row.addEventListener('mousemove', (e) => showTip(e.clientX, e.clientY, it.tip));
    row.addEventListener('mouseleave', hideTip);
    wrap.appendChild(row);
  }
  host.appendChild(wrap);
}
