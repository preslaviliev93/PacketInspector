// Tiny DOM + formatting helpers (no framework).

type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, string | number | boolean | EventListener | undefined | null>;

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs | null = null, ...children: (Child | Child[])[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v as EventListener);
      else if (k === 'class') el.className = String(v);
      else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, String(v));
    }
  }
  append(el, children);
  return el;
}

function append(el: Element, children: (Child | Child[])[]): void {
  for (const c of children) {
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else if (c !== null && c !== undefined && c !== false) el.appendChild(document.createTextNode(String(c)));
  }
}

const SVG_NS = 'http://www.w3.org/2000/svg';
export function s<K extends keyof SVGElementTagNameMap>(tag: K, attrs: Record<string, string | number | undefined> = {}, ...children: (SVGElement | string)[]): SVGElementTagNameMap[K] {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined) el.setAttribute(k, String(v));
  for (const c of children) el.append(c);
  return el;
}

export function clear(el: Element): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function $(sel: string): HTMLElement {
  const el = document.querySelector(sel);
  if (!el) throw new Error(`missing element ${sel}`);
  return el as HTMLElement;
}

export function fmtBytes(n: number): string {
  if (n < 1000) return `${n} B`;
  if (n < 1e6) return `${(n / 1e3).toFixed(1)} KB`;
  if (n < 1e9) return `${(n / 1e6).toFixed(1)} MB`;
  return `${(n / 1e9).toFixed(2)} GB`;
}

export function fmtRate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8;
  if (bits < 1e3) return `${bits.toFixed(0)} bit/s`;
  if (bits < 1e6) return `${(bits / 1e3).toFixed(1)} kbit/s`;
  if (bits < 1e9) return `${(bits / 1e6).toFixed(1)} Mbit/s`;
  return `${(bits / 1e9).toFixed(2)} Gbit/s`;
}

export function fmtNum(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1e6) return `${(n / 1e3).toFixed(n < 1e4 ? 1 : 0)}K`;
  return `${(n / 1e6).toFixed(1)}M`;
}

export function fmtTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString(undefined, { hour12: false }) + '.' + String(Math.floor((ts % 1) * 1000)).padStart(3, '0');
}

export function fmtDuration(sec: number): string {
  if (sec < 1) return `${(sec * 1000).toFixed(0)} ms`;
  if (sec < 60) return `${sec.toFixed(1)} s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m ${Math.floor(sec % 60)}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

// --------------------------------------------------------------- tooltip

let tip: HTMLDivElement | null = null;
export function showTip(x: number, y: number, content: Node | string): void {
  if (!tip) {
    tip = h('div', { class: 'tooltip', role: 'tooltip' });
    document.body.appendChild(tip);
  }
  clear(tip);
  tip.append(content);
  tip.style.display = 'block';
  const r = tip.getBoundingClientRect();
  const left = Math.min(window.innerWidth - r.width - 8, x + 14);
  const top = y + r.height + 20 > window.innerHeight ? y - r.height - 12 : y + 14;
  tip.style.left = `${Math.max(8, left)}px`;
  tip.style.top = `${Math.max(8, top)}px`;
}
export function hideTip(): void {
  if (tip) tip.style.display = 'none';
}

// --------------------------------------------------------------- toasts

export function toast(msg: string, kind: 'info' | 'error' = 'info'): void {
  const host = document.getElementById('toasts')!;
  const t = h('div', { class: `toast ${kind}`, role: 'status' }, msg);
  host.appendChild(t);
  setTimeout(() => t.remove(), kind === 'error' ? 8000 : 3500);
}

// --------------------------------------------------------------- icons (inline SVG, 16px)

const ICONS: Record<string, string> = {
  dashboard: 'M2 2h5v6H2zM9 2h5v3H9zM9 7h5v7H9zM2 10h5v4H2z',
  packets: 'M2 3h12v2H2zM2 7h12v2H2zM2 11h12v2H2z',
  flows: 'M3 2v12M13 2v12M3 5l10 2M13 9L3 11',
  alerts: 'M8 1.5l6.5 12h-13zM8 6v3.5M8 11.2v.6',
  health: 'M1 8h3l2-5 3 10 2-5h4',
  play: 'M4 2.5l9 5.5-9 5.5z',
  stop: 'M3.5 3.5h9v9h-9z',
  open: 'M1.5 4V13h12l1.5-6H4L2.5 13M1.5 4h4l1.5 1.5h6V7',
  save: 'M2.5 2.5h9l2 2v9h-11zM5 2.5v3.5h5V2.5M5 13.5v-4h6v4',
  demo: 'M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM6.5 5.5l4 2.5-4 2.5z',
  clear: 'M3 4h10M6 4V2.5h4V4M4.5 4l.7 9.5h5.6l.7-9.5',
  refresh: 'M13 3v3.5H9.5M13 6.5A5.5 5.5 0 102.6 9',
  csv: 'M3 1.5h7l3 3v10H3zM10 1.5v3h3M5 8h6M5 10.5h6M5 13h4',
  theme: 'M8 1.5a6.5 6.5 0 100 13zM8 1.5a6.5 6.5 0 010 13',
  check: 'M3 8.5l3 3 7-7',
  info: 'M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM8 7v4.5M8 4.6v.6',
  warn: 'M8 1.5l6.5 12h-13zM8 6v3.5M8 11.2v.6',
  serious: 'M5.3 1.5h5.4l3.8 3.8v5.4l-3.8 3.8H5.3l-3.8-3.8V5.3zM8 4.5v4.5M8 11v.6',
  critical: 'M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM5.5 5.5l5 5M10.5 5.5l-5 5',
  shield: 'M8 1.5l5.5 2v4c0 3.5-2.4 6-5.5 7-3.1-1-5.5-3.5-5.5-7v-4z',
  gauge: 'M2 11a6 6 0 1112 0M8 11l3-4',
  link: 'M6.5 9.5l3-3M7 4.5l1.3-1.3a2.5 2.5 0 013.5 3.5L10.5 8M9 11.5l-1.3 1.3a2.5 2.5 0 01-3.5-3.5L5.5 8',
  filter: 'M1.5 2.5h13l-5 6v5l-3-1.5v-3.5z',
  close: 'M4 4l8 8M12 4l-8 8',
  help: 'M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM6 6a2 2 0 113 1.7c-.6.4-1 .8-1 1.6M8 11.2v.6',
  database: 'M3 3.5c0-1.1 2.2-2 5-2s5 .9 5 2v9c0 1.1-2.2 2-5 2s-5-.9-5-2zM3 3.5c0 1.1 2.2 2 5 2s5-.9 5-2M3 8c0 1.1 2.2 2 5 2s5-.9 5-2',
  eye: 'M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8 12.1 12.5 8 12.5 1.5 8 1.5 8zM8 6a2 2 0 100 4 2 2 0 000-4z',
  wifi: 'M1.5 6.2a9.5 9.5 0 0113 0M3.8 8.7a6.3 6.3 0 018.4 0M6 11.1a3.1 3.1 0 014 0M8 13.4v.1',
  ethernet: 'M2.5 3.5h11v7h-11zM5 10.5v2.5M8 10.5v2.5M11 10.5v2.5M5 6.5h6',
  router: 'M1.5 9.5h13v4h-13zM4 11.5h.1M6.5 11.5h.1M11.5 9.5V5.5M9.3 4a3 3 0 014.4 0M8 2.5a5 5 0 017 0',
};

export function icon(name: string, cls = ''): SVGSVGElement {
  const svg = s('svg', { viewBox: '0 0 16 16', width: 16, height: 16, class: `icon ${cls}`, 'aria-hidden': 'true' });
  svg.append(s('path', { d: ICONS[name] ?? ICONS.info, fill: 'none', stroke: 'currentColor', 'stroke-width': 1.5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));
  return svg;
}

export type StatusKind = 'good' | 'warning' | 'serious' | 'critical' | 'info';

/** Severity/status chip: always icon + label, never color alone. */
export function statusChip(kind: StatusKind, label: string): HTMLElement {
  const ic = kind === 'good' ? 'check' : kind === 'warning' ? 'warn' : kind === 'serious' ? 'serious' : kind === 'critical' ? 'critical' : 'info';
  return h('span', { class: `chip status-${kind}` }, icon(ic), label);
}

export function severityKind(sev: 'info' | 'low' | 'medium' | 'high'): StatusKind {
  return sev === 'high' ? 'critical' : sev === 'medium' ? 'serious' : sev === 'low' ? 'warning' : 'info';
}

export const SEVERITY_LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' } as const;
