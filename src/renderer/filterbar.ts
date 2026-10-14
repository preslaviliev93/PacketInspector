// A point-and-click filter bar for the packet list.
//
// Active filters are chips in plain words ("Host demo-laptop", "Not port 443").
// "+ Add filter" walks through what to filter on and offers values taken from
// the capture itself. Underneath it still produces the same filter text as the
// typed syntax, so links from other views ("Show evidence", "flow:12") arrive
// as readable chips, and power users can type "port:443" and press Enter.

import { h, clear, icon } from './dom';
import { parseCidr } from '../shared/watch';
import { store } from './store';

export interface Chip { key: string; value: string; neg: boolean }

const KEYS = new Set(['host', 'ip', 'src', 'dst', 'net', 'network', 'subnet', 'port', 'proto', 'protocol', 'db', 'database', 'flow', 'conv', 'id', 'tag', 'is']);

const TAG_WORDS: Record<string, string> = {
  retransmission: 'Retransmissions', rst: 'Resets', 'dup-ack': 'Duplicate ACKs', 'zero-window': 'Zero window',
  'dns-error': 'Failed lookups', alert: 'Alert evidence', credentials: 'Exposed passwords', watch: 'Watchlist matches',
  mikrotik: 'From MikroTik stream', syn: 'Connection requests', database: 'Database traffic', malformed: 'Malformed packets',
};

const DB_WORDS: Record<string, string> = { mysql: 'MySQL', mariadb: 'MySQL', postgresql: 'PostgreSQL', postgres: 'PostgreSQL', pg: 'PostgreSQL', mssql: 'SQL Server', sqlserver: 'SQL Server', mongodb: 'MongoDB', mongo: 'MongoDB', redis: 'Redis', oracle: 'Oracle' };

const PORT_NAMES: Record<number, string> = {
  20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
  143: 'IMAP', 161: 'SNMP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1433: 'SQL Server', 1521: 'Oracle',
  1900: 'SSDP', 3306: 'MySQL', 3389: 'Remote Desktop', 5353: 'mDNS', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP alt', 8443: 'HTTPS alt',
  27017: 'MongoDB', 37008: 'MikroTik stream',
};

/** Human wording for a chip. */
export function chipLabel(c: Chip): string {
  const k = c.key, v = c.value;
  let s: string;
  const name = (ip: string) => { const n = store.nameOf(ip); return n ? `${n} (${ip})` : ip; };
  switch (k) {
    case 'host': case 'ip': s = `Host ${name(v)}`; break;
    case 'src': s = `From ${name(v)}`; break;
    case 'dst': s = `To ${name(v)}`; break;
    case 'net': case 'network': case 'subnet': s = `Network ${v}`; break;
    case 'port': { const n = PORT_NAMES[Number(v)]; s = `Port ${v}${n ? ` (${n})` : ''}`; break; }
    case 'proto': case 'protocol': s = `Protocol ${v.split(',').map((x) => x.toUpperCase()).join(', ')}`; break;
    case 'db': case 'database': s = v ? `Database ${DB_WORDS[v.toLowerCase()] ?? v}` : 'Any database'; break;
    case 'flow': case 'conv': s = `Connection #${v}`; break;
    case 'id': { const n = v.split(',').filter(Boolean).length; s = `${n} selected packet${n === 1 ? '' : 's'}`; break; }
    case 'tag': s = TAG_WORDS[v] ?? `Marked ${v}`; break;
    case 'is': s = v === 'problem' ? 'Problems only' : v === 'db' || v === 'database' ? 'Any database' : TAG_WORDS[v] ?? v; break;
    default: s = `${k}: ${v}`;
  }
  return c.neg ? `Not ${s.charAt(0).toLowerCase()}${s.slice(1)}` : s;
}

function tokenize(q: string): string[] {
  const out: string[] = [];
  const re = /(-?\w+:"[^"]*"|-?"[^"]*"|\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(q))) out.push(m[1].replace(/"/g, ''));
  return out;
}

/** Split filter text into chips (known key:value terms) and free search words. */
export function parseQuery(q: string): { chips: Chip[]; text: string } {
  const chips: Chip[] = [];
  const words: string[] = [];
  for (const tok of tokenize(q)) {
    const neg = tok.startsWith('-') && tok.length > 1;
    const t = neg ? tok.slice(1) : tok;
    const i = t.indexOf(':');
    const key = i > 0 ? t.slice(0, i).toLowerCase() : '';
    if (key && KEYS.has(key)) chips.push({ key, value: t.slice(i + 1), neg });
    else words.push(tok);
  }
  return { chips, text: words.join(' ') };
}

export function composeQuery(chips: Chip[], text: string): string {
  const parts = chips.map((c) => `${c.neg ? '-' : ''}${c.key}:${/\s/.test(c.value) ? `"${c.value}"` : c.value}`);
  if (text.trim()) parts.push(text.trim());
  return parts.join(' ');
}

// ------------------------------------------------------------------ quick toggles

interface Quick { label: string; tip: string; chip: Chip }
const QUICK: Quick[] = [
  { label: 'Problems', tip: 'Retransmissions, resets, zero window, failed lookups, malformed packets', chip: { key: 'is', value: 'problem', neg: false } },
  { label: 'Alerts', tip: 'Packets that triggered an alert', chip: { key: 'tag', value: 'alert', neg: false } },
  { label: 'DNS', tip: 'Name lookups', chip: { key: 'proto', value: 'dns', neg: false } },
  { label: 'Web', tip: 'HTTP, HTTPS (TLS) and QUIC', chip: { key: 'proto', value: 'http,tls,quic', neg: false } },
  { label: 'DB', tip: 'Database sessions: MySQL, PostgreSQL, SQL Server, MongoDB, Redis, Oracle', chip: { key: 'db', value: '', neg: false } },
];

const same = (a: Chip, b: Chip) => a.key === b.key && a.value.toLowerCase() === b.value.toLowerCase() && a.neg === b.neg;

// ------------------------------------------------------------------ the bar

type Field = 'host' | 'src' | 'dst' | 'net' | 'port' | 'proto' | 'db' | 'tag' | 'flow';
const FIELDS: { key: Field; label: string; hint: string }[] = [
  { key: 'host', label: 'Host or IP address', hint: 'Packets to or from a device or website' },
  { key: 'src', label: 'Sent by', hint: 'Only packets coming from this address' },
  { key: 'dst', label: 'Sent to', hint: 'Only packets going to this address' },
  { key: 'net', label: 'Network', hint: 'A whole range, e.g. 192.168.1.0/24' },
  { key: 'port', label: 'Port or service', hint: 'e.g. 443 for HTTPS, 53 for DNS' },
  { key: 'proto', label: 'Protocol', hint: 'Pick one or more' },
  { key: 'db', label: 'Database', hint: 'Database sessions' },
  { key: 'tag', label: 'Marker', hint: 'Problems, alerts, watchlist matches...' },
  { key: 'flow', label: 'Connection number', hint: 'All packets of one connection' },
];

export class FilterBar {
  readonly el: HTMLElement;
  private chips: Chip[] = [];
  private chipsHost = h('span', { class: 'fb-chips' });
  private search = h('input', { type: 'search', class: 'fb-search', placeholder: 'Search packets', 'aria-label': 'Search packets', spellcheck: 'false' });
  private addBtn = h('button', { class: 'small fb-add', 'aria-haspopup': 'true' }, '+ Add filter');
  private clearBtn = h('button', { class: 'small fb-clear', title: 'Remove all filters' }, 'Clear');
  private quickBtns: { q: Quick; b: HTMLButtonElement }[] = [];
  private pop = h('div', { class: 'fb-pop', role: 'dialog', 'aria-label': 'Add a filter' });
  private searchTimer: number | undefined;

  constructor(private onChange: () => void, extras: HTMLElement[]) {
    const quick = h('span', { class: 'quick' }, ...QUICK.map((q) => {
      const b = h('button', { class: 'small', title: q.tip, 'aria-pressed': 'false' }, q.label);
      b.onclick = () => this.toggle(q.chip);
      this.quickBtns.push({ q, b });
      return b;
    }));
    this.pop.hidden = true;
    this.el = h('div', { class: 'filterbar fb' },
      icon('filter'),
      h('div', { class: 'fb-field' }, this.chipsHost, this.search),
      h('span', { class: 'fb-addwrap' }, this.addBtn, this.pop),
      quick, this.clearBtn, ...extras);

    this.search.addEventListener('input', () => {
      clearTimeout(this.searchTimer);
      this.searchTimer = window.setTimeout(() => this.changed(), 150);
    });
    this.search.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        // "port:443" typed and Enter -> becomes a chip
        const parsed = parseQuery(this.search.value);
        if (parsed.chips.length) {
          for (const c of parsed.chips) this.add(c, false);
          this.search.value = parsed.text;
          this.changed();
        }
      } else if (e.key === 'Backspace' && !this.search.value && this.chips.length) {
        this.chips.pop();
        this.changed();
      }
    });
    this.addBtn.onclick = (e) => { e.stopPropagation(); this.pop.hidden ? this.openPicker() : this.closePicker(); };
    this.clearBtn.onclick = () => { this.chips = []; this.search.value = ''; this.changed(); };
    document.addEventListener('mousedown', (e) => { if (!this.pop.hidden && !this.pop.contains(e.target as Node) && e.target !== this.addBtn) this.closePicker(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !this.pop.hidden) this.closePicker(); });
    this.render();
  }

  /** The filter text the packet engine understands. */
  query(): string {
    return composeQuery(this.chips, this.search.value);
  }

  /** Replace everything with a filter given as text (used by links from other views). */
  setQuery(q: string): void {
    const p = parseQuery(q);
    this.chips = p.chips;
    this.search.value = p.text;
    this.render();
  }

  setError(msg: string | undefined): void {
    this.el.classList.toggle('bad', !!msg);
    this.search.title = msg ?? '';
  }

  focus(): void {
    this.search.focus();
  }

  private changed(): void {
    this.render();
    this.onChange();
  }

  private add(c: Chip, notify = true): void {
    if (!this.chips.some((x) => same(x, c))) this.chips.push(c);
    if (notify) this.changed();
  }

  private toggle(c: Chip): void {
    const i = this.chips.findIndex((x) => same(x, c));
    if (i >= 0) this.chips.splice(i, 1); else this.chips.push(c);
    this.changed();
  }

  private render(): void {
    clear(this.chipsHost);
    this.chips.forEach((c, i) => {
      const chip = h('span', { class: `fb-chip${c.neg ? ' neg' : ''}`, title: c.neg ? 'Click to include instead of exclude' : 'Click to exclude instead of include' },
        h('span', { class: 'fb-chip-label' }, chipLabel(c)),
        h('button', { class: 'fb-x', 'aria-label': `Remove filter ${chipLabel(c)}`, title: 'Remove' }, icon('close')));
      chip.querySelector('.fb-chip-label')!.addEventListener('click', () => { c.neg = !c.neg; this.changed(); });
      chip.querySelector('.fb-x')!.addEventListener('click', () => { this.chips.splice(i, 1); this.changed(); });
      this.chipsHost.appendChild(chip);
    });
    this.search.placeholder = this.chips.length ? 'Search within these' : 'Search packets';
    for (const { q, b } of this.quickBtns) {
      const on = this.chips.some((x) => same(x, q.chip));
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', String(on));
    }
    this.clearBtn.hidden = !this.chips.length && !this.search.value;
  }

  // ------------------------------------------------------------------ "+ Add filter" picker

  private closePicker(): void {
    this.pop.hidden = true;
  }

  private openPicker(): void {
    clear(this.pop);
    this.pop.append(h('div', { class: 'fb-pop-title' }, 'Filter packets by...'));
    const list = h('div', { class: 'fb-fields' });
    for (const f of FIELDS) {
      list.appendChild(h('button', { class: 'fb-field-btn', onclick: () => this.openField(f.key) },
        h('span', { class: 'fb-field-name' }, f.label), h('span', { class: 'muted small' }, f.hint)));
    }
    this.pop.appendChild(list);
    this.pop.hidden = false;
  }

  private openField(field: Field): void {
    clear(this.pop);
    const meta = FIELDS.find((f) => f.key === field)!;
    const exclude = h('input', { type: 'checkbox' });
    const error = h('div', { class: 'form-error' });
    const back = h('button', { class: 'small', onclick: () => this.openPicker() }, 'Back');
    const head = h('div', { class: 'fb-pop-title' }, meta.label);
    let body: HTMLElement;
    let read: () => { value: string } | { error: string };

    if (field === 'proto' || field === 'tag' || field === 'db') {
      // Pick from what is actually in the capture.
      const options = field === 'proto' ? this.protocolOptions() : field === 'db' ? this.dbOptions() : this.markerOptions();
      const multi = field === 'proto';
      const name = `fb-${field}`;
      body = h('div', { class: 'fb-options' }, ...(options.length ? options.map((o, i) => h('label', { class: 'fb-option' },
        h('input', { type: multi ? 'checkbox' : 'radio', name, value: o.value, checked: !multi && i === 0 }),
        h('span', null, o.label), o.count !== undefined ? h('span', { class: 'muted small' }, o.count.toLocaleString()) : null))
        : [h('div', { class: 'muted' }, field === 'db' ? 'No database traffic in this capture yet.' : 'Nothing captured yet.')]));
      read = () => {
        const picked = [...body.querySelectorAll<HTMLInputElement>('input:checked')].map((x) => x.value);
        if (!picked.length) return { error: 'Pick at least one.' };
        return { value: field === 'proto' ? picked.join(',') : picked[0] };
      };
    } else {
      const input = h('input', { type: 'text', class: 'mono', spellcheck: 'false', list: `fb-dl-${field}` });
      const dl = h('datalist', { id: `fb-dl-${field}` });
      const sugg = field === 'port' ? this.portSuggestions() : field === 'flow' ? [] : field === 'net' ? this.networkSuggestions() : this.hostSuggestions();
      for (const s of sugg) dl.appendChild(h('option', { value: s.value }, s.label));
      input.placeholder = field === 'net' ? '192.168.1.0/24' : field === 'port' ? '443' : field === 'flow' ? '12' : 'Address or name, e.g. 192.168.1.10';
      body = h('div', null, input, dl);
      read = () => {
        const v = input.value.trim().split(/\s+/)[0] ?? '';
        if (!v) return { error: 'Enter a value.' };
        if (field === 'port' && !(Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= 65535)) return { error: 'A port is a number from 1 to 65535.' };
        if (field === 'flow' && !/^\d+$/.test(v)) return { error: 'Enter a connection number, e.g. 12.' };
        if (field === 'net' && !parseCidr(v.includes('/') ? v : `${v}/32`)) return { error: 'Enter a network like 192.168.1.0/24.' };
        return { value: v };
      };
      setTimeout(() => input.focus(), 0);
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
    }

    const submit = () => {
      const r = read();
      if ('error' in r) { error.textContent = r.error; return; }
      const chip: Chip = field === 'tag' && r.value === 'is:problem'
        ? { key: 'is', value: 'problem', neg: exclude.checked }
        : { key: field, value: r.value, neg: exclude.checked };
      this.add(chip);
      this.closePicker();
    };
    this.pop.append(head, h('div', { class: 'muted small', style: 'margin-bottom:8px' }, meta.hint), body, error,
      h('label', { class: 'fb-exclude' }, exclude, 'Hide these instead of showing only these'),
      h('div', { class: 'fb-pop-actions' }, back, h('button', { class: 'small primary', onclick: submit }, 'Add filter')));
  }

  private protocolOptions(): { value: string; label: string; count?: number }[] {
    return (store.stats?.protocols ?? []).slice().sort((a, b) => b.packets - a.packets).map((p) => ({ value: p.key.toLowerCase(), label: p.key, count: p.packets }));
  }

  private dbOptions(): { value: string; label: string; count?: number }[] {
    const counts = new Map<string, number>();
    for (const f of store.flows.values()) if (f.db) counts.set(f.db.system, (counts.get(f.db.system) ?? 0) + 1);
    if (!counts.size) return [];
    return [{ value: '', label: 'Any database', count: [...counts.values()].reduce((a, b) => a + b, 0) },
      ...[...counts.entries()].map(([sys, n]) => ({ value: sys.toLowerCase(), label: DB_WORDS[sys.toLowerCase()] ?? sys, count: n }))];
  }

  private markerOptions(): { value: string; label: string; count?: number }[] {
    const counts = new Map<string, number>();
    for (const p of store.packets) for (const t of p.tags) counts.set(t, (counts.get(t) ?? 0) + 1);
    const opts: { value: string; label: string; count?: number }[] = [];
    const problems = store.packets.filter((p) => p.tags.some((t) => ['retransmission', 'rst', 'dup-ack', 'zero-window', 'malformed', 'dns-error'].includes(t))).length;
    if (problems) opts.push({ value: 'is:problem', label: 'Any problem', count: problems });
    for (const [t, label] of Object.entries(TAG_WORDS)) if (counts.get(t)) opts.push({ value: t, label, count: counts.get(t) });
    return opts;
  }

  private hostSuggestions(): { value: string; label: string }[] {
    const seen = new Map<string, number>();
    for (const t of store.stats?.topTalkers ?? []) seen.set(t.key, t.bytes);
    for (const f of store.flows.values()) {
      seen.set(f.a, (seen.get(f.a) ?? 0) + f.bytesAB + f.bytesBA);
      seen.set(f.b, (seen.get(f.b) ?? 0) + f.bytesAB + f.bytesBA);
    }
    return [...seen.entries()].sort((a, b) => b[1] - a[1]).slice(0, 300).map(([ip]) => ({ value: ip, label: store.nameOf(ip) ?? '' }));
  }

  private portSuggestions(): { value: string; label: string }[] {
    const counts = new Map<number, number>();
    for (const f of store.flows.values()) if (f.bPort !== undefined) counts.set(f.bPort, (counts.get(f.bPort) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40).map(([p, n]) => ({ value: String(p), label: `${PORT_NAMES[p] ?? ''}${PORT_NAMES[p] ? ' - ' : ''}${n} connection${n > 1 ? 's' : ''}` }));
  }

  private networkSuggestions(): { value: string; label: string }[] {
    const nets = new Set<string>();
    for (const f of store.flows.values()) for (const ip of [f.a, f.b]) {
      const m = /^(\d+\.\d+\.\d+)\.\d+$/.exec(ip);
      if (m) nets.add(`${m[1]}.0/24`);
    }
    return [...nets].slice(0, 50).map((n) => ({ value: n, label: '' }));
  }
}
