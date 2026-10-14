// Databases (Expert): every database server seen, and every session with
// who logged in, to which database, whether it was encrypted and what ran.

import type { EngineUpdate, FlowSummary } from '../../shared/types';
import { h, clear, fmtTime, icon, statusChip } from '../dom';
import { store } from '../store';
import type { Ctx, View } from '../ctx';

interface ServerRow {
  key: string;
  ip: string;
  port?: number;
  system: string;
  versions: Set<string>;
  clients: Set<string>;
  users: Set<string>;
  databases: Set<string>;
  sessions: FlowSummary[];
  encrypted: number;
  failed: number;
  queries: number;
}

const isPublic = (ip: string) => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80:|fc|fd|::1$)/i.test(ip);

export class DatabasesView implements View {
  private serverFilter: string | null = null;
  private pending = false;

  constructor(private root: HTMLElement, private ctx: Ctx) {}

  show(): void { this.render(); }

  update(u: EngineUpdate): void {
    if (!u.reset && !u.flows.some((f) => f.db)) return;
    if (this.pending) return;
    this.pending = true;
    setTimeout(() => { this.pending = false; if (this.root.classList.contains('active')) this.render(); }, 500);
  }

  private render(): void {
    clear(this.root);
    const sessions = [...store.flows.values()].filter((f) => f.db).sort((a, b) => b.lastTs - a.lastTs);
    const wrap = h('div', { style: 'max-width: 1400px' },
      h('h2', { style: 'margin: 0 0 4px; font-size: 16px' }, 'Databases'),
      h('p', { class: 'muted', style: 'margin: 0 0 14px' }, 'Database servers and sessions seen in the traffic: MySQL/MariaDB, PostgreSQL, SQL Server, MongoDB, Redis and Oracle. MySQL and PostgreSQL are recognised on any port.'));
    this.root.appendChild(wrap);
    if (!sessions.length) {
      wrap.appendChild(h('div', { class: 'empty' }, h('h3', null, 'No database traffic yet'), h('div', null, 'When a client talks to a database, you will see the server, its version, who logged in, to which database, whether it was encrypted and what ran.')));
      return;
    }

    // Group sessions by server.
    const servers = new Map<string, ServerRow>();
    for (const f of sessions) {
      const key = `${f.b}|${f.bPort}|${f.db!.system}`;
      let s = servers.get(key);
      if (!s) servers.set(key, (s = { key, ip: f.b, port: f.bPort, system: f.db!.system, versions: new Set(), clients: new Set(), users: new Set(), databases: new Set(), sessions: [], encrypted: 0, failed: 0, queries: 0 }));
      const d = f.db!;
      if (d.version) s.versions.add(d.version);
      s.clients.add(f.a);
      if (d.user) s.users.add(d.user);
      if (d.database) s.databases.add(d.database);
      s.sessions.push(f);
      if (d.encrypted) s.encrypted++;
      s.failed += d.failedLogins;
      s.queries += d.queries;
    }

    const unencrypted = sessions.filter((f) => !f.db!.encrypted).length;
    const failed = sessions.reduce((n, f) => n + f.db!.failedLogins, 0);
    const tile = (label: string, value: string, hint: string, kind?: 'serious' | 'critical') =>
      h('div', { class: 'tile' }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'hint' }, kind ? statusChip(kind, hint) : hint));
    wrap.appendChild(h('div', { class: 'tiles' },
      tile('Database servers', String(servers.size), [...new Set([...servers.values()].map((s) => s.system))].join(', ')),
      tile('Sessions', String(sessions.length), `${sessions.reduce((n, f) => n + f.db!.queries, 0)} queries seen`),
      tile('Not encrypted', String(unencrypted), unencrypted ? 'logins and queries readable' : 'all sessions encrypted', unencrypted ? 'serious' : undefined),
      tile('Failed logins', String(failed), failed ? 'see Alerts for password guessing' : 'none', failed >= 5 ? 'critical' : undefined)));

    // ------------------------------------------------ servers
    const enc = (s: ServerRow) => s.encrypted === s.sessions.length ? statusChip('good', 'Encrypted') : s.encrypted === 0 ? statusChip('serious', 'Not encrypted') : statusChip('warning', 'Mixed');
    const st = h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, ...['Server', 'System', 'Version', 'Clients', 'Users', 'Databases', 'Encryption', 'Failed logins', 'Queries', 'Exposure', ''].map((x, i) => h('th', { class: [3, 7, 8].includes(i) ? 'num' : '' }, x)))));
    const sb = h('tbody');
    for (const s of servers.values()) {
      const name = store.nameOf(s.ip);
      const publicClient = [...s.clients].some(isPublic);
      const exposure = publicClient && !isPublic(s.ip) ? statusChip('critical', 'Reached from internet') : isPublic(s.ip) ? statusChip('warning', 'On the internet') : statusChip('good', 'Internal');
      const tr = h('tr', { class: `row${this.serverFilter === s.key ? ' sel' : ''}` },
        h('td', { title: s.ip }, `${name ?? s.ip}${s.port !== undefined ? ':' + s.port : ''}`),
        h('td', null, s.system),
        h('td', null, [...s.versions].join(', ') || h('span', { class: 'muted' }, 'unknown')),
        h('td', { class: 'num' }, String(s.clients.size)),
        h('td', { title: [...s.users].join(', ') }, [...s.users].join(', ') || h('span', { class: 'muted' }, '-')),
        h('td', { title: [...s.databases].join(', ') }, [...s.databases].join(', ') || h('span', { class: 'muted' }, '-')),
        h('td', null, enc(s)),
        h('td', { class: 'num' }, String(s.failed)),
        h('td', { class: 'num' }, String(s.queries)),
        h('td', null, exposure),
        h('td', null, h('button', { class: 'small', title: `Add ${s.ip} to the Watchlist`, onclick: (e: Event) => { e.stopPropagation(); this.ctx.addWatch('ip', s.ip, `${s.system} server`); } }, icon('eye'), 'Watch')));
      tr.onclick = () => { this.serverFilter = this.serverFilter === s.key ? null : s.key; this.render(); };
      sb.appendChild(tr);
    }
    st.appendChild(sb);
    wrap.append(h('div', { class: 'card', style: 'padding: 0; overflow: auto' }, st),
      h('p', { class: 'muted small', style: 'margin: 6px 0 18px' }, 'Click a server to list only its sessions below.'));

    // ------------------------------------------------ sessions
    const shown = this.serverFilter ? servers.get(this.serverFilter)?.sessions ?? [] : sessions;
    const head = h('div', { class: 'toolbar-row' }, h('div', { class: 'section-title grow', style: 'margin:0' }, this.serverFilter ? `Sessions on ${this.serverFilter.split('|').slice(0, 2).join(':')}` : 'All sessions'),
      this.serverFilter ? h('button', { class: 'small', onclick: () => { this.serverFilter = null; this.render(); } }, 'Show all') : null);
    const tt = h('table', { class: 'tbl' },
      h('thead', null, h('tr', null, ...['Started', 'Client', 'Server', 'System', 'User', 'Database', 'Login', 'Encrypted', 'Queries', 'Last query or error', ''].map((x, i) => h('th', { class: i === 8 ? 'num' : '' }, x)))));
    const tb = h('tbody');
    for (const f of shown.slice(0, 1000)) {
      const d = f.db!;
      const login = d.login === 'ok' ? statusChip('good', 'OK') : d.login === 'failed' ? statusChip('critical', `Failed${d.failedLogins > 1 ? ` ×${d.failedLogins}` : ''}`) : h('span', { class: 'muted' }, d.encrypted ? 'inside TLS' : 'not seen');
      const last = d.lastError && d.login === 'failed' ? d.lastError : d.lastQuery ?? d.lastError ?? '';
      const tr = h('tr', { class: 'row' },
        h('td', null, fmtTime(f.firstTs)),
        h('td', { title: f.a }, store.nameOf(f.a) ?? f.a),
        h('td', { title: f.b }, `${store.nameOf(f.b) ?? f.b}${f.bPort !== undefined ? ':' + f.bPort : ''}`),
        h('td', null, d.system),
        h('td', null, d.user ?? h('span', { class: 'muted' }, '-')),
        h('td', null, d.database ?? h('span', { class: 'muted' }, '-')),
        h('td', null, login),
        h('td', null, d.encrypted ? statusChip('good', 'Yes') : statusChip('serious', 'No')),
        h('td', { class: 'num' }, String(d.queries)),
        h('td', { class: 'mono', title: last, style: 'max-width: 420px' }, last),
        h('td', null, h('button', { class: 'small', onclick: (e: Event) => { e.stopPropagation(); this.ctx.showPackets(`flow:${f.id}`); } }, 'Packets')));
      tr.onclick = () => this.ctx.showFlow(f.id);
      tb.appendChild(tr);
    }
    tt.appendChild(tb);
    wrap.append(head, h('div', { class: 'card', style: 'padding: 0; overflow: auto' }, tt));
  }
}
