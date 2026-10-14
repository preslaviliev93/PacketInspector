import type { CaptureToolInfo, EngineUpdate } from '../shared/types';
import { $, h, clear, icon, toast, fmtBytes, fmtDuration } from './dom';
import { store } from './store';
import type { Ctx, View, ViewName } from './ctx';
import { DashboardView } from './views/dashboard';
import { PacketsView } from './views/packets';
import { FlowsView } from './views/flows';
import { AlertsView } from './views/alerts';
import { HealthView } from './views/health';
import { StartScreen } from './views/start';
import { DatabasesView } from './views/databases';
import { WatchView } from './views/watch';
import { getMode, isSimple, onModeChange, setMode, type Mode } from './mode';

const api = window.pi;
let current: ViewName = 'dashboard';
let tool: CaptureToolInfo | null = null;

// ------------------------------------------------------------------ theme

function initTheme(): void {
  let saved: string | null = null;
  try { saved = localStorage.getItem('theme'); } catch { /* storage unavailable */ }
  if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
  $('#btn-theme').append(icon('theme'));
  $('#btn-theme').onclick = () => {
    const isDark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === 'dark'
      : matchMedia('(prefers-color-scheme: dark)').matches;
    const next = isDark ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('theme', next); } catch { /* ignore */ }
    views[current].show();
  };
}

// ------------------------------------------------------------------ navigation

const ctx: Ctx = {
  go,
  showPackets(filter, selectId) {
    // Packets are an Expert view. If something asks for them in Simple mode, switch and say so.
    if (isSimple()) {
      setMode('expert');
      toast('Switched to Expert mode to show the individual packets.');
    }
    go('packets');
    packets.setFilter(filter, selectId);
  },
  showFlow(id) {
    go('flows');
    flows.select(id);
  },
  showAlerts(search) {
    alerts.setSearch(search ?? '');
    go('alerts');
  },
  showConnections(search) {
    go('flows');
    flows.setSearch(search);
  },
  addWatch(kind, value, label) {
    watch.add(kind, value, label ?? '', 'medium');
  },
};

const ifaceSel = $('#iface') as HTMLSelectElement;
const capFilter = $('#capfilter') as HTMLInputElement;
const btnStart = $('#btn-start') as HTMLButtonElement;
const btnStop = $('#btn-stop') as HTMLButtonElement;

// Shown on the Overview tab whenever nothing is loaded: pick what to capture.
const start = new StartScreen({
  capture: (id, filter) => {
    ifaceSel.value = id;
    capFilter.value = filter;
    startCapture();
  },
  importFile: () => openFile(),
  demo: () => startDemo(),
  recheck: () => loadInterfaces(),
}, capFilter);

const dashboard = new DashboardView($('#view-dashboard'), ctx, start.el);
const packets = new PacketsView($('#view-packets'), ctx);
const flows = new FlowsView($('#view-flows'), ctx);
const alerts = new AlertsView($('#view-alerts'), ctx);
const health = new HealthView($('#view-health'), ctx);
const databases = new DatabasesView($('#view-databases'), ctx);
const watch = new WatchView($('#view-watch'), ctx);
const views: Record<ViewName, View> = { dashboard, packets, flows, alerts, health, databases, watch };

function go(v: ViewName): void {
  current = v;
  document.querySelectorAll<HTMLElement>('.sidenav button').forEach((b) => b.classList.toggle('active', b.dataset.view === v));
  document.querySelectorAll<HTMLElement>('.view').forEach((el) => el.classList.toggle('active', el.id === `view-${v}`));
  views[v].show();
}

document.querySelectorAll<HTMLElement>('.sidenav button').forEach((b) => {
  b.onclick = () => go(b.dataset.view as ViewName);
});

// ------------------------------------------------------------------ simple / expert mode

const modeButtons = [...document.querySelectorAll<HTMLButtonElement>('.mode-switch button')];
function applyMode(m: Mode): void {
  modeButtons.forEach((b) => {
    b.classList.toggle('on', b.dataset.mode === m);
    b.setAttribute('aria-pressed', String(b.dataset.mode === m));
  });
  if (m === 'simple' && ['packets', 'databases', 'watch'].includes(current)) go('dashboard');
  else views[current].show();
}
modeButtons.forEach((b) => { b.onclick = () => setMode(b.dataset.mode as Mode); });
onModeChange(applyMode);
document.querySelectorAll<HTMLElement>('.sidenav .ic').forEach((el) => el.replaceWith(icon(el.dataset.icon!)));
window.addEventListener('keydown', (e) => {
  if (!(e.ctrlKey || e.metaKey)) return;
  const map: Record<string, ViewName> = { '1': 'dashboard', '2': 'packets', '3': 'flows', '4': 'alerts', '5': 'health', '6': 'databases', '7': 'watch' };
  const expertOnly: ViewName[] = ['packets', 'databases', 'watch'];
  if (map[e.key] && !(expertOnly.includes(map[e.key]) && isSimple())) { e.preventDefault(); go(map[e.key]); }
  if (e.key === 'f' && !isSimple()) { e.preventDefault(); if (current !== 'packets') go('packets'); (document.querySelector('#view-packets .fb-search') as HTMLInputElement).focus(); }
});

// ------------------------------------------------------------------ toolbar

btnStart.append(icon('play'), 'Start');
btnStop.append(icon('stop'), 'Stop');
$('#btn-open').append(icon('open'), 'Import');
$('#btn-demo').append(icon('demo'), 'Demo');
$('#btn-save').append(icon('save'), 'Save');
$('#btn-export').append(icon('csv'), 'Export');
$('#btn-clear').append(icon('clear'));
$('#btn-refresh').append(icon('refresh'));

async function loadInterfaces(): Promise<void> {
  const previous = ifaceSel.value;
  start.setLoading();
  tool = await api.getToolInfo();
  const list = await api.listInterfaces();
  start.setData(tool, list);
  clear(ifaceSel);
  const local = h('optgroup', { label: 'This computer' });
  if (!list.length) local.append(h('option', { value: '', disabled: true }, 'No network adapters found'));
  for (const i of list) {
    const addr = i.addresses?.find((a) => a.includes('.')) ?? i.addresses?.[0];
    const ok = i.available !== false;
    const why = ok ? '' : !tool.path ? ' (needs capture tools)' : ' (no IPv4 address)';
    local.append(h('option', { value: i.id, title: i.id, disabled: !ok }, `${i.name}${addr ? ` - ${addr}` : ''}${why}`));
  }
  const remote = h('optgroup', { label: 'Remote' },
    h('option', { value: 'tzsp:37008', title: 'Receive packets streamed by a MikroTik router (/tool sniffer streaming) on UDP 37008' }, 'MikroTik sniffer stream (TZSP, UDP 37008)'));
  ifaceSel.append(local, remote);
  const firstUsable = [...ifaceSel.options].find((o) => !o.disabled);
  ifaceSel.value = [...ifaceSel.options].some((o) => o.value === previous && !o.disabled) ? previous : firstUsable?.value ?? '';
  updateButtons();
  dashboard.show();
}

async function startCapture(): Promise<void> {
  if (!ifaceSel.value) { toast('Pick a network interface first', 'error'); return; }
  hideBanner();
  try {
    await api.startCapture({ interfaceId: ifaceSel.value, captureFilter: capFilter.value });
  } catch (e) {
    showBanner(cleanError(e), true);
  }
}

async function startDemo(): Promise<void> {
  hideBanner();
  await api.startDemo();
  toast('Demo started: a simulated home network with a few incidents mixed in. Watch the Alerts tab.');
}

async function openFile(): Promise<void> {
  hideBanner();
  try {
    await api.openFile();
  } catch (e) {
    showBanner(cleanError(e), true);
  }
}

function cleanError(e: unknown): string {
  return String((e as Error).message ?? e).replace(/^Error invoking remote method '[^']+': (Error: )?/, '');
}

btnStart.onclick = () => startCapture();
ifaceSel.onchange = () => updateButtons();

// Drag a capture file anywhere onto the window to import it.
window.addEventListener('dragover', (e) => { e.preventDefault(); document.body.classList.add('dropping'); });
window.addEventListener('dragleave', (e) => { if (!e.relatedTarget) document.body.classList.remove('dropping'); });
window.addEventListener('drop', async (e) => {
  e.preventDefault();
  document.body.classList.remove('dropping');
  const file = e.dataTransfer?.files[0];
  if (!file) return;
  try {
    await api.importFile(file);
  } catch (err) {
    showBanner(cleanError(err), true);
  }
});
btnStop.onclick = () => api.stopCapture();
$('#btn-open').onclick = () => openFile();
$('#btn-demo').onclick = () => startDemo();
$('#btn-refresh').onclick = () => loadInterfaces();
$('#btn-clear').onclick = () => api.clear();
$('#btn-save').onclick = async () => {
  const p = await api.saveCapture();
  if (p) toast(`Saved to ${p}`);
};
const menu = $('#export-menu');
$('#btn-export').onclick = (e) => { e.stopPropagation(); menu.hidden = !menu.hidden; };
document.addEventListener('click', () => { menu.hidden = true; });
menu.querySelectorAll<HTMLButtonElement>('button').forEach((b) => {
  b.onclick = async () => {
    menu.hidden = true;
    const p = await api.exportCsv(b.dataset.csv as 'flows' | 'alerts' | 'packets');
    if (p) toast(`Exported to ${p}`);
  };
});

function updateButtons(): void {
  const busy = store.status.state === 'capturing' || store.status.state === 'reading';
  // MikroTik streams are filtered on the router; built-in Windows capture has no BPF engine.
  const remote = ifaceSel.value.startsWith('tzsp:') || ifaceSel.value.startsWith('win:');
  btnStart.disabled = busy || !ifaceSel.value;
  btnStop.disabled = store.status.state !== 'capturing';
  ifaceSel.disabled = busy;
  // Filtering for a MikroTik stream happens on the router (/tool sniffer filter-*).
  capFilter.disabled = busy || remote || !tool?.path;
  capFilter.title = ifaceSel.value.startsWith('tzsp:')
    ? 'For a MikroTik stream, set filters on the router: /tool sniffer set filter-ip-address=... filter-port=...'
    : ifaceSel.value.startsWith('win:')
      ? 'Capture filters need Npcap. With the built-in Windows capture, use the display filter on the Packets tab instead.'
      : 'BPF capture filter, applied by the capture driver before packets reach the app';
  ($('#btn-save') as HTMLButtonElement).disabled = !store.packets.length;
  ($('#btn-export') as HTMLButtonElement).disabled = !store.packets.length;
}

// ------------------------------------------------------------------ banner & status bar

function showBanner(msg: string, error: boolean, action?: { label: string; run: () => void }): void {
  const b = $('#banner');
  clear(b);
  b.className = `banner${error ? ' error' : ''}`;
  b.append(icon(error ? 'critical' : 'info'), h('div', { class: 'grow' }, msg),
    ...(action ? [h('button', { class: 'small primary', onclick: action.run }, action.label)] : []),
    h('button', { class: 'small icon-btn', 'aria-label': 'Dismiss', onclick: hideBanner }, icon('close')));
  b.hidden = false;
}

async function allowFirewall(): Promise<void> {
  toast('Windows will ask for permission to add the firewall rule.');
  const r = await api.allowStreamFirewall();
  if (r.ok) {
    hideBanner();
    toast('Firewall rule added. Packets from the MikroTik can now reach Packet Inspector.');
  } else {
    toast(r.error ?? 'The firewall rule was not added.', 'error');
  }
}
function hideBanner(): void {
  $('#banner').hidden = true;
}

function renderStatus(): void {
  const st = store.status;
  const el = $('#st-state');
  el.className = `st-state ${st.state}`;
  el.textContent = { idle: 'Idle', capturing: 'Capturing', reading: 'Reading file', stopped: 'Stopped', error: 'Error' }[st.state];
  $('#st-source').textContent = st.source;
  const s = store.stats;
  $('#st-packets').textContent = `${store.packets.length.toLocaleString()} packets`;
  $('#st-bytes').textContent = s ? fmtBytes(s.totalBytes) : '';
  $('#st-duration').textContent = s?.startTs && s.lastTs ? fmtDuration(s.lastTs - s.startTs) : '';
  const sev = store.alertsBySeverity();
  const badge = $('#alert-badge');
  const n = sev.high + sev.medium + sev.low;
  badge.hidden = n === 0;
  badge.textContent = String(n);
  badge.classList.toggle('quiet', sev.high === 0 && sev.medium === 0);
}

// ------------------------------------------------------------------ updates

store.subscribe((u: EngineUpdate) => {
  if (u.status) {
    if (u.status.state === 'error' && u.status.message) showBanner(u.status.message, true);
    else if (u.status.message) toast(u.status.message);
    if (u.status.notice) {
      showBanner(u.status.notice.text, false, u.status.notice.action === 'allow-firewall' ? { label: 'Allow through firewall', run: () => allowFirewall() } : undefined);
    }
  }
  if (u.toast) toast(u.toast);
  views[current].update(u);
  // Keep the alert badge / buttons / status live regardless of the visible view.
  renderStatus();
  updateButtons();
});

api.onUpdate((u) => store.apply(u));

initTheme();
applyMode(getMode());
api.getVersion().then((v) => { $('#st-version').textContent = `v${v}`; });
loadInterfaces();
api.getFullState().then((s) => {
  store.apply({ ...s, status: s.status });
  go('dashboard');
});
