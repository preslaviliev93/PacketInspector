import { app, BrowserWindow, dialog, ipcMain, shell } from 'electron';
import { readFile, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { CaptureStatus, StartCaptureOptions, WatchRule } from '../shared/types';
import { normalizeRuleValue } from '../shared/watch';
import { Engine } from './engine';
import { findCaptureTool, interfaceKind, listInterfaces, LiveCapture } from './capture/live';
import { DemoSource } from './capture/demo';
import { writePcapng } from './capture/pcap';
import { readCaptureFile } from './capture/file';
import { TzspListener, TZSP_PORT } from './capture/tzsp';
import { WinRawCapture } from './capture/winraw';
import { allowStreamThroughFirewall, firewallAllowsStream } from './capture/firewall';
import { networkInterfaces } from 'node:os';
import { toCsv } from './csv';

const engine = new Engine();
let win: BrowserWindow | null = null;
let live: LiveCapture | null = null;
let demo: DemoSource | null = null;
let tzsp: TzspListener | null = null;
let winraw: WinRawCapture | null = null;
let status: CaptureStatus = { state: 'idle', source: '' };
let flushCount = 0;

function setStatus(s: CaptureStatus): void {
  status = s;
  engine.setStatus(s);
}

function stopSources(): void {
  live?.stop();
  live = null;
  demo?.stop();
  demo = null;
  tzsp?.stop();
  tzsp = null;
  winraw?.stop();
  winraw = null;
}

function createWindow(): void {
  win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1000,
    minHeight: 640,
    title: 'Packet Inspector',
    icon: join(__dirname, '..', 'renderer', 'icon.png'),
    backgroundColor: '#141413',
    autoHideMenuBar: true,
    webPreferences: {
      preload: join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(join(__dirname, '..', 'renderer', 'index.html'));
  // Open external links in the user's browser, never inside the app.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.on('closed', () => { win = null; });
}

// Push batched updates to the UI 4x per second; stats once per second.
setInterval(() => {
  if (!win) return;
  const u = engine.flush(flushCount++ % 4 === 0);
  if (u) win.webContents.send('engine:update', u);
}, 250);

// ------------------------------------------------------------------ watch rules (saved in the user's profile)

const watchFile = () => join(app.getPath('userData'), 'watchlist.json');
let watchRules: WatchRule[] = [];

/** Keep only well-formed rules; values are re-validated so a hand-edited file can't break matching. */
function sanitizeRules(input: unknown): WatchRule[] {
  if (!Array.isArray(input)) return [];
  const out: WatchRule[] = [];
  for (const r of input as Partial<WatchRule>[]) {
    if (!r || !['ip', 'network', 'host', 'port'].includes(r.kind as string) || typeof r.value !== 'string') continue;
    const n = normalizeRuleValue(r.kind!, r.value);
    if ('error' in n) continue;
    out.push({
      id: typeof r.id === 'string' && r.id ? r.id.slice(0, 64) : Math.random().toString(36).slice(2, 10),
      kind: r.kind!,
      value: n.value,
      label: typeof r.label === 'string' && r.label.trim() ? r.label.trim().slice(0, 80) : undefined,
      severity: ['info', 'low', 'medium', 'high'].includes(r.severity as string) ? r.severity! : 'medium',
      enabled: r.enabled !== false,
      created: typeof r.created === 'number' ? r.created : Date.now(),
    });
  }
  return out.slice(0, 500);
}

async function loadWatchRules(): Promise<void> {
  try {
    watchRules = sanitizeRules(JSON.parse(await readFile(watchFile(), 'utf8')));
  } catch {
    watchRules = [];
  }
  engine.setWatchRules(watchRules);
}

ipcMain.handle('firewall:allow', () => allowStreamThroughFirewall());
ipcMain.handle('watch:list', () => watchRules);
ipcMain.handle('watch:save', async (_e, rules: unknown) => {
  watchRules = sanitizeRules(rules);
  engine.setWatchRules(watchRules);
  await writeFile(watchFile(), JSON.stringify(watchRules, null, 2), 'utf8');
  return watchRules;
});

ipcMain.handle('tool:info', () => findCaptureTool(true));
// Baked in at build time from package.json, so it is right however the app is launched.
declare const __APP_VERSION__: string;
ipcMain.handle('app:version', () => __APP_VERSION__);
ipcMain.handle('iface:list', () => listInterfaces());
ipcMain.handle('engine:full', () => ({ ...engine.fullState(), status }));
ipcMain.handle('packet:detail', (_e, id: number) => engine.detail(id));
ipcMain.handle('flow:packets', (_e, id: number) => engine.flowPackets(id));

ipcMain.handle('capture:start', async (_e, opts: StartCaptureOptions) => {
  stopSources();
  if (opts.interfaceId.startsWith('tzsp:')) {
    const port = Number(opts.interfaceId.slice(5)) || TZSP_PORT;
    engine.reset();
    const source = `MikroTik stream (TZSP, UDP ${port})`;
    tzsp = new TzspListener((f) => engine.ingest(f), (err) => {
      tzsp = null;
      setStatus(err ? { state: 'error', source, message: err } : { state: 'stopped', source });
    });
    const listener = tzsp;
    listener.start(port);
    // Addresses the router could stream to: real adapters only (not WSL/Hyper-V/VPN virtual ones).
    const myIps = Object.entries(networkInterfaces())
      .filter(([name]) => ['Ethernet', 'Wi-Fi', 'Other'].includes(interfaceKind(name)))
      .flatMap(([, list]) => list ?? [])
      .filter((a) => a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.'))
      .map((a) => a.address);
    const ipText = myIps.length ? myIps.join(' or ') : "this computer's IP address";
    const blocked = !(await firewallAllowsStream());
    setStatus({
      state: 'capturing', source,
      message: `Listening on UDP ${port}. On the MikroTik: /tool sniffer set streaming-enabled=yes streaming-server=${myIps[0] ?? '<this PC>'}, then /tool sniffer start`,
      notice: blocked ? {
        text: `Windows Firewall will probably block the router's packets: there is no rule allowing incoming UDP ${port}, and on a "Public" network Windows drops it silently. Click "Allow through firewall" to add the rule (Windows asks for permission once).`,
        action: 'allow-firewall',
      } : undefined,
    });
    // If nothing arrives, say what to check instead of leaving an empty screen.
    setTimeout(async () => {
      if (tzsp !== listener || listener.received > 0) return;
      const stillBlocked = !(await firewallAllowsStream());
      setStatus({
        state: 'capturing', source,
        notice: {
          text: [
            `No packets have arrived from the MikroTik in 10 seconds. Things to check:`,
            `1. On the router, the sniffer must be running and streaming to this computer: streaming-server=${ipText}, port ${port} (/tool sniffer print shows running: yes).`,
            stillBlocked ? `2. Windows Firewall: incoming UDP ${port} is not allowed yet. Use "Allow through firewall".` : `2. Windows Firewall: the rule for UDP ${port} is in place.`,
            `3. VPN apps with "kill switch" or "block local network" settings can drop traffic from the router.`,
            `4. If the sniffer has filters set (Filter tab), make sure some traffic actually matches them.`,
          ].join('\n'),
          action: stillBlocked ? 'allow-firewall' : undefined,
        },
      });
    }, 10_000);
    return;
  }
  if (opts.interfaceId.startsWith('win:')) {
    const addresses = opts.interfaceId.slice(4).split(',').filter(Boolean);
    if (!addresses.length) throw new Error('This adapter has no IPv4 address, so there is nothing to capture on it yet. Connect it to a network first.');
    engine.reset();
    const source = `Live: ${addresses.join(', ')} (built-in Windows capture)`;
    const cap = new WinRawCapture((f) => engine.ingest(f), (err) => {
      if (winraw === cap) winraw = null;
      setStatus(err ? { state: 'error', source, message: err } : { state: 'stopped', source });
    });
    winraw = cap;
    cap.start({ addresses });
    setStatus({ state: 'capturing', source, message: 'Windows will ask for administrator permission to read network traffic. Choose Yes to start capturing.' });
    return;
  }
  const tool = await findCaptureTool();
  if (!tool.path) throw new Error(tool.help);
  engine.reset();
  const source = `Live: ${opts.interfaceId}`;
  live = new LiveCapture(tool, (f) => engine.ingest(f), (err) => {
    live = null;
    setStatus(err ? { state: 'error', source, message: err } : { state: 'stopped', source });
  });
  live.start(opts.interfaceId, opts.captureFilter);
  setStatus({ state: 'capturing', source });
});

ipcMain.handle('capture:demo', () => {
  stopSources();
  engine.reset();
  demo = new DemoSource((f) => engine.ingest(f));
  demo.start();
  setStatus({ state: 'capturing', source: 'Demo network (simulated traffic)' });
});

ipcMain.handle('capture:stop', () => {
  const wasDemo = !!demo || !!tzsp || !!winraw;
  stopSources();
  if (wasDemo || status.state === 'capturing') setStatus({ state: 'stopped', source: status.source });
});

ipcMain.handle('capture:clear', () => {
  engine.reset();
  if (status.state !== 'capturing') setStatus({ state: 'idle', source: '' });
});

async function importFile(path: string): Promise<void> {
  stopSources();
  engine.reset();
  const source = `File: ${basename(path)}`;
  setStatus({ state: 'reading', source });
  try {
    await readCaptureFile(path, (f) => engine.ingest(f));
    setStatus({ state: 'stopped', source, message: `Imported ${engine.packetCount.toLocaleString()} packets from ${basename(path)}.` });
  } catch (e) {
    setStatus({ state: 'error', source, message: `Could not read ${basename(path)}: ${(e as Error).message}. Packet Inspector reads pcap and pcapng files (optionally gzipped), as written by tcpdump, Wireshark/dumpcap and the MikroTik sniffer.` });
  }
}

ipcMain.handle('file:open', async () => {
  const r = await dialog.showOpenDialog(win!, {
    title: 'Import capture file',
    filters: [
      { name: 'Packet captures (tcpdump, Wireshark, MikroTik)', extensions: ['pcap', 'pcapng', 'cap', 'dmp', 'gz'] },
      { name: 'All files', extensions: ['*'] },
    ],
    properties: ['openFile'],
  });
  if (r.canceled || !r.filePaths[0]) return false;
  await importFile(r.filePaths[0]);
  return true;
});

ipcMain.handle('file:import-path', async (_e, path: string) => {
  if (typeof path !== 'string' || !path) return false;
  await importFile(path);
  return true;
});

ipcMain.handle('file:save', async (_e, ids?: number[]) => {
  const frames = engine.framesFor(ids);
  if (!frames.length) return null;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const r = await dialog.showSaveDialog(win!, {
    title: ids ? `Save ${frames.length} packets` : 'Save capture',
    defaultPath: `capture-${stamp}.pcapng`,
    filters: [{ name: 'pcapng (Wireshark compatible)', extensions: ['pcapng'] }],
  });
  if (r.canceled || !r.filePath) return null;
  await writeFile(r.filePath, writePcapng(frames));
  return r.filePath;
});

ipcMain.handle('file:csv', async (_e, kind: 'flows' | 'alerts' | 'packets') => {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const r = await dialog.showSaveDialog(win!, {
    title: `Export ${kind} as CSV`,
    defaultPath: `${kind}-${stamp}.csv`,
    filters: [{ name: 'CSV', extensions: ['csv'] }],
  });
  if (r.canceled || !r.filePath) return null;
  await writeFile(r.filePath, toCsv(kind, engine), 'utf8');
  return r.filePath;
});

app.whenReady().then(async () => {
  await loadWatchRules();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => {
  stopSources();
  app.quit();
});
