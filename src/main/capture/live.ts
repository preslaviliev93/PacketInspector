// Live capture via an external, battle-tested capture binary:
//   - dumpcap (ships with Wireshark; uses Npcap on Windows, libpcap on Linux)
//   - tcpdump (Linux fallback, elevated through pkexec when needed)
// The binary writes pcap/pcapng to stdout, which we parse ourselves. This
// avoids native Node modules, so the app runs unchanged on Windows and Linux.

import { spawn, execFile, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { join } from 'node:path';
import type { CaptureInterface, CaptureToolInfo, InterfaceKind } from '../../shared/types';
import { PcapStreamReader, type RawFrame } from './pcap';
import { helperPath, winRawAvailable } from './winraw';

const isWin = process.platform === 'win32';

function run(cmd: string, args: string[], timeout = 8000): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, windowsHide: true }, (err, stdout, stderr) => {
      const code = err ? (typeof (err as NodeJS.ErrnoException).code === 'number' ? Number((err as NodeJS.ErrnoException).code) : 1) : 0;
      resolve({ stdout: String(stdout), stderr: String(stderr), code });
    });
  });
}

async function which(name: string): Promise<string | null> {
  const r = await run(isWin ? 'where' : 'which', [name], 4000);
  if (r.code !== 0) return null;
  const first = r.stdout.split(/\r?\n/).find((l) => l.trim());
  return first ? first.trim() : null;
}

let cached: CaptureToolInfo | null = null;

export async function findCaptureTool(refresh = false): Promise<CaptureToolInfo> {
  if (cached && !refresh) return cached;
  const candidates: string[] = isWin
    ? [
        join(process.env['ProgramFiles'] ?? 'C:\\Program Files', 'Wireshark', 'dumpcap.exe'),
        join(process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)', 'Wireshark', 'dumpcap.exe'),
      ]
    : ['/usr/bin/dumpcap', '/usr/sbin/dumpcap', '/usr/local/bin/dumpcap'];
  let path = candidates.find((p) => existsSync(p)) ?? (await which('dumpcap'));
  if (path) return (cached = { backend: 'dumpcap', path, help: '', platform: process.platform });

  if (!isWin) {
    path = ['/usr/sbin/tcpdump', '/usr/bin/tcpdump', '/sbin/tcpdump'].find((p) => existsSync(p)) ?? (await which('tcpdump'));
    if (path) return (cached = { backend: 'tcpdump', path, help: '', platform: process.platform });
  }
  if (winRawAvailable()) {
    return (cached = {
      backend: 'windows',
      path: helperPath(),
      platform: process.platform,
      help: 'Using the capture built into Windows: it asks for administrator permission when you start and sees IP traffic (TCP, UDP, DNS, TLS, ICMP...) but not Ethernet-level frames such as ARP. For full capture without the permission prompt, install the free Npcap driver from npcap.com (optional).',
    });
  }
  return (cached = {
    backend: null,
    path: null,
    platform: process.platform,
    help: isWin
      ? 'Live capture needs Npcap + dumpcap. Install Wireshark from wireshark.org (it bundles both; keep "Npcap" checked during setup), then click Refresh. Meanwhile you can open .pcap/.pcapng files or run the demo.'
      : 'Live capture needs dumpcap or tcpdump. Install one with your package manager, e.g. "sudo apt install tshark" (Debian/Ubuntu, answer YES to allow non-root capture) or "sudo dnf install wireshark-cli", then add yourself to the "wireshark" group: "sudo usermod -aG wireshark $USER" and log in again. Meanwhile you can open .pcap/.pcapng files or run the demo.',
  });
}

/** Guess what kind of adapter this is from its name, so the UI can say "Wi-Fi" rather than a GUID. */
export function interfaceKind(...names: (string | undefined)[]): InterfaceKind {
  const n = names.filter(Boolean).join(' ');
  if (/^any/i.test(n)) return 'All interfaces';
  if (/loopback|^lo|npf_loopback/i.test(n)) return 'Loopback';
  if (/bluetooth/i.test(n)) return 'Bluetooth';
  if (/vpn|wireguard|nordlynx|mullvad|proton|tailscale|zerotier|openvpn|tund*|tapd*|wgd+|pppd+/i.test(n)) return 'VPN';
  if (/vethernet|hyper-v|docker|veth|virbr|vmware|virtualbox|vbox|br-|wsl|vmnet|virtual/i.test(n)) return 'Virtual';
  if (/wi-?fi|wlan|wlp|wlx|wireless|802.11/i.test(n)) return 'Wi-Fi';
  if (/ethernet|ethd|enp|eno|ens|enx|emd|local area connection/i.test(n)) return 'Ethernet';
  return 'Other';
}

export async function listInterfaces(): Promise<CaptureInterface[]> {
  const tool = await findCaptureTool();
  const osIfs = networkInterfaces();
  const osInfo = (...names: (string | undefined)[]) => {
    for (const n of names) {
      const list = n ? osIfs[n] : undefined;
      if (list) {
        const mac = list.find((a) => a.mac && a.mac !== '00:00:00:00:00:00')?.mac;
        return { addresses: list.map((a) => a.address), mac };
      }
    }
    return {};
  };
  let out: CaptureInterface[] = [];
  if (tool.backend === 'windows') {
    // Built-in capture binds to the adapter's IPv4 address(es).
    for (const [n, list] of Object.entries(osIfs)) {
      const v4 = (list ?? []).filter((a) => a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.')).map((a) => a.address);
      out.push({ id: `win:${v4.join(',')}`, name: n, ...osInfo(n), kind: interfaceKind(n), available: v4.length > 0 });
    }
  } else if (tool.path) {
    const r = await run(tool.path, ['-D']);
    out = parseInterfaceList(r.stdout, isWin).map((i) => ({
      ...i, ...osInfo(i.description, i.id), kind: interfaceKind(i.name, i.id, i.description), available: true,
    }));
  }
  if (!out.length && tool.backend !== 'windows') {
    // No capture tool (or it listed nothing): still show the machine's adapters so the
    // user can see what is there; they become capturable once the tool is installed.
    // On Linux the OS name is also the capture name, so it stays usable with tcpdump.
    for (const n of Object.keys(osIfs)) {
      out.push({ id: n, name: n, ...osInfo(n), kind: interfaceKind(n), available: !!tool.path && !isWin });
    }
  }
  // Real adapters with an IPv4 address first; loopback and virtual ones last.
  const rank: Record<InterfaceKind, number> = { Ethernet: 0, 'Wi-Fi': 0, VPN: 1, 'All interfaces': 2, Other: 2, Bluetooth: 3, Virtual: 3, Loopback: 4 };
  const score = (i: CaptureInterface) => rank[i.kind ?? 'Other'] * 2 + (i.addresses?.some((x) => x.includes('.')) ? 0 : 1);
  return out.sort((a, b) => score(a) - score(b));
}

/**
 * Parse `dumpcap -D` / `tcpdump -D` output.
 *   dumpcap (Windows): "1. \Device\NPF_{GUID} (Wi-Fi)"
 *   tcpdump (Linux):   "1.eth0 [Up, Running, Connected]" or "2.wlan0 (Wireless) [Up]"
 * On Windows the friendly name in parentheses is the one people recognise.
 */
export function parseInterfaceList(stdout: string, windows: boolean): CaptureInterface[] {
  const out: CaptureInterface[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^\s*\d+\.\s*(\S+)(?:\s+\(([^)]*)\))?/.exec(line);
    if (!m) continue;
    const [, id, desc] = m;
    out.push(windows && desc ? { id, name: desc, description: desc } : { id, name: id, description: desc });
  }
  return out;
}

export class LiveCapture {
  private proc: ChildProcess | null = null;
  private stderr = '';
  private stopping = false;

  constructor(
    private tool: CaptureToolInfo,
    private onFrame: (f: RawFrame) => void,
    private onExit: (error?: string) => void,
  ) {}

  start(interfaceId: string, captureFilter?: string): void {
    const filter = captureFilter?.trim();
    let cmd = this.tool.path!;
    let args: string[];
    if (this.tool.backend === 'dumpcap') {
      args = ['-i', interfaceId, '-w', '-', '-q'];
      if (filter) args.push('-f', filter);
    } else {
      args = ['-i', interfaceId, '-U', '-n', '-w', '-'];
      if (filter) args.push(filter);
      if (!isWin && process.getuid?.() !== 0 && existsSync('/usr/bin/pkexec')) {
        args = [cmd, ...args];
        cmd = '/usr/bin/pkexec';
      }
    }
    const reader = new PcapStreamReader(this.onFrame);
    const proc = spawn(cmd, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    this.proc = proc;
    proc.stdout!.on('data', (chunk: Buffer) => {
      try {
        reader.push(chunk);
      } catch (e) {
        this.stderr += `\n${(e as Error).message}`;
        this.stop();
      }
    });
    proc.stdout!.on('error', () => { /* EPIPE on stop */ });
    proc.stderr!.on('data', (c: Buffer) => { this.stderr = (this.stderr + c.toString()).slice(-4000); });
    proc.on('error', (err) => this.onExit(`Could not start ${cmd}: ${err.message}`));
    proc.on('close', (code) => {
      this.proc = null;
      if (this.stopping || code === 0) return this.onExit();
      this.onExit(explainFailure(this.stderr, code, this.tool));
    });
  }

  stop(): void {
    if (!this.proc) return;
    this.stopping = true;
    // An elevated (pkexec) child cannot be signalled by us; closing its
    // stdout makes it exit on the next write (SIGPIPE).
    this.proc.stdout?.destroy();
    try { this.proc.kill(isWin ? undefined : 'SIGINT'); } catch { /* already gone */ }
  }
}

function explainFailure(stderr: string, code: number | null, tool: CaptureToolInfo): string {
  const s = stderr.trim();
  if (/permission|not permitted|privilege|You don't have permission/i.test(s)) {
    return isWin
      ? `Permission denied by ${tool.backend}. Npcap may be installed in "admin-only" mode - run Packet Inspector as Administrator, or reinstall Npcap without that option.\n\n${s}`
      : `Permission denied by ${tool.backend}. Allow non-root capture with:\n  sudo usermod -aG wireshark $USER   (then log out and in)\nor\n  sudo setcap cap_net_raw,cap_net_admin=eip ${tool.path}\n\n${s}`;
  }
  if (code === 126 || code === 127) return 'Authentication was cancelled, so capture could not start.';
  return `Capture stopped unexpectedly (exit code ${code}).\n${s || 'No error output.'}`;
}
