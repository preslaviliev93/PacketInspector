// The screen shown when nothing is loaded: pick an adapter, the MikroTik
// stream, a file, or the demo. If no capture tool is installed, the adapters
// are still listed and the setup steps are shown right here.

import type { CaptureInterface, CaptureToolInfo } from '../../shared/types';
import { h, clear, icon, toast } from '../dom';

export interface StartActions {
  capture(interfaceId: string, filter: string): void;
  importFile(): void;
  demo(): void;
  recheck(): void;
}

const KIND_ICON: Record<string, string> = {
  'Wi-Fi': 'wifi', Ethernet: 'ethernet', VPN: 'shield', Loopback: 'refresh', Virtual: 'dashboard',
  Bluetooth: 'link', 'All interfaces': 'flows', Other: 'ethernet',
};
const SECONDARY = new Set(['Virtual', 'Loopback', 'Bluetooth']);

export class StartScreen {
  readonly el = h('div', { class: 'start' });
  private filter = h('input', { type: 'text', class: 'mono', placeholder: 'optional, e.g. not port 22   or   host 192.168.1.50', spellcheck: 'false', 'aria-label': 'Capture filter' });
  private showAll = false;
  private tool: CaptureToolInfo | null = null;
  private ifaces: CaptureInterface[] = [];
  private loading = true;

  constructor(private actions: StartActions, private filterTwin: HTMLInputElement) {
    // Keep the start screen filter and the toolbar filter in sync.
    this.filter.addEventListener('input', () => { this.filterTwin.value = this.filter.value; });
    this.filterTwin.addEventListener('input', () => { this.filter.value = this.filterTwin.value; });
    this.render();
  }

  setData(tool: CaptureToolInfo, ifaces: CaptureInterface[]): void {
    this.tool = tool;
    this.ifaces = ifaces;
    this.loading = false;
    this.render();
  }

  setLoading(): void {
    this.loading = true;
    this.render();
  }

  private render(): void {
    clear(this.el);
    this.el.append(
      h('h1', null, 'What would you like to look at?'),
      h('p', { class: 'lead' }, 'Pick a network adapter to start capturing, or open a capture you already have.'),
    );
    if (this.loading) {
      this.el.append(h('div', { class: 'muted' }, 'Looking for network adapters...'));
      return;
    }
    const canCapture = !!this.tool?.path;
    const builtIn = this.tool?.backend === 'windows';
    if (!canCapture) this.el.append(this.setupPanel());
    if (builtIn) this.el.append(this.builtInNote());

    // ------------------------------------------------ adapters
    const primary = this.ifaces.filter((i) => !SECONDARY.has(i.kind ?? 'Other'));
    const secondary = this.ifaces.filter((i) => SECONDARY.has(i.kind ?? 'Other'));
    const shown = this.showAll || !primary.length ? this.ifaces : primary;
    const grid = h('div', { class: 'start-grid' }, ...shown.map((i) => this.ifaceCard(i)));
    const head = h('div', { class: 'start-head' },
      h('h2', null, 'This computer'),
      canCapture && !builtIn ? h('label', { class: 'start-filter expert-only' }, h('span', null, 'Capture filter'), this.filter) : null);
    this.el.append(head);
    if (!this.ifaces.length) {
      this.el.append(h('div', { class: 'muted' }, 'No network adapters were found.'));
    } else {
      this.el.append(grid);
      if (secondary.length && primary.length) {
        this.el.append(h('button', { class: 'link more', onclick: () => { this.showAll = !this.showAll; this.render(); } },
          this.showAll ? 'Hide virtual and loopback adapters' : `Show ${secondary.length} more (virtual, loopback, Bluetooth)`));
      }
    }

    // ------------------------------------------------ other sources
    this.el.append(h('h2', null, 'Other sources'));
    this.el.append(h('div', { class: 'start-grid' },
      this.sourceCard('router', 'MikroTik router', 'Receive what the router\'s packet sniffer streams to this computer (TZSP, UDP 37008).',
        'Start listening', () => this.actions.capture('tzsp:37008', ''),
        'On the router: /tool sniffer set streaming-enabled=yes streaming-server=<this computer\'s IP>, then /tool sniffer start'),
      this.sourceCard('open', 'Capture file', 'Open a .pcap, .pcapng or .pcap.gz from tcpdump, Wireshark or a MikroTik. You can also drag a file onto the window.',
        'Import a file', () => this.actions.importFile()),
      this.sourceCard('demo', 'Demo network', 'A simulated home network with a few incidents mixed in. Nothing to install, nothing captured.',
        'Run the demo', () => this.actions.demo()),
    ));
  }

  private ifaceCard(i: CaptureInterface): HTMLElement {
    const ok = i.available !== false;
    const v4 = i.addresses?.filter((a) => a.includes('.')) ?? [];
    const v6 = i.addresses?.filter((a) => a.includes(':')) ?? [];
    const card = h('div', { class: `start-card${ok ? ' clickable' : ' disabled'}`, role: ok ? 'button' : undefined, tabindex: ok ? 0 : undefined, title: i.id },
      h('div', { class: 'start-card-top' },
        h('span', { class: 'start-icon' }, icon(KIND_ICON[i.kind ?? 'Other'] ?? 'ethernet')),
        h('div', { class: 'grow' },
          h('div', { class: 'start-name' }, i.name),
          h('div', { class: 'muted small' }, i.kind ?? 'Adapter', i.mac ? ` - ${i.mac}` : '')),
      ),
      h('div', { class: 'start-addrs mono' },
        v4.length ? v4.join(', ') : h('span', { class: 'muted' }, 'no IPv4 address'),
        v6.length ? h('div', { class: 'muted' }, v6[0] + (v6.length > 1 ? ` +${v6.length - 1}` : '')) : null),
      h('div', { class: 'start-actions' },
        ok ? h('span', { class: 'start-go' }, icon('play'), 'Capture')
          : h('span', { class: 'muted small' }, this.tool?.path ? 'Not connected (no IPv4 address)' : 'Needs the capture tools (see above)')),
    );
    if (ok) {
      const go = () => this.actions.capture(i.id, this.filter.value);
      card.onclick = go;
      card.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } };
    }
    return card;
  }

  private sourceCard(ic: string, title: string, text: string, action: string, run: () => void, hint?: string): HTMLElement {
    const card = h('div', { class: 'start-card clickable', role: 'button', tabindex: 0, title: hint ?? '' },
      h('div', { class: 'start-card-top' },
        h('span', { class: 'start-icon' }, icon(ic)),
        h('div', { class: 'grow' }, h('div', { class: 'start-name' }, title))),
      h('p', { class: 'muted small' }, text),
      h('div', { class: 'start-actions' }, h('span', { class: 'start-go' }, icon('play'), action)));
    card.onclick = run;
    card.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); run(); } };
    return card;
  }

  private builtInNote(): HTMLElement {
    return h('div', { class: 'note' },
      icon('info'),
      h('div', null,
        h('b', null, 'Ready to capture, nothing to install. '),
        'Windows will ask for administrator permission when you start. This built-in mode sees all IP traffic (web, DNS, TLS, ping and so on) but not Ethernet-level frames such as ARP. ',
        'For those, and to skip the permission prompt, you can optionally install the free ',
        h('a', { href: 'https://npcap.com/#download', target: '_blank', rel: 'noopener' }, 'Npcap driver'),
        ' and click ', h('button', { class: 'link', onclick: () => this.actions.recheck() }, 'check again'), '.'));
  }

  private setupPanel(): HTMLElement {
    const win = this.tool?.platform === 'win32';
    const copy = (cmd: string) => h('button', { class: 'small', onclick: () => navigator.clipboard.writeText(cmd).then(() => toast('Copied')) }, 'Copy');
    const cmdRow = (cmd: string) => h('div', { class: 'cmd' }, h('code', null, cmd), copy(cmd));
    const steps = win
      ? h('ol', null,
          h('li', null, 'Download Wireshark from ', h('a', { href: 'https://www.wireshark.org/download.html', target: '_blank', rel: 'noopener' }, 'wireshark.org'), '. It includes the Npcap capture driver.'),
          h('li', null, 'Run the installer. When it asks about Npcap, leave ', h('b', null, 'Install Npcap'), ' ticked.'),
          h('li', null, 'Come back here and click ', h('b', null, 'Check again'), '. Your adapters become clickable.'))
      : h('ol', null,
          h('li', null, 'Install the capture tools (answer ', h('b', null, 'Yes'), ' if asked whether non-superusers may capture):',
            cmdRow('sudo apt install tshark'), h('div', { class: 'muted small' }, 'Fedora: sudo dnf install wireshark-cli')),
          h('li', null, 'Allow your account to capture, then log out and back in:', cmdRow('sudo usermod -aG wireshark $USER')),
          h('li', null, 'Click ', h('b', null, 'Check again'), '.'));
    return h('div', { class: 'setup' },
      h('div', { class: 'setup-head' },
        icon('info'),
        h('div', { class: 'grow' },
          h('h2', null, 'One more step to capture on this computer'),
          h('p', { class: 'muted' }, win
            ? 'Windows needs a small capture driver (Npcap) to see network traffic. Your adapters are listed below and will work once it is installed.'
            : 'Linux needs dumpcap or tcpdump to see network traffic. Your adapters are listed below and will work once one of them is installed.')),
        h('button', { class: 'primary', onclick: () => this.actions.recheck() }, icon('refresh'), 'Check again')),
      steps,
      h('p', { class: 'muted small' }, 'You do not need this for importing files, the MikroTik stream or the demo.'));
  }
}
