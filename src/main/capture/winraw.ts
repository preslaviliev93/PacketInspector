// Built-in Windows capture: no driver, no Wireshark.
//
// Windows lets administrators read all IP traffic of an adapter through a raw
// socket (SIO_RCVALL). We ship a tiny helper (src/native/win-capture.cs) that
// does exactly that. It is started elevated (one UAC prompt per capture) and
// streams pcap back over a loopback TCP connection guarded by a random token.

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { join, sep } from 'node:path';
import { PcapStreamReader, type RawFrame } from './pcap';

const CONNECT_TIMEOUT_MS = 120_000; // the user may take a while to answer the UAC prompt

/** Location of the helper, both in development and inside a packaged app (asar unpacked). */
export function helperPath(): string {
  return join(__dirname, '..', 'helper', 'pi-capture.exe').replace(`app.asar${sep}`, `app.asar.unpacked${sep}`);
}

export function winRawAvailable(): boolean {
  return process.platform === 'win32' && existsSync(helperPath());
}

export interface WinRawOptions {
  /** Local IP addresses of the adapter to capture on. */
  addresses: string[];
  /** Launches the helper; replaceable in tests (default: elevated via UAC). */
  launch?: (exe: string, args: string[]) => Promise<void>;
  exe?: string;
}

/** Start `exe` elevated. Resolves once launched; rejects if the user declines the UAC prompt. */
function launchElevated(exe: string, args: string[]): Promise<void> {
  const q = (s: string) => `'${s.replace(/'/g, "''")}'`;
  const cmd = `Start-Process -FilePath ${q(exe)} -ArgumentList ${q(args.join(' '))} -Verb RunAs -WindowStyle Hidden`;
  return new Promise((resolve, reject) => {
    const ps = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', cmd], { windowsHide: true });
    let err = '';
    ps.stderr.on('data', (c) => { err += c; });
    ps.on('error', reject);
    ps.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(/cancel/i.test(err) ? 'cancelled' : err.trim() || `exit code ${code}`));
    });
  });
}

export class WinRawCapture {
  private server: Server | null = null;
  private conn: Socket | null = null;
  private timer: NodeJS.Timeout | null = null;
  private done = false;

  constructor(private onFrame: (f: RawFrame) => void, private onExit: (error?: string) => void) {}

  start(opts: WinRawOptions): void {
    const token = randomBytes(16).toString('hex');
    const exe = opts.exe ?? helperPath();
    const launch = opts.launch ?? launchElevated;
    const server = createServer({ allowHalfOpen: false });
    this.server = server;
    server.maxConnections = 1;

    server.on('connection', (sock) => {
      if (this.conn) { sock.destroy(); return; }
      this.conn = sock;
      if (this.timer) clearTimeout(this.timer);
      server.close(); // one helper per capture; stop accepting
      let head = Buffer.alloc(0);
      let reader: PcapStreamReader | null = null;
      sock.on('data', (chunk: Buffer) => {
        if (reader) {
          try { reader.push(chunk); } catch (e) { this.finish(`Capture stream was corrupted: ${(e as Error).message}`); }
          return;
        }
        head = Buffer.concat([head, chunk]);
        // Expect two text lines: "PIH1 <token>" then "OK" or "ERR <message>".
        const text = head.toString('latin1');
        const first = text.indexOf('\n');
        const second = first >= 0 ? text.indexOf('\n', first + 1) : -1;
        if (second < 0) {
          if (head.length > 4096) this.finish('Unexpected data from the capture helper.');
          return;
        }
        if (text.slice(0, first) !== `PIH1 ${token}`) { this.finish('The capture helper could not be verified.'); return; }
        const status = text.slice(first + 1, second);
        if (status !== 'OK') {
          this.finish(status.startsWith('ERR ') ? status.slice(4) : 'The capture helper failed to start.');
          return;
        }
        reader = new PcapStreamReader(this.onFrame);
        const rest = head.subarray(Buffer.byteLength(text.slice(0, second + 1), 'latin1'));
        if (rest.length) {
          try { reader.push(rest); } catch (e) { this.finish(`Capture stream was corrupted: ${(e as Error).message}`); }
        }
      });
      sock.on('error', () => { /* reported via close */ });
      sock.on('close', () => this.finish());
    });

    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      this.timer = setTimeout(() => this.finish('The capture helper did not start in time.'), CONNECT_TIMEOUT_MS);
      launch(exe, [String(port), token, opts.addresses.join(',')]).catch((e: Error) => {
        this.finish(e.message === 'cancelled'
          ? 'Capture needs administrator permission on Windows, and the request was declined. Click Start again and choose Yes to allow it.'
          : `Could not start the capture helper: ${e.message}`);
      });
    });
    server.on('error', (e) => this.finish(`Could not start capture: ${e.message}`));
  }

  stop(): void {
    this.finish();
  }

  private finish(error?: string): void {
    if (this.done) return;
    this.done = true;
    if (this.timer) clearTimeout(this.timer);
    // Closing the connection makes the helper exit.
    this.conn?.destroy();
    this.server?.close();
    this.conn = null;
    this.server = null;
    this.onExit(error);
  }
}
