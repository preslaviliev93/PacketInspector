// Windows Firewall rule for the MikroTik stream (inbound UDP 37008).
//
// On "Public" networks Windows drops unsolicited inbound UDP unless a rule
// allows it, so the router's TZSP stream never reaches the app. The rule is a
// plain port rule, so it works for the installed app and development builds alike.

import { execFile, spawn } from 'node:child_process';
import { TZSP_PORT } from './tzsp';

export const FIREWALL_RULE_NAME = 'Packet Inspector - MikroTik stream (UDP 37008)';

function run(cmd: string, args: string[]): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true, timeout: 15000 }, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, out: `${stdout}${stderr}` });
    });
  });
}

/** True when an enabled inbound rule with our name exists (or we're not on Windows). */
export async function firewallAllowsStream(): Promise<boolean> {
  if (process.platform !== 'win32') return true;
  // Reading rules needs no admin rights.
  const r = await run('netsh', ['advfirewall', 'firewall', 'show', 'rule', `name=${FIREWALL_RULE_NAME}`]);
  return r.code === 0 && /Enabled:\s+Yes/i.test(r.out);
}

/**
 * The script that adds the rule, run in an elevated PowerShell. It is passed
 * base64-encoded (-EncodedCommand), so no quoting can break it: the rule name
 * contains spaces and parentheses, which is what tripped up an earlier version.
 */
export function firewallScript(): string {
  const name = FIREWALL_RULE_NAME.replace(/'/g, "''");
  return [
    `$name = '${name}'`,
    `& netsh.exe advfirewall firewall delete rule "name=$name" | Out-Null`,
    `& netsh.exe advfirewall firewall add rule "name=$name" dir=in action=allow protocol=UDP localport=${TZSP_PORT} profile=any`,
    'exit $LASTEXITCODE',
  ].join('\n');
}

/** PowerShell command (for the non-elevated side) that runs firewallScript() elevated and waits. */
export function elevatedFirewallCommand(): string {
  const encoded = Buffer.from(firewallScript(), 'utf16le').toString('base64');
  return `$p = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-WindowStyle','Hidden','-EncodedCommand','${encoded}' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode`;
}

/** Add the rule. Windows shows one administrator prompt. Resolves to whether the rule exists afterwards. */
export async function allowStreamThroughFirewall(): Promise<{ ok: boolean; error?: string }> {
  if (process.platform !== 'win32') return { ok: true };
  const outer = elevatedFirewallCommand();
  const result = await new Promise<{ code: number; err: string }>((resolve) => {
    const ps = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', outer], { windowsHide: true });
    let err = '';
    ps.stderr.on('data', (c) => { err += c; });
    ps.on('error', (e) => resolve({ code: 1, err: e.message }));
    ps.on('close', (code) => resolve({ code: code ?? 1, err }));
  });
  if (await firewallAllowsStream()) return { ok: true };
  if (/cancel/i.test(result.err)) return { ok: false, error: 'The administrator prompt was declined, so the firewall rule was not added.' };
  return { ok: false, error: `Could not add the firewall rule. ${result.err.trim()}`.trim() };
}
