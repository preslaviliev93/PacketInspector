// Simple / Expert mode.
//
// Expert (the default) shows everything: packets, protocols, capture filters,
// evidence and sequence diagrams. Simple hides packet-level detail and uses
// everyday wording, for people who just want to know what is going on.

import type { Severity } from '../shared/types';

export type Mode = 'simple' | 'expert';

const KEY = 'mode';
let mode: Mode = load();
const listeners: ((m: Mode) => void)[] = [];

function load(): Mode {
  try {
    return localStorage.getItem(KEY) === 'simple' ? 'simple' : 'expert';
  } catch {
    return 'expert';
  }
}

export function getMode(): Mode {
  return mode;
}

export function isSimple(): boolean {
  return mode === 'simple';
}

export function setMode(m: Mode): void {
  if (m === mode) return;
  mode = m;
  document.body.dataset.mode = m;
  try { localStorage.setItem(KEY, m); } catch { /* storage unavailable */ }
  for (const l of listeners) l(m);
}

export function onModeChange(l: (m: Mode) => void): void {
  listeners.push(l);
}

/** Pick wording for the current mode. */
export function t(expert: string, simple: string): string {
  return mode === 'simple' ? simple : expert;
}

const SIMPLE_SEVERITY: Record<Severity, string> = { high: 'Needs attention', medium: 'Worth a look', low: 'Minor', info: 'FYI' };
const EXPERT_SEVERITY: Record<Severity, string> = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

export function severityLabel(s: Severity): string {
  return (mode === 'simple' ? SIMPLE_SEVERITY : EXPERT_SEVERITY)[s];
}

document.body.dataset.mode = mode;
