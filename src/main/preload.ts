import { contextBridge, ipcRenderer, webUtils, type IpcRendererEvent } from 'electron';
import type { EngineUpdate, PacketInspectorApi } from '../shared/types';

const api: PacketInspectorApi & { getFullState(): Promise<EngineUpdate> } = {
  getToolInfo: () => ipcRenderer.invoke('tool:info'),
  getVersion: () => ipcRenderer.invoke('app:version'),
  listInterfaces: () => ipcRenderer.invoke('iface:list'),
  startCapture: (opts) => ipcRenderer.invoke('capture:start', opts),
  startDemo: () => ipcRenderer.invoke('capture:demo'),
  stopCapture: () => ipcRenderer.invoke('capture:stop'),
  openFile: () => ipcRenderer.invoke('file:open'),
  importFile: (file) => ipcRenderer.invoke('file:import-path', webUtils.getPathForFile(file)),
  saveCapture: (ids) => ipcRenderer.invoke('file:save', ids),
  exportCsv: (kind) => ipcRenderer.invoke('file:csv', kind),
  clear: () => ipcRenderer.invoke('capture:clear'),
  getPacketDetail: (id) => ipcRenderer.invoke('packet:detail', id),
  getFlowPackets: (id) => ipcRenderer.invoke('flow:packets', id),
  getWatchRules: () => ipcRenderer.invoke('watch:list'),
  allowStreamFirewall: () => ipcRenderer.invoke('firewall:allow'),
  saveWatchRules: (rules) => ipcRenderer.invoke('watch:save', rules),
  getFullState: () => ipcRenderer.invoke('engine:full'),
  onUpdate: (cb) => {
    const h = (_e: IpcRendererEvent, u: EngineUpdate) => cb(u);
    ipcRenderer.on('engine:update', h);
    return () => ipcRenderer.removeListener('engine:update', h);
  },
};

contextBridge.exposeInMainWorld('pi', api);
