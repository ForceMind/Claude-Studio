import { contextBridge, ipcRenderer } from 'electron';
import type { Bridge, ShellState } from './model';

const bridge: Bridge = {
  read: () => ipcRenderer.invoke('shell:read'),
  detectProxy: () => ipcRenderer.invoke('shell:detect-proxy'),
  send: command => ipcRenderer.invoke('shell:command', command),
  subscribe(listener) {
    const receive = (_event: Electron.IpcRendererEvent, state: ShellState) => listener(state);
    ipcRenderer.on('shell:state', receive);
    return () => { ipcRenderer.removeListener('shell:state', receive); };
  },
  onAddress(listener) {
    const receive = () => listener();
    ipcRenderer.on('shell:address', receive);
    return () => { ipcRenderer.removeListener('shell:address', receive); };
  }
};

contextBridge.exposeInMainWorld('claudeBrowser', bridge);
