import { contextBridge, ipcRenderer } from 'electron';
import type { UpdateStatus } from './update-check';

contextBridge.exposeInMainWorld('updatePreview', {
  read: () => ipcRenderer.invoke('update-preview:read'),
  subscribe(listener: (status: UpdateStatus) => void) {
    ipcRenderer.on('update-preview:status', (_event, status: UpdateStatus) => listener(status));
  }
});

window.addEventListener('online', () => {
  void ipcRenderer.invoke('update-preview:online').catch(() => {});
});
