const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('spaceLauncher', {
  action: (action, profile, values) => ipcRenderer.invoke('spaces:action', action, profile, values)
});
