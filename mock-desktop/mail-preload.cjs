const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('mockMail', (action, payload) => ipcRenderer.invoke('mock:mail', action, payload));
