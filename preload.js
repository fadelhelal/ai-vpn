'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('aivpn', {
  init: () => ipcRenderer.invoke('app:init'),
  connect: (id) => ipcRenderer.invoke('servers:connect', id),
  disconnect: () => ipcRenderer.invoke('session:disconnect'),
  getState: () => ipcRenderer.invoke('session:state'),
  guardState: () => ipcRenderer.invoke('guard:state'),
  guardCheck: () => ipcRenderer.invoke('guard:check'),
  repinServer: () => ipcRenderer.invoke('guard:repin'),
  refreshIntel: () => ipcRenderer.invoke('intel:refresh'),
  openIntel: (url) => ipcRenderer.invoke('intel:open', url),
  updateSettings: (patch) => ipcRenderer.invoke('settings:set', patch),
  restoreNetwork: () => ipcRenderer.invoke('killswitch:restore'),
  checkForUpdate: () => ipcRenderer.invoke('update:check'),
  pickEngine: () => ipcRenderer.invoke('engine:pick'),
  importProfile: () => ipcRenderer.invoke('profile:import'),
  removeProfile: () => ipcRenderer.invoke('profile:remove'),
  quit: () => ipcRenderer.invoke('app:quit'),
  onState: (callback) => {
    const handler = (_event, state) => callback(state);
    ipcRenderer.on('state', handler);
    return () => ipcRenderer.removeListener('state', handler);
  },
  onGuard: (callback) => {
    const handler = (_event, payload) => callback(payload);
    ipcRenderer.on('guard', handler);
    return () => ipcRenderer.removeListener('guard', handler);
  },
  onGuardFocus: (callback) => {
    const handler = () => callback();
    ipcRenderer.on('guard:focus', handler);
    return () => ipcRenderer.removeListener('guard:focus', handler);
  },
});
