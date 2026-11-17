'use strict';

const { app, BrowserWindow, ipcMain, Tray, Menu, dialog, nativeImage, shell, Notification } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { SettingsStore } = require('./src/store');
const { VpnSession } = require('./src/session');
const { readProfileFile, profileInfo } = require('./src/profiles');
const { Guard, entersCritical, shouldDisconnectOnCritical, pinKey } = require('./src/guard');
const { engineVerdict, errorFor } = require('./src/enginecheck');
const { Intel } = require('./src/intel');
const { validFeedUrl, checkForUpdate } = require('./src/updater');

const APP_ID = 'org.community.aivpn.desktop';
const captureIndex = process.argv.indexOf('--capture');
const captureMode = captureIndex !== -1;
const captureTab = (process.argv.find((arg) => arg.startsWith('--tab=')) || '').split('=')[1] || '';
const captureSize = (process.argv.find((arg) => arg.startsWith('--size=')) || '').split('=')[1] || '';
const captureConnect = (process.argv.find((arg) => arg.startsWith('--connect=')) || '').split('=')[1] || '';

let win = null;
let tray = null;
let store = null;
let session = null;
let quitting = false;
let trayHinted = false;
let guard = null;
let intel = null;
let guardTimer = null;
let guardBusy = false;
let lastGuardLevel = 'idle';
let enginePickedThisSession = false;

function guardAlertText(report, autoDisconnected = false) {
  const english = store.get('language') === 'en';
  const labels = english
    ? { tunnel: 'tunnel', route: 'routing', dns: 'DNS', ipv6: 'IPv6', firewall: 'kill switch', crypto: 'crypto', cert: 'certificate', engine: 'engine', residual: 'leftovers after disconnect' }
    : { tunnel: 'النفق', route: 'المسار', dns: 'DNS', ipv6: 'IPv6', firewall: 'Kill Switch', crypto: 'التشفير', cert: 'الشهادة', engine: 'المحرّك', residual: 'بقايا ما بعد الفصل' };
  const failed = [
    ...new Set(
      (report.checks || [])
        .filter((check) => check.level === 'critical')
        .map((check) => labels[check.id] || check.id)
    )
  ];
  if (english) {
    return {
      title: 'Connection protection alert',
      body:
        `Critical check failed: ${failed.join(', ')}. Open AI VPN for details.` +
        (autoDisconnected ? ' The connection was disconnected automatically.' : '')
    };
  }
  return {
    title: 'خطر في حماية الاتصال',
    body:
      `فشل فحص حرج: ${failed.join('، ')}. افتح AI VPN لعرض التفاصيل.` +
      (autoDisconnected ? ' تم فصل الاتصال تلقائياً.' : '')
  };
}

function showGuardAlert(report, autoDisconnected = false) {
  if (quitting || captureMode || !report) return;
  const { title, body } = guardAlertText(report, autoDisconnected);
  const open = () => {
    if (!win || win.isDestroyed()) return;
    win.show();
    win.focus();
    win.webContents.send('guard:focus');
  };
  if (tray) {
    try {
      tray.removeAllListeners('balloon-click');
      tray.displayBalloon({ title, content: body, icon: path.join(__dirname, 'assets', 'icon.png') });
      tray.once('balloon-click', open);
      return;
    } catch {
      // fall through to a native toast
    }
  }
  try {
    if (Notification.isSupported()) {
      const note = new Notification({ title, body, icon: path.join(__dirname, 'assets', 'icon.png') });
      note.on('click', open);
      note.show();
    }
  } catch {
    // alerts are best-effort; the in-app banner still shows the report
  }
}

async function runGuard(force = false) {
  if (!guard || !win || win.isDestroyed()) return guard ? guard.last : null;
  const state = session.snapshot();
  if (!force && state.status !== 'CONNECTED') return guard.last;
  if (guardBusy) return guard.last;
  guardBusy = true;
  try {
    const report = await guard.inspect({
      state,
      logFile: session.logFile,
      enginePath: resolveEngine(store.get('enginePath')),
      strict: store.get('killSwitchStrict') !== false
    });
    const transition = entersCritical(lastGuardLevel, report.level);
    const auto = transition && shouldDisconnectOnCritical(report.level, state.status);
    if (transition) showGuardAlert(report, auto);
    lastGuardLevel = report.level;
    if (auto) session.disconnect().catch(() => {});
    updateTray(state);
    if (!win.isDestroyed()) win.webContents.send('guard', { report, intel: intel.cached() });
    return report;
  } finally {
    guardBusy = false;
  }
}

function scheduleGuard() {
  if (guardTimer) clearInterval(guardTimer);
  guardTimer = null;
  if (session.snapshot().status !== 'CONNECTED') {
    runGuard(true).catch(() => {});
    // The after-disconnect audit runs once adapter teardown has had time to finish.
    setTimeout(() => runGuard(true).catch(() => {}), 6000);
    return;
  }
  setTimeout(() => runGuard(true).catch(() => {}), 4000);
  guardTimer = setInterval(() => runGuard(true).catch(() => {}), 15000);
}

async function refreshIntel(force = false) {
  if (!intel) return null;
  const data = await intel.refresh({ force }).catch(() => intel.cached());
  if (win && !win.isDestroyed()) win.webContents.send('guard', { report: guard ? guard.last : null, intel: data });
  return data;
}

function resolveEngine(preferred) {
  const candidates = [
    preferred,
    process.env.OPENVPN_EXE,
    // Bundled OpenVPN (shipped with the app)
    path.join(__dirname, 'resources', 'openvpn', 'openvpn.exe'),
    // System-installed OpenVPN (fallback)
    'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
    'C:\\Program Files (x86)\\OpenVPN\\bin\\openvpn.exe'
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // try next
    }
  }
  return null;
}

function engineInfo() {
  const found = resolveEngine(store.get('enginePath'));
  return { found: Boolean(found), path: found || '', preferred: store.get('enginePath') || '' };
}

async function settingsView() {
  const profile = await store.getSecret('privateProfile');
  return {
    ...(await store.publicView()),
    privateProfileExpiresAt: profile ? profileInfo(profile).expiresAt : 0,
    engine: engineInfo(),
    killSwitchLocked: session ? session.killSwitch.locked() : false,
    version: app.getVersion()
  };
}

function createWindow() {
  win = new BrowserWindow({
    width: 1180,
    height: 880,
    minWidth: 980,
    minHeight: 720,
    show: !captureMode,
    backgroundColor: '#081322',
    autoHideMenuBar: true,
    title: 'AI VPN',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webviewTag: false,
      allowRunningInsecureContent: false,
      backgroundThrottling: false,
      paintWhenInitiallyHidden: true
    }
  });
  // The UI is a single local page. Any attempt to navigate away or open a new
  // window comes from injected or unexpected content, so it is refused here as
  // well as in the CSP.
  win.webContents.on('will-navigate', (event) => event.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-attach-webview', (event) => event.preventDefault());
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.on('close', (event) => {
    if (quitting) return;
    event.preventDefault();
    win.hide();
    if (!trayHinted && tray) {
      trayHinted = true;
      try {
        tray.displayBalloon({
          title: 'AI VPN',
          content: 'التطبيق يعمل في شريط النظام. من أيقونة الصينية يمكنك الفصل أو الخروج.'
        });
      } catch {
        // balloons are optional
      }
    }
  });
  win.on('closed', () => {
    win = null;
  });
}

function createTray() {
  try {
    const image = nativeImage
      .createFromPath(path.join(__dirname, 'assets', 'icon.png'))
      .resize({ width: 16, height: 16 });
    tray = new Tray(image);
    tray.on('click', () => {
      if (!win) return;
      win.show();
      win.focus();
    });
    updateTray(session.snapshot());
  } catch {
    tray = null;
  }
}

function trayText() {
  const ar = store.get('language') !== 'en';
  return ar
    ? {
        disconnected: 'غير متصل',
        connecting: 'جارٍ الاتصال',
        connected: 'متصل',
        disconnecting: 'جارٍ الفصل',
        failed: 'فشل الاتصال',
        show: 'إظهار',
        disconnect: 'فصل',
        quit: 'خروج',
        guardCritical: 'حالة الحماية: خطر',
        guardWarn: 'حالة الحماية: تحذير'
      }
    : {
        disconnected: 'Disconnected',
        connecting: 'Connecting',
        connected: 'Connected',
        disconnecting: 'Disconnecting',
        failed: 'Connection failed',
        show: 'Show',
        disconnect: 'Disconnect',
        quit: 'Quit',
        guardCritical: 'Protection: critical',
        guardWarn: 'Protection: warning'
      };
}

function updateTray(state) {
  if (!tray) return;
  const tr = trayText();
  const labels = {
    DISCONNECTED: tr.disconnected,
    CONNECTING: tr.connecting,
    CONNECTED: tr.connected,
    DISCONNECTING: tr.disconnecting,
    FAILED: tr.failed
  };
  const level = guard && guard.last ? guard.last.level : null;
  const alert = level === 'critical' ? tr.guardCritical : level === 'warn' ? tr.guardWarn : '';
  const status = `AI VPN — ${labels[state.status] || labels.DISCONNECTED}`;
  tray.setToolTip(alert ? `${status} — ${alert}` : status);
  const template = [
    {
      label: tr.show,
      click: () => {
        if (win) {
          win.show();
          win.focus();
        }
      }
    }
  ];
  if (alert) {
    template.push({
      label: alert,
      click: () => {
        if (!win) return;
        win.show();
        win.focus();
        win.webContents.send('guard:focus');
      }
    });
  }
  template.push(
    {
      label: tr.disconnect,
      enabled: state.status === 'CONNECTED' || state.status === 'CONNECTING',
      click: () => session.disconnect()
    },
    { type: 'separator' },
    { label: tr.quit, click: () => app.quit() }
  );
  tray.setContextMenu(Menu.buildFromTemplate(template));
}

function registerIpc() {
  ipcMain.handle('app:init', async () => ({
    settings: await settingsView(),
    state: session.snapshot(),
    guard: guard ? guard.last : null,
    intel: intel ? intel.cached() : null
  }));

  ipcMain.handle('guard:state', () => ({
    report: guard ? guard.last : null,
    intel: intel ? intel.cached() : null
  }));

  ipcMain.handle('guard:check', async () => {
    const report = await runGuard(true);
    return { report, intel: intel ? intel.cached() : null };
  });

  ipcMain.handle('guard:repin', async () => {
    const state = session.snapshot();
    const key = pinKey(state.server);
    const cleared = guard.resetPin(key);
    const report = state.status === 'CONNECTED' ? await runGuard(true) : guard.last;
    return { ok: true, cleared, report };
  });

  ipcMain.handle('intel:refresh', async () => ({ intel: await refreshIntel(true) }));

  ipcMain.handle('intel:open', async (_event, url) => {
    let parsed = null;
    try {
      parsed = new URL(String(url));
    } catch {
      return { ok: false };
    }
    const allowed = ['nvd.nist.gov', 'www.cisa.gov', 'cisa.gov'];
    if (parsed.protocol !== 'https:' || !allowed.includes(parsed.hostname)) return { ok: false };
    await shell.openExternal(parsed.toString());
    return { ok: true };
  });

  ipcMain.handle('servers:connect', async (_event, id) => {
    if (!store.get('disclosureAccepted')) return { needDisclosure: true };
    try {
      if (id !== 'private') return { error: 'PRIVATE_ONLY' };
      const profile = await store.getSecret('privateProfile');
      if (!profile) return { error: 'NO_PRIVATE_PROFILE' };
      const enginePath = resolveEngine(store.get('enginePath'));
      const verifyEngine = async (candidate) => {
        const signature = await guard.signatureOf(candidate, { fresh: true });
        return engineVerdict({
          enginePath: candidate,
          strict: store.get('engineStrict') !== false,
          signature,
          pickedInSession: enginePickedThisSession
        });
      };
      const verdict = enginePath ? await verifyEngine(enginePath) : null;
      if (!verdict || !verdict.ok) return { error: errorFor(verdict ? verdict.reason : 'missing') };
      return {
        state: await session.connect({
          server: { id: 'private', host: 'Stockholm private server', ip: null, country: 'Sweden', countryCode: 'SE' },
          config: profile,
          isPrivate: true,
          killSwitchEnabled: Boolean(store.get('killSwitchEnabled')),
          killSwitchStrict: store.get('killSwitchStrict') !== false,
          fingerprintPin: guard.pinnedFingerprint('private'),
          useCredentials: false,
          allowLegacyTls: false,
          enginePath,
          verifyEngine: async (candidate) => {
            const fresh = await verifyEngine(candidate);
            return { ok: fresh.ok, error: errorFor(fresh.reason) };
          }
        })
      };
    } catch (error) {
      return { error: error.message || 'CONNECT_FAILED' };
    }
  });

  ipcMain.handle('session:disconnect', async () => session.disconnect());
  ipcMain.handle('session:state', () => session.snapshot());

  ipcMain.handle('killswitch:restore', async () => {
    if (!session.killSwitch.locked()) return { ok: true, settings: await settingsView() };
    try {
      await session.killSwitch.recover();
      return { ok: session.killSwitch.locked() === false, settings: await settingsView() };
    } catch (error) {
      return { error: error.message || 'KILLSWITCH_RESTORE_FAILED', settings: await settingsView() };
    }
  });

  ipcMain.handle('settings:set', async (_event, patch) => {
    const data = patch && typeof patch === 'object' ? patch : {};
    if (data.language === 'ar' || data.language === 'en') {
      store.set({ language: data.language });
      updateTray(session.snapshot());
    }
    if (typeof data.disclosureAccepted === 'boolean') store.set({ disclosureAccepted: data.disclosureAccepted });
    // enginePath is deliberately not accepted here: it leads to an elevated
    // launch, so it may only change through the native file picker.
    if (typeof data.killSwitchEnabled === 'boolean') store.set({ killSwitchEnabled: data.killSwitchEnabled });
    if (typeof data.killSwitchStrict === 'boolean') store.set({ killSwitchStrict: data.killSwitchStrict });
    if (typeof data.engineStrict === 'boolean') store.set({ engineStrict: data.engineStrict });
    if (typeof data.releaseFeedUrl === 'string') {
      const url = data.releaseFeedUrl.trim();
      if (url && !validFeedUrl(url)) return { error: 'UPDATE_URL_INVALID', settings: await settingsView() };
      store.set({ releaseFeedUrl: url });
    }
    return { settings: await settingsView() };
  });

  ipcMain.handle('update:check', async () => {
    const feedUrl = store.get('releaseFeedUrl');
    if (!feedUrl) return { error: 'UPDATE_URL_MISSING' };
    try { return await checkForUpdate(feedUrl, app.getVersion()); }
    catch (error) { return { error: error.message || 'UPDATE_FAILED' }; }
  });

  ipcMain.handle('engine:pick', async () => {
    const result = await dialog.showOpenDialog(win, {
      title: 'اختر ملف openvpn.exe',
      properties: ['openFile'],
      filters: [{ name: 'OpenVPN', extensions: ['exe'] }]
    });
    if (result.canceled || !result.filePaths[0]) return { canceled: true };
    const picked = result.filePaths[0];
    const signature = await guard.signatureOf(picked, { fresh: true });
    const verdict = engineVerdict({
      enginePath: picked,
      strict: store.get('engineStrict') !== false,
      signature,
      pickedInSession: true
    });
    if (!verdict.ok) return { error: errorFor(verdict.reason), settings: await settingsView() };
    store.set({ enginePath: picked });
    enginePickedThisSession = true;
    return { settings: await settingsView() };
  });

  ipcMain.handle('profile:import', async () => {
    const result = await dialog.showOpenDialog(win, {
      title: 'اختر ملف إعداد OpenVPN',
      properties: ['openFile'],
      filters: [{ name: 'OpenVPN', extensions: ['ovpn'] }]
    });
    if (result.canceled || !result.filePaths[0]) return { canceled: true };
    if (!store.encryptionAvailable()) return { error: 'ENCRYPTION_UNAVAILABLE' };
    try {
      const text = readProfileFile(result.filePaths[0]);
      if (!store.setSecret('privateProfile', text)) return { error: 'ENCRYPTION_UNAVAILABLE' };
      const name = path.basename(result.filePaths[0]);
      store.set({ privateProfileName: name, privateProfileExpiresAt: profileInfo(text).expiresAt });
      return { ok: true, name, settings: await settingsView() };
    } catch (error) {
      return { error: error.message === 'PROFILE_TOO_LARGE' ? 'PROFILE_TOO_LARGE' : 'PROFILE_INVALID' };
    }
  });

  ipcMain.handle('profile:remove', async () => {
    store.setSecret('privateProfile', null);
    store.set({ privateProfileName: '', privateProfileExpiresAt: 0 });
    return { ok: true, settings: await settingsView() };
  });

  ipcMain.handle('app:quit', () => app.quit());
}

async function captureAndExit() {
  const target = process.argv[captureIndex + 1] || path.join(app.getPath('temp'), 'aivpn-desktop.png');
  try {
    if (!win.isVisible()) win.showInactive();
    await new Promise((resolve) => setTimeout(resolve, 9000));
    if (/^\d{3,4}x\d{3,4}$/.test(captureSize)) {
      const [width, height] = captureSize.split('x').map(Number);
      win.setContentSize(width, height);
      await new Promise((resolve) => setTimeout(resolve, 900));
    }
    if (captureConnect === 'private') {
      const result = await win.webContents.executeJavaScript("window.aivpn.connect('private')");
      process.stdout.write(`capture connect: ${JSON.stringify(result && result.state && result.state.status)}\n`);
      await new Promise((resolve) => setTimeout(resolve, 15000));
    }
    if (/^[a-z]+$/.test(captureTab)) {
      await win.webContents
        .executeJavaScript(
          `document.querySelector('.tabbar button[data-goto="${captureTab}"]')?.click(); true`
        )
        .catch(() => {});
      await new Promise((resolve) => setTimeout(resolve, 1200));
    }
    const image = await win.webContents.capturePage();
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, image.toPNG());
  } catch (error) {
    process.stdout.write(`capture failed: ${error.message}\n`);
    await session.disconnect().catch(() => {});
    app.exit(1);
    return;
  }
  await session.disconnect().catch(() => {});
  app.exit(0);
}

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (!win) return;
    win.show();
    win.focus();
  });

  app.whenReady().then(async () => {
    app.setAppUserModelId(APP_ID);
    Menu.setApplicationMenu(null);
    const userData = app.getPath('userData');
    store = new SettingsStore(userData);
    await store.detectEncryption();
    guard = new Guard({ storeFile: path.join(userData, 'guard.json') });
    intel = new Intel({ cacheFile: path.join(userData, 'intel.json') });
    session = new VpnSession({
      runDir: path.join(userData, 'run'),
      findEngine: async () => resolveEngine(store.get('enginePath')),
      getCredentials: () => ({ username: '', password: '' })
    });
    if (!captureMode && session.killSwitch.locked()) {
      // A previous run stopped while the fail-closed kill switch was armed;
      // one elevated restore puts the network back before the UI opens.
      await session.killSwitch.recover().catch(() => {});
    }
    if (!captureMode) {
      // A crashed run can leave its elevated supervisor (and engine) behind.
      // One stop marker tears it down without another UAC prompt.
      await session.recoverStaleSupervisor().catch(() => {});
    }
    session.on('state', (state) => {
      if (state.status === 'CONNECTING') lastGuardLevel = 'idle';
      updateTray(state);
      if (win && !win.isDestroyed()) win.webContents.send('state', state);
      scheduleGuard();
    });

    registerIpc();
    createWindow();
    if (!captureMode) createTray();
    refreshIntel().catch(() => {});
    setInterval(() => refreshIntel().catch(() => {}), 6 * 60 * 60 * 1000);

    if (captureMode) {
      win.webContents.once('did-finish-load', () => {
        captureAndExit().catch(() => app.exit(1));
      });
    }
  });

  app.on('window-all-closed', () => {
    // The window is hidden instead of destroyed; quitting goes through the tray.
  });

  app.on('before-quit', (event) => {
    if (quitting) return;
    event.preventDefault();
    quitting = true;
    if (!session) {
      app.exit(0);
      return;
    }
    session
      .disconnect()
      .catch(() => {})
      .finally(() => app.exit(0));
  });
}
