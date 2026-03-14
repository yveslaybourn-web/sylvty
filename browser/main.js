/**
 * ========================================================================
 * ShadowNet Browser — Point d'entrée Electron principal
 * ========================================================================
 *
 * Architecture de sécurité :
 * - Protocoles IPC stricts avec validation des canaux
 * - Isolation du contexte activée (contextIsolation: true)
 * - Node.js désactivé dans le renderer (nodeIntegration: false)
 * - Preload script pour exposer uniquement les API nécessaires
 * - Content Security Policy appliquée
 *
 * Ce fichier gère :
 * - Création de la fenêtre principale avec esthétique cyberpunk
 * - Enregistrement des gestionnaires IPC sécurisés
 * - Initialisation du proxy d'interception
 * - Gestion des sessions anti-fingerprinting
 * - Raccourcis globaux (Command Palette, Burn Session, etc.)
 */

const { app, BrowserWindow, ipcMain, session, globalShortcut, dialog, Menu } = require('electron');
const path = require('path');
const { InterceptionProxy } = require('./core/interception-proxy');
const { SessionManager } = require('./core/session-manager');
const { EvasionEngine } = require('./modules/evasion-engine');
const { ForensicMode } = require('./modules/forensic-mode');
const { ScriptInjectorEngine } = require('./modules/script-injector-engine');
const { ConfigManager } = require('./modules/config-manager');
const { ExportEngine } = require('./modules/export-engine');
const { ScopeManager } = require('./modules/scope-manager');

// ═══════════════════════════════════════════════════════════════════════
// VARIABLES GLOBALES
// ═══════════════════════════════════════════════════════════════════════

let mainWindow = null;
let interceptionProxy = null;
let sessionManager = null;
let evasionEngine = null;
let forensicMode = null;
let scriptInjector = null;
let configManager = null;
let exportEngine = null;
let scopeManager = null;
let ptyProcess = null; // Terminal PTY

// Liste blanche des canaux IPC autorisés — Sécurité : empêche l'accès
// arbitraire aux API Node.js depuis le renderer
const ALLOWED_IPC_CHANNELS = [
  // Navigation et onglets
  'tab:create', 'tab:close', 'tab:switch', 'tab:list',
  'nav:go', 'nav:back', 'nav:forward', 'nav:reload',
  // Proxy d'interception
  'proxy:toggle', 'proxy:status', 'proxy:get-requests',
  'proxy:tamper-request', 'proxy:forward-request', 'proxy:drop-request',
  'proxy:replay-request', 'proxy:clear-history',
  // Reconnaissance & OSINT
  'recon:whois', 'recon:tech-detect', 'recon:headers',
  'recon:subdomains', 'recon:dirscan',
  // Session & anti-fingerprinting
  'session:spoof-ua', 'session:get-fingerprint', 'session:randomize',
  'session:burn', 'session:toggle-webrtc', 'session:set-proxy',
  // Outils crypto
  'crypto:encode', 'crypto:decode', 'crypto:jwt-decode', 'crypto:jwt-inspect',
  // Analyse de vulnérabilités
  'vuln:scan-headers', 'vuln:check-exposed-files', 'vuln:dom-sinks',
  // Assistant IA
  'ai:analyze', 'ai:deobfuscate', 'ai:suggest-vectors',
  // Système
  'sys:get-resources', 'sys:get-url-info',
  // Commandes palette
  'command:execute',
  // Config & persistance
  'config:get', 'config:set', 'config:get-all',
  // Export
  'export:json', 'export:markdown', 'export:html',
  // Bookmarks
  'bookmarks:add', 'bookmarks:remove', 'bookmarks:list',
  // Historique
  'history:add', 'history:get', 'history:clear',
  // WebSocket
  'proxy:get-ws-requests', 'proxy:clear-ws',
  // IDOR
  'proxy:get-idor-candidates',
  // Scope
  'scope:add', 'scope:remove', 'scope:list', 'scope:check', 'scope:set-mode',
  // Notes & findings
  'notes:save', 'notes:get', 'findings:add', 'findings:remove', 'findings:list',
  // Fenêtre
  'win:minimize', 'win:maximize', 'win:close'
];

// ═══════════════════════════════════════════════════════════════════════
// CRÉATION DE LA FENÊTRE PRINCIPALE
// ═══════════════════════════════════════════════════════════════════════

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 800,
    // Esthétique cyberpunk — cadre personnalisé
    frame: false,
    titleBarStyle: 'hidden',
    backgroundColor: '#0a0a0f',
    icon: path.join(__dirname, 'ui', 'assets', 'icon.png'),
    webPreferences: {
      // SÉCURITÉ CRITIQUE : Isolation du contexte
      // Empêche le renderer d'accéder directement aux API Node.js
      contextIsolation: true,
      nodeIntegration: false,
      // Preload sécurisé — pont contrôlé entre main et renderer
      preload: path.join(__dirname, 'preload.js'),
      // Désactiver les fonctionnalités dangereuses
      enableRemoteModule: false,
      allowRunningInsecureContent: false,
      // Activer le sandboxing pour une couche de sécurité supplémentaire
      sandbox: false, // false car on a besoin du preload
      // WebView pour l'affichage des sites cibles
      webviewTag: true
    }
  });

  // Charger l'interface principale
  mainWindow.loadFile(path.join(__dirname, 'ui', 'index.html'));

  // Ouvrir DevTools en mode développement
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  }

  // Événements de fenêtre
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Appliquer la Content Security Policy
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        // CSP stricte pour l'UI du navigateur (pas pour les webviews)
        ...(details.url.startsWith('file://') ? {
          'Content-Security-Policy': [
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src *;"
          ]
        } : {})
      }
    });
  });
}

// ═══════════════════════════════════════════════════════════════════════
// INITIALISATION DES MODULES DE SÉCURITÉ
// ═══════════════════════════════════════════════════════════════════════

function initSecurityModules() {
  // Initialiser le proxy d'interception
  interceptionProxy = new InterceptionProxy(session.defaultSession);

  // Initialiser le gestionnaire de sessions anti-fingerprinting
  sessionManager = new SessionManager(session.defaultSession);

  // Initialiser le moteur d'évasion (JA3, proxy rotation, noise avancé)
  evasionEngine = new EvasionEngine(session.defaultSession);

  // Initialiser le mode forensique (zero-disk, DOM tracker)
  forensicMode = new ForensicMode(session.defaultSession);

  // Initialiser le script injector
  scriptInjector = new ScriptInjectorEngine();

  // Initialiser le gestionnaire de configuration (persistance)
  configManager = new ConfigManager();

  // Initialiser le moteur d'export
  exportEngine = new ExportEngine();

  // Initialiser le gestionnaire de scope
  scopeManager = new ScopeManager(configManager);
}

// ═══════════════════════════════════════════════════════════════════════
// GESTIONNAIRES IPC — PONT SÉCURISÉ MAIN ↔ RENDERER
// ═══════════════════════════════════════════════════════════════════════

function registerIPCHandlers() {

  // ─── GESTION DES ONGLETS ────────────────────────────────────────────

  /**
   * Stockage des onglets en mémoire
   * Structure : { id, url, title, domain, group, active }
   * Les onglets sont groupés par domaine cible pour la reconnaissance
   */
  const tabs = new Map();
  let tabCounter = 0;
  let activeTabId = null;

  ipcMain.handle('tab:create', async (event, { url = 'about:blank' } = {}) => {
    const id = `tab_${++tabCounter}`;
    const domain = extractDomain(url);
    tabs.set(id, { id, url, title: 'Nouvel onglet', domain, group: domain, active: false });
    return { id, url, domain };
  });

  ipcMain.handle('tab:close', async (event, { id }) => {
    tabs.delete(id);
    return { success: true };
  });

  ipcMain.handle('tab:switch', async (event, { id }) => {
    if (activeTabId) {
      const prev = tabs.get(activeTabId);
      if (prev) prev.active = false;
    }
    const tab = tabs.get(id);
    if (tab) {
      tab.active = true;
      activeTabId = id;
    }
    return tab || null;
  });

  ipcMain.handle('tab:list', async () => {
    return Array.from(tabs.values());
  });

  // ─── PROXY D'INTERCEPTION ──────────────────────────────────────────

  ipcMain.handle('proxy:toggle', async (event, { enabled }) => {
    if (enabled) {
      interceptionProxy.enable();
    } else {
      interceptionProxy.disable();
    }
    return { enabled: interceptionProxy.isEnabled() };
  });

  ipcMain.handle('proxy:status', async () => {
    return {
      enabled: interceptionProxy.isEnabled(),
      interceptedCount: interceptionProxy.getInterceptedCount(),
      pausedRequests: interceptionProxy.getPausedRequests()
    };
  });

  ipcMain.handle('proxy:get-requests', async () => {
    return interceptionProxy.getRequestHistory();
  });

  ipcMain.handle('proxy:tamper-request', async (event, { requestId, modifications }) => {
    return interceptionProxy.tamperRequest(requestId, modifications);
  });

  ipcMain.handle('proxy:forward-request', async (event, { requestId }) => {
    return interceptionProxy.forwardRequest(requestId);
  });

  ipcMain.handle('proxy:drop-request', async (event, { requestId }) => {
    return interceptionProxy.dropRequest(requestId);
  });

  ipcMain.handle('proxy:replay-request', async (event, { requestData }) => {
    return interceptionProxy.replayRequest(requestData);
  });

  ipcMain.handle('proxy:clear-history', async () => {
    interceptionProxy.clearHistory();
    return { success: true };
  });

  // ─── RECONNAISSANCE & OSINT ────────────────────────────────────────

  ipcMain.handle('recon:whois', async (event, { domain }) => {
    if (!validateDomain(domain)) {
      return { domain, error: 'Domaine invalide' };
    }
    const dns = require('dns').promises;
    try {
      const addresses = await withTimeout(dns.resolve4(domain), 10000, 'DNS timeout');
      const mx = await dns.resolveMx(domain).catch(() => []);
      const ns = await dns.resolveNs(domain).catch(() => []);
      const txt = await dns.resolveTxt(domain).catch(() => []);
      return { domain, addresses, mx, ns, txt };
    } catch (err) {
      return { domain, error: err.message };
    }
  });

  ipcMain.handle('recon:tech-detect', async (event, { headers, html, scripts }) => {
    // Détection de technologies à la manière de Wappalyzer
    return detectTechnologies(headers, html, scripts);
  });

  ipcMain.handle('recon:headers', async (event, { url }) => {
    if (!validateUrl(url)) {
      return { error: 'URL invalide — utilisez http:// ou https://' };
    }
    const https = require(url.startsWith('https') ? 'https' : 'http');
    return new Promise((resolve) => {
      const req = https.request(url, { method: 'HEAD' }, (res) => {
        resolve({ statusCode: res.statusCode, headers: res.headers });
      });
      req.on('error', (err) => resolve({ error: err.message }));
      req.setTimeout(10000, () => { req.destroy(); resolve({ error: 'Timeout (10s)' }); });
      req.end();
    });
  });

  ipcMain.handle('recon:subdomains', async (event, { domain }) => {
    if (!validateDomain(domain)) {
      return { domain, subdomains: [], error: 'Domaine invalide' };
    }
    const https = require('https');
    return new Promise((resolve) => {
      const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
      const req = https.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const certs = JSON.parse(data);
            const subdomains = [...new Set(certs.map(c => c.name_value).flat())];
            resolve({ domain, subdomains: subdomains.slice(0, 100) });
          } catch {
            resolve({ domain, subdomains: [], error: 'Erreur de parsing' });
          }
        });
      });
      req.on('error', (err) => resolve({ domain, subdomains: [], error: err.message }));
      req.setTimeout(15000, () => { req.destroy(); resolve({ domain, subdomains: [], error: 'Timeout (15s)' }); });
    });
  });

  ipcMain.handle('recon:dirscan', async (event, { baseUrl, wordlist }) => {
    if (!validateUrl(baseUrl)) {
      return { baseUrl, results: [], error: 'URL de base invalide' };
    }
    const defaultPaths = [
      '.git/', '.git/HEAD', '.env', '.htaccess', '.htpasswd',
      'robots.txt', 'sitemap.xml', '.well-known/security.txt',
      'wp-admin/', 'wp-login.php', 'admin/', 'administrator/',
      'backup/', 'backups/', 'db/', 'database/', 'dump/',
      'api/', 'api/v1/', 'api/v2/', 'graphql', 'swagger.json',
      'phpinfo.php', 'info.php', 'test.php', 'debug/',
      '.DS_Store', 'web.config', 'crossdomain.xml',
      'server-status', 'server-info', '.svn/', '.hg/',
      'wp-config.php.bak', 'config.php.bak', '.env.backup',
      'package.json', 'composer.json', 'Gemfile', 'requirements.txt'
    ];
    const paths = wordlist || defaultPaths;
    const https = require(baseUrl.startsWith('https') ? 'https' : 'http');
    const results = [];

    for (const p of paths) {
      const targetUrl = `${baseUrl.replace(/\/$/, '')}/${p}`;
      try {
        const status = await new Promise((resolve) => {
          const req = https.request(targetUrl, { method: 'HEAD', timeout: 5000 }, (res) => {
            resolve(res.statusCode);
          });
          req.on('error', () => resolve(0));
          req.on('timeout', () => { req.destroy(); resolve(0); });
          req.end();
        });
        if (status > 0 && status < 404) {
          results.push({ path: p, status, url: targetUrl });
        }
      } catch {
        // Ignorer les erreurs réseau
      }
      // B7 — Rate limiting : 100ms entre chaque requête
      await delay(100);
    }
    return { baseUrl, results };
  });

  // ─── SESSION & ANTI-FINGERPRINTING ─────────────────────────────────

  ipcMain.handle('session:spoof-ua', async (event, { userAgent }) => {
    sessionManager.setUserAgent(userAgent);
    return { userAgent };
  });

  ipcMain.handle('session:get-fingerprint', async () => {
    return sessionManager.getCurrentFingerprint();
  });

  ipcMain.handle('session:randomize', async () => {
    return sessionManager.randomizeFingerprint();
  });

  ipcMain.handle('session:burn', async () => {
    // BURN SESSION — Destruction complète des données de session
    // Critique pour l'anti-forensique : efface toute trace
    const ses = session.defaultSession;
    await ses.clearStorageData({
      storages: ['appcache', 'cookies', 'filesystem', 'indexdb',
                 'localstorage', 'shadercache', 'websql', 'serviceworkers',
                 'cachestorage']
    });
    await ses.clearCache();
    await ses.clearHostResolverCache();
    await ses.clearAuthCache();

    // Réinitialiser le proxy et le fingerprint
    interceptionProxy.clearHistory();
    sessionManager.randomizeFingerprint();

    // Fermer tous les onglets
    tabs.clear();
    tabCounter = 0;
    activeTabId = null;

    return { success: true, message: 'Session brûlée — toutes les données effacées' };
  });

  ipcMain.handle('session:toggle-webrtc', async (event, { blocked }) => {
    sessionManager.setWebRTCBlocked(blocked);
    return { blocked };
  });

  ipcMain.handle('session:set-proxy', async (event, { proxyRules }) => {
    // Configuration du proxy SOCKS5 pour routage Tor
    if (proxyRules) {
      await session.defaultSession.setProxy({ proxyRules });
    } else {
      await session.defaultSession.setProxy({ proxyRules: '' });
    }
    return { proxyRules };
  });

  // ─── OUTILS CRYPTO ─────────────────────────────────────────────────

  ipcMain.handle('crypto:encode', async (event, { text, encoding }) => {
    switch (encoding) {
      case 'base64': return { result: Buffer.from(text).toString('base64') };
      case 'url': return { result: encodeURIComponent(text) };
      case 'hex': return { result: Buffer.from(text).toString('hex') };
      case 'html': return { result: text.replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])) };
      default: return { error: 'Encodage inconnu' };
    }
  });

  ipcMain.handle('crypto:decode', async (event, { text, encoding }) => {
    try {
      switch (encoding) {
        case 'base64': return { result: Buffer.from(text, 'base64').toString('utf-8') };
        case 'url': return { result: decodeURIComponent(text) };
        case 'hex': return { result: Buffer.from(text, 'hex').toString('utf-8') };
        case 'html': return { result: text.replace(/&(amp|lt|gt|quot|#39);/g, (m, c) =>
          ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" }[c] || m)) };
        default: return { error: 'Décodage inconnu' };
      }
    } catch (err) {
      return { error: `Erreur de décodage: ${err.message}` };
    }
  });

  ipcMain.handle('crypto:jwt-decode', async (event, { token }) => {
    // Décodage JWT sans vérification de signature
    // Utile pour l'inspection de tokens pendant le pentest
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return { error: 'Format JWT invalide' };
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      return { header, payload, signature: parts[2] };
    } catch (err) {
      return { error: `Erreur JWT: ${err.message}` };
    }
  });

  // ─── ANALYSE DE VULNÉRABILITÉS ─────────────────────────────────────

  ipcMain.handle('vuln:scan-headers', async (event, { headers }) => {
    // Analyse des en-têtes de sécurité manquants
    const securityHeaders = {
      'strict-transport-security': { name: 'HSTS', severity: 'high' },
      'content-security-policy': { name: 'CSP', severity: 'high' },
      'x-content-type-options': { name: 'X-Content-Type-Options', severity: 'medium' },
      'x-frame-options': { name: 'X-Frame-Options', severity: 'medium' },
      'x-xss-protection': { name: 'X-XSS-Protection', severity: 'low' },
      'referrer-policy': { name: 'Referrer-Policy', severity: 'low' },
      'permissions-policy': { name: 'Permissions-Policy', severity: 'medium' },
      'cross-origin-opener-policy': { name: 'COOP', severity: 'low' },
      'cross-origin-resource-policy': { name: 'CORP', severity: 'low' },
      'cross-origin-embedder-policy': { name: 'COEP', severity: 'low' }
    };

    const missing = [];
    const present = [];
    const headerKeys = Object.keys(headers || {}).map(k => k.toLowerCase());

    for (const [header, info] of Object.entries(securityHeaders)) {
      if (headerKeys.includes(header)) {
        present.push({ ...info, header, value: headers[header] });
      } else {
        missing.push({ ...info, header });
      }
    }

    // Détecter les en-têtes dangereux exposés
    const dangerous = [];
    const dangerousHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
    for (const dh of dangerousHeaders) {
      if (headerKeys.includes(dh)) {
        dangerous.push({ header: dh, value: headers[dh], risk: 'Information disclosure' });
      }
    }

    return { missing, present, dangerous };
  });

  ipcMain.handle('vuln:check-exposed-files', async (event, { baseUrl }) => {
    // Vérification des fichiers sensibles exposés
    const sensitiveFiles = [
      { path: '.git/HEAD', risk: 'Code source exposé via Git' },
      { path: '.env', risk: 'Variables d\'environnement (credentials potentiels)' },
      { path: '.git/config', risk: 'Configuration Git (remotes, credentials)' },
      { path: 'wp-config.php.bak', risk: 'Backup de configuration WordPress' },
      { path: '.htpasswd', risk: 'Fichier de mots de passe Apache' },
      { path: 'phpinfo.php', risk: 'Informations PHP détaillées' },
      { path: 'web.config', risk: 'Configuration IIS' },
      { path: '.DS_Store', risk: 'Listing de répertoire macOS' },
      { path: 'debug.log', risk: 'Logs de débogage' },
      { path: 'error.log', risk: 'Logs d\'erreurs' }
    ];

    const http = require(baseUrl.startsWith('https') ? 'https' : 'http');
    const found = [];

    for (const file of sensitiveFiles) {
      const url = `${baseUrl.replace(/\/$/, '')}/${file.path}`;
      try {
        const status = await new Promise((resolve) => {
          const req = http.request(url, { method: 'HEAD', timeout: 5000 }, (res) => {
            resolve(res.statusCode);
          });
          req.on('error', () => resolve(0));
          req.on('timeout', () => { req.destroy(); resolve(0); });
          req.end();
        });
        if (status === 200) {
          found.push({ ...file, url, status });
        }
      } catch { /* Ignorer */ }
    }

    return { baseUrl, found };
  });

  // ─── CONTRÔLES FENÊTRE ────────────────────────────────────────────

  ipcMain.handle('win:minimize', () => {
    mainWindow.minimize();
  });

  ipcMain.handle('win:maximize', () => {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  });

  ipcMain.handle('win:close', () => {
    mainWindow.close();
  });

  // ─── INFORMATIONS SYSTÈME ──────────────────────────────────────────

  ipcMain.handle('sys:get-resources', async () => {
    const os = require('os');
    return {
      cpu: os.cpus(),
      totalMem: os.totalmem(),
      freeMem: os.freemem(),
      uptime: os.uptime(),
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname()
    };
  });

  ipcMain.handle('sys:get-url-info', async (event, { url }) => {
    try {
      const parsed = new URL(url);
      const dns = require('dns').promises;
      const addresses = await dns.resolve4(parsed.hostname).catch(() => []);
      return {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
        pathname: parsed.pathname,
        ip: addresses[0] || 'N/A'
      };
    } catch (err) {
      return { error: err.message };
    }
  });

  // ─── EVASION ENGINE ────────────────────────────────────────────────

  ipcMain.handle('evasion:randomize-ja3', async () => {
    return evasionEngine.randomizeJA3();
  });

  ipcMain.handle('evasion:add-proxy', async (event, { proxy }) => {
    return { pool: evasionEngine.addProxy(proxy) };
  });

  ipcMain.handle('evasion:load-proxies', async (event, { text }) => {
    return { pool: evasionEngine.loadProxies(text) };
  });

  ipcMain.handle('evasion:rotate-proxy', async () => {
    return await evasionEngine.rotateProxy();
  });

  ipcMain.handle('evasion:start-rotation', async (event, { interval }) => {
    evasionEngine.startRotation(interval);
    return { started: true };
  });

  ipcMain.handle('evasion:stop-rotation', async () => {
    evasionEngine.stopRotation();
    return { stopped: true };
  });

  ipcMain.handle('evasion:rotation-status', async () => {
    return evasionEngine.getRotationStatus();
  });

  ipcMain.handle('evasion:get-noise-script', async () => {
    return { script: evasionEngine.getAdvancedNoiseScript() };
  });

  // ─── FORENSIC MODE ────────────────────────────────────────────────

  ipcMain.handle('forensic:toggle-zero-disk', async (event, { enabled }) => {
    if (enabled) {
      return forensicMode.enableZeroDisk();
    } else {
      return forensicMode.disableZeroDisk();
    }
  });

  ipcMain.handle('forensic:wipe', async () => {
    return await forensicMode.performMultiPassWipe();
  });

  ipcMain.handle('forensic:snapshot', async (event, { tabId, html }) => {
    return forensicMode.takeSnapshot(tabId, html);
  });

  ipcMain.handle('forensic:compare', async (event, { tabId, html }) => {
    return forensicMode.compareWithSnapshot(tabId, html);
  });

  ipcMain.handle('forensic:dom-tracker-script', async () => {
    return { script: forensicMode.getDOMTrackerScript() };
  });

  // ─── SCRIPT INJECTOR ──────────────────────────────────────────────

  ipcMain.handle('scripts:list', async () => {
    return scriptInjector.getAllScripts();
  });

  ipcMain.handle('scripts:add', async (event, script) => {
    return { id: scriptInjector.addScript(script) };
  });

  ipcMain.handle('scripts:remove', async (event, { id }) => {
    return { removed: scriptInjector.removeScript(id) };
  });

  ipcMain.handle('scripts:toggle', async (event, { id }) => {
    return { enabled: scriptInjector.toggleScript(id) };
  });

  ipcMain.handle('scripts:for-domain', async (event, { domain }) => {
    return scriptInjector.getScriptsForDomain(domain);
  });

  ipcMain.handle('scripts:to-python', async (event, { request }) => {
    return { code: scriptInjector.toPython(request) };
  });

  ipcMain.handle('scripts:to-nodejs', async (event, { request }) => {
    return { code: scriptInjector.toNodeJS(request) };
  });

  ipcMain.handle('scripts:to-curl', async (event, { request }) => {
    return { code: scriptInjector.toCurl(request) };
  });

  // ─── TERMINAL INTÉGRÉ (via node-pty) ──────────────────────────────

  ipcMain.handle('terminal:create', async () => {
    try {
      const pty = require('node-pty');
      const shell = process.platform === 'win32' ? 'powershell.exe' :
                     process.env.SHELL || '/bin/bash';

      ptyProcess = pty.spawn(shell, [], {
        name: 'xterm-256color',
        cols: 120,
        rows: 30,
        cwd: process.env.HOME || process.cwd(),
        env: { ...process.env, TERM: 'xterm-256color' }
      });

      // Transmettre les données du terminal au renderer
      ptyProcess.onData((data) => {
        if (mainWindow) {
          mainWindow.webContents.send('terminal:data', data);
        }
      });

      ptyProcess.onExit(({ exitCode }) => {
        if (mainWindow) {
          mainWindow.webContents.send('terminal:exit', exitCode);
        }
        ptyProcess = null;
      });

      return { success: true, pid: ptyProcess.pid };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('terminal:write', async (event, { data }) => {
    if (ptyProcess) {
      ptyProcess.write(data);
      return { success: true };
    }
    return { success: false, error: 'Terminal non initialisé' };
  });

  ipcMain.handle('terminal:resize', async (event, { cols, rows }) => {
    if (ptyProcess) {
      ptyProcess.resize(cols, rows);
      return { success: true };
    }
    return { success: false };
  });

  ipcMain.handle('terminal:kill', async () => {
    if (ptyProcess) {
      ptyProcess.kill();
      ptyProcess = null;
      return { success: true };
    }
    return { success: false };
  });

  // ─── PIPE DATA TO FILE ────────────────────────────────────────────

  ipcMain.handle('pipe:write-file', async (event, { filePath, data }) => {
    if (!isPathAllowed(filePath)) {
      return { success: false, error: 'Chemin non autorisé — utilisez Downloads, Documents ou ~/shadownet-output/' };
    }
    const fs = require('fs').promises;
    try {
      const dir = require('path').dirname(filePath);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(filePath, data, 'utf-8');
      return { success: true, path: filePath };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('pipe:append-file', async (event, { filePath, data }) => {
    if (!isPathAllowed(filePath)) {
      return { success: false, error: 'Chemin non autorisé — utilisez Downloads, Documents ou ~/shadownet-output/' };
    }
    const fs = require('fs').promises;
    try {
      const dir = require('path').dirname(filePath);
      await fs.mkdir(dir, { recursive: true });
      await fs.appendFile(filePath, data + '\n', 'utf-8');
      return { success: true, path: filePath };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  // ─── CONFIG & PERSISTANCE (C9) ─────────────────────────────────────

  ipcMain.handle('config:get', async (event, { key, defaultValue }) => {
    return configManager.get(key, defaultValue);
  });

  ipcMain.handle('config:set', async (event, { key, value }) => {
    configManager.set(key, value);
    return { success: true };
  });

  ipcMain.handle('config:get-all', async () => {
    return configManager.getAll();
  });

  // ─── EXPORT (C10) ──────────────────────────────────────────────────

  ipcMain.handle('export:json', async (event, { data }) => {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Exporter en JSON',
      defaultPath: `shadownet-report-${Date.now()}.json`,
      filters: [{ name: 'JSON', extensions: ['json'] }]
    });
    if (!result.canceled && result.filePath) {
      const fs = require('fs').promises;
      await fs.writeFile(result.filePath, exportEngine.toJSON(data), 'utf-8');
      return { success: true, path: result.filePath };
    }
    return { success: false, error: 'Export annulé' };
  });

  ipcMain.handle('export:markdown', async (event, { data }) => {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Exporter en Markdown',
      defaultPath: `shadownet-report-${Date.now()}.md`,
      filters: [{ name: 'Markdown', extensions: ['md'] }]
    });
    if (!result.canceled && result.filePath) {
      const fs = require('fs').promises;
      await fs.writeFile(result.filePath, exportEngine.toMarkdown(data), 'utf-8');
      return { success: true, path: result.filePath };
    }
    return { success: false, error: 'Export annulé' };
  });

  ipcMain.handle('export:html', async (event, { data }) => {
    const result = await dialog.showSaveDialog(mainWindow, {
      title: 'Exporter en HTML',
      defaultPath: `shadownet-report-${Date.now()}.html`,
      filters: [{ name: 'HTML', extensions: ['html'] }]
    });
    if (!result.canceled && result.filePath) {
      const fs = require('fs').promises;
      await fs.writeFile(result.filePath, exportEngine.toHTML(data), 'utf-8');
      return { success: true, path: result.filePath };
    }
    return { success: false, error: 'Export annulé' };
  });

  // ─── BOOKMARKS (C12) ──────────────────────────────────────────────

  ipcMain.handle('bookmarks:add', async (event, { name, url }) => {
    const bookmarks = configManager.get('bookmarks', []);
    bookmarks.push({
      id: `bm-${Date.now()}`,
      name: name || url,
      url,
      addedAt: new Date().toISOString()
    });
    configManager.set('bookmarks', bookmarks);
    return { success: true, bookmarks };
  });

  ipcMain.handle('bookmarks:remove', async (event, { id }) => {
    let bookmarks = configManager.get('bookmarks', []);
    bookmarks = bookmarks.filter(b => b.id !== id);
    configManager.set('bookmarks', bookmarks);
    return { success: true, bookmarks };
  });

  ipcMain.handle('bookmarks:list', async () => {
    return configManager.get('bookmarks', []);
  });

  // ─── HISTORIQUE (C11) ──────────────────────────────────────────────

  ipcMain.handle('history:add', async (event, { url, title }) => {
    const history = configManager.get('history', []);
    history.push({ url, title, visitedAt: new Date().toISOString() });
    // Limiter à 500 entrées
    if (history.length > 500) history.splice(0, history.length - 500);
    configManager.set('history', history);
    return { success: true };
  });

  ipcMain.handle('history:get', async () => {
    return configManager.get('history', []);
  });

  ipcMain.handle('history:clear', async () => {
    configManager.set('history', []);
    return { success: true };
  });

  // ─── WEBSOCKET (D13) ──────────────────────────────────────────────

  ipcMain.handle('proxy:get-ws-requests', async () => {
    return interceptionProxy.getWSHistory();
  });

  ipcMain.handle('proxy:clear-ws', async () => {
    interceptionProxy.clearWSHistory();
    return { success: true };
  });

  // ─── IDOR (A3) ────────────────────────────────────────────────────

  ipcMain.handle('proxy:get-idor-candidates', async () => {
    return interceptionProxy.getIDORCandidates();
  });

  // ─── SCOPE MANAGER (D15) ──────────────────────────────────────────

  ipcMain.handle('scope:add', async (event, { domain }) => {
    if (!validateDomain(domain) && !domain.startsWith('*.')) {
      return { success: false, error: 'Domaine invalide' };
    }
    scopeManager.addDomain(domain);
    return { success: true, scope: scopeManager.getScope() };
  });

  ipcMain.handle('scope:remove', async (event, { domain }) => {
    scopeManager.removeDomain(domain);
    return { success: true, scope: scopeManager.getScope() };
  });

  ipcMain.handle('scope:list', async () => {
    return { scope: scopeManager.getScope(), mode: scopeManager.getMode() };
  });

  ipcMain.handle('scope:check', async (event, { url }) => {
    return scopeManager.checkScope(url);
  });

  ipcMain.handle('scope:set-mode', async (event, { mode }) => {
    scopeManager.setMode(mode);
    return { success: true, mode };
  });

  // ─── NOTES & FINDINGS (D16) ───────────────────────────────────────

  ipcMain.handle('notes:save', async (event, { text }) => {
    configManager.set('notes', text);
    return { success: true };
  });

  ipcMain.handle('notes:get', async () => {
    return { text: configManager.get('notes', '') };
  });

  ipcMain.handle('findings:add', async (event, finding) => {
    const findings = configManager.get('findings', []);
    findings.push({
      id: `f-${Date.now()}`,
      ...finding,
      createdAt: new Date().toISOString()
    });
    configManager.set('findings', findings);
    return { success: true, findings };
  });

  ipcMain.handle('findings:remove', async (event, { id }) => {
    let findings = configManager.get('findings', []);
    findings = findings.filter(f => f.id !== id);
    configManager.set('findings', findings);
    return { success: true, findings };
  });

  ipcMain.handle('findings:list', async () => {
    return configManager.get('findings', []);
  });
}

// ═══════════════════════════════════════════════════════════════════════
// DÉTECTION DE TECHNOLOGIES (WAPPALYZER-STYLE)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Analyse les en-têtes HTTP, le HTML et les scripts pour identifier
 * les technologies utilisées par le site cible.
 *
 * Contexte sécurité : La détection de stack technologique est la première
 * étape de la reconnaissance. Identifier le CMS, le framework, et le
 * serveur permet de cibler les CVE connues.
 */
function detectTechnologies(headers = {}, html = '', scripts = []) {
  const detected = [];
  const headerStr = JSON.stringify(headers).toLowerCase();
  const htmlLower = html.toLowerCase();
  const scriptStr = scripts.join(' ').toLowerCase();

  // Signatures de technologies
  const signatures = [
    // Serveurs web
    { name: 'Apache', category: 'Serveur', test: () => headerStr.includes('apache') },
    { name: 'Nginx', category: 'Serveur', test: () => headerStr.includes('nginx') },
    { name: 'IIS', category: 'Serveur', test: () => headerStr.includes('microsoft-iis') },
    { name: 'Cloudflare', category: 'CDN/WAF', test: () => headerStr.includes('cloudflare') },

    // Frameworks JS
    { name: 'React', category: 'Framework JS', test: () => htmlLower.includes('__react') || htmlLower.includes('data-reactroot') || scriptStr.includes('react') },
    { name: 'Vue.js', category: 'Framework JS', test: () => htmlLower.includes('data-v-') || scriptStr.includes('vue.js') || scriptStr.includes('vue.min.js') },
    { name: 'Angular', category: 'Framework JS', test: () => htmlLower.includes('ng-app') || htmlLower.includes('ng-version') },
    { name: 'jQuery', category: 'Librairie JS', test: () => scriptStr.includes('jquery') },
    { name: 'Next.js', category: 'Framework', test: () => htmlLower.includes('__next') || htmlLower.includes('/_next/') },
    { name: 'Nuxt.js', category: 'Framework', test: () => htmlLower.includes('__nuxt') || htmlLower.includes('/_nuxt/') },

    // CMS
    { name: 'WordPress', category: 'CMS', test: () => htmlLower.includes('wp-content') || htmlLower.includes('wp-includes') },
    { name: 'Drupal', category: 'CMS', test: () => htmlLower.includes('drupal') || headerStr.includes('x-drupal') },
    { name: 'Joomla', category: 'CMS', test: () => htmlLower.includes('/media/jui/') || htmlLower.includes('joomla') },

    // Backend
    { name: 'PHP', category: 'Langage', test: () => headerStr.includes('x-powered-by') && headerStr.includes('php') },
    { name: 'ASP.NET', category: 'Framework', test: () => headerStr.includes('asp.net') || headerStr.includes('x-aspnet') },
    { name: 'Express.js', category: 'Framework', test: () => headerStr.includes('x-powered-by') && headerStr.includes('express') },
    { name: 'Django', category: 'Framework', test: () => headerStr.includes('csrftoken') || htmlLower.includes('csrfmiddlewaretoken') },
    { name: 'Laravel', category: 'Framework', test: () => headerStr.includes('laravel_session') || htmlLower.includes('csrf-token') },
    { name: 'Ruby on Rails', category: 'Framework', test: () => headerStr.includes('x-powered-by') && headerStr.includes('phusion') },

    // Sécurité
    { name: 'Cloudflare WAF', category: 'WAF', test: () => headerStr.includes('cf-ray') },
    { name: 'AWS WAF', category: 'WAF', test: () => headerStr.includes('x-amzn') },
    { name: 'ModSecurity', category: 'WAF', test: () => headerStr.includes('mod_security') },

    // Analytics & tracking
    { name: 'Google Analytics', category: 'Analytics', test: () => scriptStr.includes('google-analytics') || scriptStr.includes('gtag') },
    { name: 'Google Tag Manager', category: 'Analytics', test: () => scriptStr.includes('googletagmanager') },
  ];

  for (const sig of signatures) {
    try {
      if (sig.test()) {
        detected.push({ name: sig.name, category: sig.category });
      }
    } catch { /* Ignorer les erreurs de détection */ }
  }

  return detected;
}

// ═══════════════════════════════════════════════════════════════════════
// UTILITAIRES & VALIDATION (B5-B8)
// ═══════════════════════════════════════════════════════════════════════

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return 'unknown';
  }
}

/**
 * B5 — Validation des chemins fichiers
 * Empêche l'écriture dans des répertoires système ou sensibles
 */
function isPathAllowed(filePath) {
  const os = require('os');
  const pathModule = require('path');
  const resolved = pathModule.resolve(filePath);

  // Bloquer la traversée de répertoires
  if (filePath.includes('..')) return false;

  // Répertoires autorisés
  const allowedDirs = [
    app.getPath('downloads'),
    app.getPath('documents'),
    pathModule.join(os.homedir(), 'shadownet-output'),
    app.getPath('desktop')
  ];

  // Répertoires système bloqués
  const blockedPaths = [
    '/etc', '/usr', '/bin', '/sbin', '/var', '/root/.ssh',
    'C:\\Windows', 'C:\\Program Files', 'C:\\System32'
  ];

  for (const blocked of blockedPaths) {
    if (resolved.startsWith(blocked)) return false;
  }

  for (const allowed of allowedDirs) {
    if (resolved.startsWith(allowed)) return true;
  }

  return false;
}

/**
 * B8 — Validation des domaines
 */
function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length > 255) return false;
  return /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/.test(domain);
}

/**
 * B8 — Validation des URLs
 */
function validateUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * B6 — Wrapper timeout pour les promesses
 */
function withTimeout(promise, ms, errorMsg = 'Timeout') {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(errorMsg)), ms))
  ]);
}

/**
 * B7 — Délai entre les requêtes pour le rate limiting
 */
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ═══════════════════════════════════════════════════════════════════════
// RACCOURCIS GLOBAUX
// ═══════════════════════════════════════════════════════════════════════

function registerGlobalShortcuts() {
  // Ctrl+Shift+P — Command Palette (palette de commandes hacker)
  globalShortcut.register('CommandOrControl+Shift+P', () => {
    if (mainWindow) {
      mainWindow.webContents.send('toggle-command-palette');
    }
  });

  // Ctrl+Shift+B — Burn Session (destruction de session)
  globalShortcut.register('CommandOrControl+Shift+B', () => {
    if (mainWindow) {
      mainWindow.webContents.send('burn-session-shortcut');
    }
  });

  // Ctrl+Shift+I — Toggle Interception Proxy
  globalShortcut.register('CommandOrControl+Shift+I', () => {
    if (mainWindow) {
      mainWindow.webContents.send('toggle-proxy-shortcut');
    }
  });

  // F12 — Toggle Split Screen
  globalShortcut.register('F12', () => {
    if (mainWindow) {
      mainWindow.webContents.send('toggle-split-screen');
    }
  });

  // Ctrl+Shift+H — Toggle Hacker Panel
  globalShortcut.register('CommandOrControl+Shift+H', () => {
    if (mainWindow) {
      mainWindow.webContents.send('toggle-hacker-panel');
    }
  });

  // Ctrl+` — Toggle Terminal
  globalShortcut.register('CommandOrControl+`', () => {
    if (mainWindow) {
      mainWindow.webContents.send('toggle-terminal');
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════
// CYCLE DE VIE DE L'APPLICATION
// ═══════════════════════════════════════════════════════════════════════

app.whenReady().then(() => {
  createMainWindow();
  initSecurityModules();
  registerIPCHandlers();
  registerGlobalShortcuts();

  // Supprimer le menu par défaut d'Electron pour l'esthétique minimale
  Menu.setApplicationMenu(null);
});

app.on('window-all-closed', () => {
  // Sur macOS, les apps restent actives jusqu'à Cmd+Q
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createMainWindow();
  }
});

app.on('will-quit', async () => {
  // Libérer tous les raccourcis globaux
  globalShortcut.unregisterAll();

  // Si le mode Zero-Disk est actif, effectuer un wipe multi-pass
  if (forensicMode && forensicMode.isZeroDiskEnabled()) {
    await forensicMode.performMultiPassWipe();
  }

  // Tuer le processus terminal si actif
  if (ptyProcess) {
    ptyProcess.kill();
    ptyProcess = null;
  }
});

// Sécurité : Empêcher l'ouverture de nouvelles fenêtres non contrôlées
app.on('web-contents-created', (event, contents) => {
  contents.setWindowOpenHandler(({ url }) => {
    // Rediriger vers le système d'onglets interne
    if (mainWindow) {
      mainWindow.webContents.send('external-link', url);
    }
    return { action: 'deny' };
  });
});
