/**
 * ========================================================================
 * ShadowNet Browser — Script de Preload Sécurisé
 * ========================================================================
 *
 * Ce script agit comme un pont sécurisé entre le processus principal
 * (Node.js) et le renderer (navigateur). Il expose uniquement les API
 * nécessaires via contextBridge, empêchant l'accès direct aux modules
 * Node.js depuis le code de l'interface.
 *
 * Contexte sécurité : Le preload est la couche de sécurité la plus
 * critique dans une app Electron. Il définit la surface d'attaque
 * accessible depuis le renderer.
 */

const { contextBridge, ipcRenderer } = require('electron');

// ═══════════════════════════════════════════════════════════════════════
// API EXPOSÉES AU RENDERER
// ═══════════════════════════════════════════════════════════════════════

contextBridge.exposeInMainWorld('shadownet', {

  // ─── GESTION DES ONGLETS ────────────────────────────────────────────
  tabs: {
    create: (options) => ipcRenderer.invoke('tab:create', options),
    close: (id) => ipcRenderer.invoke('tab:close', { id }),
    switch: (id) => ipcRenderer.invoke('tab:switch', { id }),
    list: () => ipcRenderer.invoke('tab:list')
  },

  // ─── NAVIGATION ────────────────────────────────────────────────────
  nav: {
    go: (url) => ipcRenderer.invoke('nav:go', { url }),
    back: () => ipcRenderer.invoke('nav:back'),
    forward: () => ipcRenderer.invoke('nav:forward'),
    reload: () => ipcRenderer.invoke('nav:reload')
  },

  // ─── PROXY D'INTERCEPTION ──────────────────────────────────────────
  proxy: {
    toggle: (enabled) => ipcRenderer.invoke('proxy:toggle', { enabled }),
    status: () => ipcRenderer.invoke('proxy:status'),
    getRequests: () => ipcRenderer.invoke('proxy:get-requests'),
    tamper: (requestId, modifications) =>
      ipcRenderer.invoke('proxy:tamper-request', { requestId, modifications }),
    forward: (requestId) => ipcRenderer.invoke('proxy:forward-request', { requestId }),
    drop: (requestId) => ipcRenderer.invoke('proxy:drop-request', { requestId }),
    replay: (requestData) => ipcRenderer.invoke('proxy:replay-request', { requestData }),
    clearHistory: () => ipcRenderer.invoke('proxy:clear-history')
  },

  // ─── RECONNAISSANCE & OSINT ────────────────────────────────────────
  recon: {
    whois: (domain) => ipcRenderer.invoke('recon:whois', { domain }),
    detectTech: (data) => ipcRenderer.invoke('recon:tech-detect', data),
    headers: (url) => ipcRenderer.invoke('recon:headers', { url }),
    subdomains: (domain) => ipcRenderer.invoke('recon:subdomains', { domain }),
    dirScan: (baseUrl, wordlist) =>
      ipcRenderer.invoke('recon:dirscan', { baseUrl, wordlist })
  },

  // ─── SESSION & ANTI-FINGERPRINTING ─────────────────────────────────
  session: {
    spoofUA: (userAgent) => ipcRenderer.invoke('session:spoof-ua', { userAgent }),
    getFingerprint: () => ipcRenderer.invoke('session:get-fingerprint'),
    randomize: () => ipcRenderer.invoke('session:randomize'),
    burn: () => ipcRenderer.invoke('session:burn'),
    toggleWebRTC: (blocked) => ipcRenderer.invoke('session:toggle-webrtc', { blocked }),
    setProxy: (proxyRules) => ipcRenderer.invoke('session:set-proxy', { proxyRules })
  },

  // ─── OUTILS CRYPTO ─────────────────────────────────────────────────
  crypto: {
    encode: (text, encoding) => ipcRenderer.invoke('crypto:encode', { text, encoding }),
    decode: (text, encoding) => ipcRenderer.invoke('crypto:decode', { text, encoding }),
    jwtDecode: (token) => ipcRenderer.invoke('crypto:jwt-decode', { token })
  },

  // ─── ANALYSE DE VULNÉRABILITÉS ─────────────────────────────────────
  vuln: {
    scanHeaders: (headers) => ipcRenderer.invoke('vuln:scan-headers', { headers }),
    checkExposedFiles: (baseUrl) => ipcRenderer.invoke('vuln:check-exposed-files', { baseUrl }),
    domSinks: () => ipcRenderer.invoke('vuln:dom-sinks')
  },

  // ─── ASSISTANT IA ──────────────────────────────────────────────────
  ai: {
    analyze: (data) => ipcRenderer.invoke('ai:analyze', data),
    deobfuscate: (code) => ipcRenderer.invoke('ai:deobfuscate', { code }),
    suggestVectors: (data) => ipcRenderer.invoke('ai:suggest-vectors', data)
  },

  // ─── SYSTÈME ───────────────────────────────────────────────────────
  system: {
    getResources: () => ipcRenderer.invoke('sys:get-resources'),
    getUrlInfo: (url) => ipcRenderer.invoke('sys:get-url-info', { url })
  },

  // ─── COMMANDES ─────────────────────────────────────────────────────
  command: {
    execute: (cmd) => ipcRenderer.invoke('command:execute', { cmd })
  },

  // ─── EVASION ENGINE ───────────────────────────────────────────────
  evasion: {
    randomizeJA3: () => ipcRenderer.invoke('evasion:randomize-ja3'),
    addProxy: (proxy) => ipcRenderer.invoke('evasion:add-proxy', { proxy }),
    loadProxies: (text) => ipcRenderer.invoke('evasion:load-proxies', { text }),
    rotateProxy: () => ipcRenderer.invoke('evasion:rotate-proxy'),
    startRotation: (interval) => ipcRenderer.invoke('evasion:start-rotation', { interval }),
    stopRotation: () => ipcRenderer.invoke('evasion:stop-rotation'),
    rotationStatus: () => ipcRenderer.invoke('evasion:rotation-status'),
    getNoiseScript: () => ipcRenderer.invoke('evasion:get-noise-script')
  },

  // ─── FORENSIC MODE ────────────────────────────────────────────────
  forensic: {
    toggleZeroDisk: (enabled) => ipcRenderer.invoke('forensic:toggle-zero-disk', { enabled }),
    wipe: () => ipcRenderer.invoke('forensic:wipe'),
    snapshot: (tabId, html) => ipcRenderer.invoke('forensic:snapshot', { tabId, html }),
    compare: (tabId, html) => ipcRenderer.invoke('forensic:compare', { tabId, html }),
    getDOMTrackerScript: () => ipcRenderer.invoke('forensic:dom-tracker-script')
  },

  // ─── SCRIPT INJECTOR ──────────────────────────────────────────────
  scripts: {
    list: () => ipcRenderer.invoke('scripts:list'),
    add: (script) => ipcRenderer.invoke('scripts:add', script),
    remove: (id) => ipcRenderer.invoke('scripts:remove', { id }),
    toggle: (id) => ipcRenderer.invoke('scripts:toggle', { id }),
    forDomain: (domain) => ipcRenderer.invoke('scripts:for-domain', { domain }),
    toPython: (request) => ipcRenderer.invoke('scripts:to-python', { request }),
    toNodeJS: (request) => ipcRenderer.invoke('scripts:to-nodejs', { request }),
    toCurl: (request) => ipcRenderer.invoke('scripts:to-curl', { request })
  },

  // ─── TERMINAL ─────────────────────────────────────────────────────
  terminal: {
    create: () => ipcRenderer.invoke('terminal:create'),
    write: (data) => ipcRenderer.invoke('terminal:write', { data }),
    resize: (cols, rows) => ipcRenderer.invoke('terminal:resize', { cols, rows }),
    kill: () => ipcRenderer.invoke('terminal:kill')
  },

  // ─── PIPE DATA ────────────────────────────────────────────────────
  pipe: {
    writeFile: (filePath, data) => ipcRenderer.invoke('pipe:write-file', { filePath, data }),
    appendFile: (filePath, data) => ipcRenderer.invoke('pipe:append-file', { filePath, data })
  },

  // ─── ÉVÉNEMENTS (Écoute depuis le main process) ────────────────────
  on: (channel, callback) => {
    // Liste blanche des événements autorisés depuis le main process
    const allowedEvents = [
      'toggle-command-palette',
      'burn-session-shortcut',
      'toggle-proxy-shortcut',
      'toggle-split-screen',
      'toggle-hacker-panel',
      'toggle-terminal',
      'external-link',
      'proxy-request-intercepted',
      'waf-detected',
      'api-key-leaked',
      'security-header-missing',
      'terminal:data',
      'terminal:exit'
    ];
    if (allowedEvents.includes(channel)) {
      ipcRenderer.on(channel, (event, ...args) => callback(...args));
    }
  },

  // Retirer un écouteur d'événement
  removeListener: (channel, callback) => {
    ipcRenderer.removeListener(channel, callback);
  }
});
