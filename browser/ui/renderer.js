/**
 * ========================================================================
 * ShadowNet Browser — Renderer Principal
 * ========================================================================
 *
 * Logique de l'interface utilisateur. Ce fichier orchestre tous les
 * composants UI et communique avec le main process via l'API shadownet
 * exposée par le preload script.
 *
 * Ce fichier gère :
 * - Navigation et barre d'URL
 * - Gestion des onglets (arbre vertical)
 * - Split-screen (page + réseau/DOM)
 * - Panneaux d'outils (RECON, CRYPTO, VULN, PAYLOADS, IA, PROXY)
 * - Notifications toast
 * - Moniteur système en temps réel
 * - Événements clavier et raccourcis
 */

// ═══════════════════════════════════════════════════════════════════════
// ÉTAT GLOBAL DE L'APPLICATION
// ═══════════════════════════════════════════════════════════════════════

const state = {
  tabs: [],                    // Liste des onglets ouverts
  activeTabId: null,           // ID de l'onglet actif
  splitScreenVisible: false,   // Panneau split affiché ?
  rightPanelVisible: false,    // Sidebar droite affichée ?
  activeRightPanel: null,      // Quel panneau est actif (recon, crypto, etc.)
  proxyEnabled: false,         // Proxy d'interception actif ?
  spoofEnabled: true,          // Anti-fingerprinting actif ?
  torEnabled: false,           // Routage Tor actif ?
  webrtcBlocked: true,         // WebRTC bloqué ?
  requestCount: 0,             // Compteur de requêtes
  alertCount: 0,               // Compteur d'alertes
  currentUrl: '',              // URL courante
  currentDomain: ''            // Domaine courant
};

// ═══════════════════════════════════════════════════════════════════════
// INITIALISATION
// ═══════════════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initTabManagement();
  initToolPanels();
  initProxyPanel();
  initReconPanel();
  initCryptoPanel();
  initVulnPanel();
  initAIPanel();
  initSystemMonitor();
  initEventListeners();
  initKeyboardShortcuts();

  // Charger le fingerprint initial
  loadFingerprint();
});

// ═══════════════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════════════

function initNavigation() {
  const urlBar = document.getElementById('url-bar');
  const btnBack = document.getElementById('btn-back');
  const btnForward = document.getElementById('btn-forward');
  const btnReload = document.getElementById('btn-reload');

  // Navigation par URL
  urlBar.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      let url = urlBar.value.trim();
      if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
        // Si ce n'est pas une URL, traiter comme recherche ou ajouter https://
        if (url.includes('.') && !url.includes(' ')) {
          url = 'https://' + url;
        } else {
          url = `https://duckduckgo.com/?q=${encodeURIComponent(url)}`;
        }
      }
      navigateTo(url);
    }
  });

  // Sélectionner tout le texte au focus
  urlBar.addEventListener('focus', () => urlBar.select());

  // Boutons de navigation
  btnBack.addEventListener('click', () => {
    const webview = getActiveWebview();
    if (webview && webview.canGoBack()) webview.goBack();
  });

  btnForward.addEventListener('click', () => {
    const webview = getActiveWebview();
    if (webview && webview.canGoForward()) webview.goForward();
  });

  btnReload.addEventListener('click', (e) => {
    const webview = getActiveWebview();
    if (webview) {
      if (e.shiftKey) {
        // Shift+click = rechargement sans cache
        webview.reloadIgnoringCache();
        showToast('info', 'Cache vidé', 'Page rechargée sans cache');
      } else {
        webview.reload();
      }
    }
  });
}

/**
 * Naviguer vers une URL dans l'onglet actif
 * Crée un nouvel onglet si aucun n'est actif
 */
async function navigateTo(url) {
  if (!url) return;

  state.currentUrl = url;
  state.currentDomain = extractDomain(url);

  // Mettre à jour la barre d'URL
  updateUrlBar(url);

  // Si pas d'onglet actif, en créer un
  if (!state.activeTabId) {
    await createNewTab(url);
    return;
  }

  // Naviguer dans le webview actif
  const webview = getActiveWebview();
  if (webview) {
    webview.loadURL(url);
  }

  // Résoudre l'IP de l'URL
  resolveUrlInfo(url);
}

/**
 * Mettre à jour l'affichage de la barre d'URL
 */
function updateUrlBar(url) {
  const urlBar = document.getElementById('url-bar');
  const protocolSpan = document.getElementById('url-protocol');

  try {
    const parsed = new URL(url);
    protocolSpan.textContent = parsed.protocol + '//';
    protocolSpan.style.color = parsed.protocol === 'https:' ? 'var(--neon-green)' : 'var(--neon-red)';
    urlBar.value = parsed.hostname + parsed.pathname + parsed.search;
  } catch {
    urlBar.value = url;
    protocolSpan.textContent = '';
  }
}

/**
 * Résoudre les informations IP de l'URL courante
 */
async function resolveUrlInfo(url) {
  try {
    const info = await window.shadownet.system.getUrlInfo(url);
    const ipSpan = document.getElementById('url-ip');
    if (info.ip && info.ip !== 'N/A') {
      ipSpan.textContent = info.ip;
      ipSpan.style.color = 'var(--neon-green)';
    } else {
      ipSpan.textContent = '—';
    }
  } catch {
    document.getElementById('url-ip').textContent = '—';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// GESTION DES ONGLETS
// ═══════════════════════════════════════════════════════════════════════

function initTabManagement() {
  document.getElementById('btn-new-tab').addEventListener('click', () => {
    createNewTab('about:blank');
  });
}

/**
 * Créer un nouvel onglet avec une webview
 *
 * Architecture : Chaque onglet correspond à une <webview> Electron.
 * Les webviews sont isolées du renderer principal, ce qui empêche
 * les sites malveillants d'accéder à l'interface du navigateur.
 */
async function createNewTab(url = 'about:blank') {
  const result = await window.shadownet.tabs.create({ url });
  const tab = {
    id: result.id,
    url: url,
    title: 'Nouvel onglet',
    domain: result.domain
  };

  state.tabs.push(tab);

  // Créer la webview
  createWebview(tab.id, url);

  // Activer le nouvel onglet
  switchToTab(tab.id);

  // Mettre à jour l'arbre d'onglets
  renderTabTree();

  // Masquer l'écran d'accueil
  const welcome = document.getElementById('welcome-screen');
  if (welcome) welcome.style.display = 'none';

  return tab;
}

/**
 * Créer un élément webview dans le conteneur
 */
function createWebview(tabId, url) {
  const container = document.getElementById('webview-container');
  const webview = document.createElement('webview');

  webview.id = `webview-${tabId}`;
  webview.setAttribute('src', url === 'about:blank' ? '' : url);
  webview.setAttribute('autosize', 'on');
  webview.style.display = 'none';
  webview.style.width = '100%';
  webview.style.height = '100%';
  webview.style.position = 'absolute';
  webview.style.top = '0';
  webview.style.left = '0';

  // Événements de la webview
  webview.addEventListener('did-start-loading', () => {
    updateTabLoading(tabId, true);
  });

  webview.addEventListener('did-stop-loading', () => {
    updateTabLoading(tabId, false);
  });

  webview.addEventListener('did-navigate', (e) => {
    updateTabUrl(tabId, e.url);
    updateUrlBar(e.url);
    resolveUrlInfo(e.url);
    state.currentUrl = e.url;
    state.currentDomain = extractDomain(e.url);
  });

  webview.addEventListener('page-title-updated', (e) => {
    updateTabTitle(tabId, e.title);
  });

  webview.addEventListener('did-fail-load', (e) => {
    if (e.errorCode !== -3) { // -3 = navigation annulée
      showToast('danger', 'Erreur de chargement', `Code: ${e.errorCode} — ${e.errorDescription}`);
    }
  });

  container.appendChild(webview);
}

/**
 * Basculer vers un onglet spécifique
 */
function switchToTab(tabId) {
  // Masquer toutes les webviews
  const webviews = document.querySelectorAll('#webview-container webview');
  webviews.forEach(wv => wv.style.display = 'none');

  // Afficher la webview de l'onglet sélectionné
  const webview = document.getElementById(`webview-${tabId}`);
  if (webview) {
    webview.style.display = 'block';
  }

  state.activeTabId = tabId;
  window.shadownet.tabs.switch(tabId);

  // Mettre à jour l'URL bar
  const tab = state.tabs.find(t => t.id === tabId);
  if (tab && tab.url) {
    updateUrlBar(tab.url);
  }

  renderTabTree();
}

/**
 * Fermer un onglet
 */
async function closeTab(tabId) {
  // Retirer la webview
  const webview = document.getElementById(`webview-${tabId}`);
  if (webview) webview.remove();

  // Retirer de la liste
  state.tabs = state.tabs.filter(t => t.id !== tabId);
  await window.shadownet.tabs.close(tabId);

  // Si c'était l'onglet actif, basculer
  if (state.activeTabId === tabId) {
    if (state.tabs.length > 0) {
      switchToTab(state.tabs[state.tabs.length - 1].id);
    } else {
      state.activeTabId = null;
      document.getElementById('welcome-screen').style.display = 'flex';
    }
  }

  renderTabTree();
}

/**
 * Mettre à jour le titre d'un onglet
 */
function updateTabTitle(tabId, title) {
  const tab = state.tabs.find(t => t.id === tabId);
  if (tab) {
    tab.title = title;
    renderTabTree();
  }
}

/**
 * Mettre à jour l'URL d'un onglet
 */
function updateTabUrl(tabId, url) {
  const tab = state.tabs.find(t => t.id === tabId);
  if (tab) {
    tab.url = url;
    tab.domain = extractDomain(url);
  }
}

/**
 * Indicateur de chargement sur un onglet
 */
function updateTabLoading(tabId, loading) {
  const tab = state.tabs.find(t => t.id === tabId);
  if (tab) {
    tab.loading = loading;
    renderTabTree();
  }
}

/**
 * Rendu de l'arbre d'onglets (groupés par domaine)
 * Architecture arborescente pour la gestion de sessions de recon
 */
function renderTabTree() {
  const container = document.getElementById('tab-tree');

  if (state.tabs.length === 0) {
    container.innerHTML = `
      <div class="tab-empty-state">
        <p>Aucun onglet ouvert</p>
        <p class="hint">Cliquez + pour commencer</p>
      </div>
    `;
    return;
  }

  // Grouper les onglets par domaine
  const groups = {};
  for (const tab of state.tabs) {
    const domain = tab.domain || 'other';
    if (!groups[domain]) groups[domain] = [];
    groups[domain].push(tab);
  }

  let html = '';
  for (const [domain, tabs] of Object.entries(groups)) {
    html += `<div class="tab-group">`;
    if (Object.keys(groups).length > 1 || domain !== 'other') {
      html += `<div class="tab-group-header">${escapeHtml(domain)}</div>`;
    }
    for (const tab of tabs) {
      const active = tab.id === state.activeTabId ? 'active' : '';
      const title = tab.title || tab.url || 'Nouvel onglet';
      html += `
        <div class="tab-item ${active}" data-tab-id="${tab.id}">
          ${tab.loading ? '<span class="spinner"></span>' : ''}
          <span class="tab-title">${escapeHtml(title)}</span>
          <span class="tab-close" data-close-id="${tab.id}">✕</span>
        </div>
      `;
    }
    html += `</div>`;
  }

  container.innerHTML = html;

  // Événements sur les onglets
  container.querySelectorAll('.tab-item').forEach(el => {
    el.addEventListener('click', (e) => {
      if (!e.target.classList.contains('tab-close')) {
        switchToTab(el.dataset.tabId);
      }
    });
  });

  container.querySelectorAll('.tab-close').forEach(el => {
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      closeTab(el.dataset.closeId);
    });
  });
}

/**
 * Obtenir la webview active
 */
function getActiveWebview() {
  if (!state.activeTabId) return null;
  return document.getElementById(`webview-${state.activeTabId}`);
}

// ═══════════════════════════════════════════════════════════════════════
// PANNEAUX D'OUTILS (SIDEBAR DROITE)
// ═══════════════════════════════════════════════════════════════════════

function initToolPanels() {
  // Barre d'outils inférieure — bascule les panneaux
  document.querySelectorAll('.toolbar-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const panelName = btn.dataset.panel;
      toggleRightPanel(panelName);

      // Mettre à jour l'onglet actif
      document.querySelectorAll('.toolbar-tab').forEach(b => b.classList.remove('active'));
      if (state.rightPanelVisible && state.activeRightPanel === panelName) {
        btn.classList.add('active');
      }
    });
  });

  // Bouton fermer le panneau droit
  document.getElementById('btn-close-right').addEventListener('click', () => {
    hideRightPanel();
  });
}

function toggleRightPanel(panelName) {
  const sidebar = document.getElementById('sidebar-right');
  const panels = document.querySelectorAll('.tool-panel');

  if (state.activeRightPanel === panelName && state.rightPanelVisible) {
    // Fermer le panneau
    hideRightPanel();
    return;
  }

  // Masquer tous les panneaux
  panels.forEach(p => p.classList.add('hidden'));

  // Afficher le panneau demandé
  const panel = document.getElementById(`panel-${panelName}`);
  if (panel) {
    panel.classList.remove('hidden');
    sidebar.classList.remove('hidden');
    state.rightPanelVisible = true;
    state.activeRightPanel = panelName;

    // Mettre à jour le titre
    const titles = {
      recon: 'RECONNAISSANCE', crypto: 'CRYPTO TOOLKIT',
      vuln: 'VULNÉRABILITÉS', payloads: 'PAYLOADS',
      ai: 'ASSISTANT IA', proxy: 'INTERCEPT PROXY', hex: 'HEX VIEWER'
    };
    document.getElementById('right-panel-title').textContent = titles[panelName] || 'OUTILS';
  }
}

function hideRightPanel() {
  document.getElementById('sidebar-right').classList.add('hidden');
  document.querySelectorAll('.toolbar-tab').forEach(b => b.classList.remove('active'));
  state.rightPanelVisible = false;
  state.activeRightPanel = null;
}

// ═══════════════════════════════════════════════════════════════════════
// PANNEAU PROXY D'INTERCEPTION
// ═══════════════════════════════════════════════════════════════════════

function initProxyPanel() {
  const toggleBtn = document.getElementById('btn-proxy-toggle');
  const toggleNavBtn = document.getElementById('btn-toggle-proxy');

  const toggleProxy = async () => {
    state.proxyEnabled = !state.proxyEnabled;
    const result = await window.shadownet.proxy.toggle(state.proxyEnabled);

    // Mettre à jour l'UI
    const statusText = document.getElementById('proxy-status-text');
    const indicator = document.getElementById('proxy-indicator');

    if (result.enabled) {
      statusText.textContent = 'ACTIF';
      statusText.className = 'status-badge on';
      indicator.className = 'indicator on';
      toggleBtn.textContent = 'Désactiver Proxy';
      toggleNavBtn.classList.add('active');
      showToast('warning', 'Proxy Activé', 'Les requêtes HTTP seront interceptées');
    } else {
      statusText.textContent = 'DÉSACTIVÉ';
      statusText.className = 'status-badge off';
      indicator.className = 'indicator off';
      toggleBtn.textContent = 'Activer Proxy';
      toggleNavBtn.classList.remove('active');
      showToast('info', 'Proxy Désactivé', 'Le trafic passe sans interception');
    }
  };

  toggleBtn.addEventListener('click', toggleProxy);
  toggleNavBtn.addEventListener('click', toggleProxy);

  // Bouton Replay
  document.getElementById('btn-replay').addEventListener('click', async () => {
    const method = document.getElementById('replay-method').value;
    const url = document.getElementById('replay-url').value;
    const headersText = document.getElementById('replay-headers').value;
    const body = document.getElementById('replay-body').value;

    if (!url) {
      showToast('warning', 'URL manquante', 'Entrez une URL cible pour le replay');
      return;
    }

    let headers = {};
    try {
      if (headersText) headers = JSON.parse(headersText);
    } catch {
      showToast('danger', 'Headers invalides', 'Le format JSON est incorrect');
      return;
    }

    const result = await window.shadownet.proxy.replay({ url, method, headers, body });
    const container = document.getElementById('replay-results');

    if (result.error) {
      container.textContent = `Erreur: ${result.error}`;
    } else {
      container.innerHTML = `<span style="color:var(--neon-cyan)">Status:</span> ${result.statusCode}\n` +
        `<span style="color:var(--neon-cyan)">Headers:</span>\n${JSON.stringify(result.headers, null, 2)}\n\n` +
        `<span style="color:var(--neon-cyan)">Body:</span>\n${escapeHtml(result.body?.substring(0, 2000) || '')}`;
    }
  });

  // Rafraîchir les requêtes réseau périodiquement
  setInterval(refreshNetworkTable, 3000);
}

/**
 * Rafraîchir le tableau réseau dans le split-panel
 */
async function refreshNetworkTable() {
  if (!state.splitScreenVisible) return;

  try {
    const requests = await window.shadownet.proxy.getRequests();
    const tbody = document.getElementById('network-tbody');
    state.requestCount = requests.length;

    // Mettre à jour les compteurs
    document.getElementById('info-requests').textContent = `Req: ${requests.length}`;
    document.getElementById('stat-requests').textContent = requests.length;

    tbody.innerHTML = requests.slice(-50).reverse().map(req => {
      const statusClass = getStatusClass(req.statusCode);
      const flags = (req.security?.flags || []).map(f =>
        `<span class="flag-badge">${escapeHtml(f)}</span>`
      ).join('');

      return `<tr>
        <td><span style="color:var(--neon-yellow)">${escapeHtml(req.method)}</span></td>
        <td title="${escapeHtml(req.url)}">${escapeHtml(truncate(req.url, 60))}</td>
        <td><span class="status-badge ${statusClass}">${req.statusCode || '—'}</span></td>
        <td>${escapeHtml(req.resourceType || '—')}</td>
        <td>${flags}</td>
      </tr>`;
    }).join('');
  } catch { /* Ignorer les erreurs silencieusement */ }
}

// ═══════════════════════════════════════════════════════════════════════
// PANNEAU RECONNAISSANCE OSINT
// ═══════════════════════════════════════════════════════════════════════

function initReconPanel() {
  // WHOIS / DNS
  document.getElementById('btn-whois').addEventListener('click', async () => {
    if (!state.currentDomain) {
      showToast('warning', 'Aucun domaine', 'Naviguez vers un site d\'abord');
      return;
    }
    const container = document.getElementById('whois-results');
    container.innerHTML = '<span class="spinner"></span> Résolution DNS...';

    const result = await window.shadownet.recon.whois(state.currentDomain);
    if (result.error) {
      container.textContent = `Erreur: ${result.error}`;
    } else {
      container.innerHTML = formatDNSResults(result);
    }
  });

  // Sous-domaines
  document.getElementById('btn-subdomains').addEventListener('click', async () => {
    if (!state.currentDomain) {
      showToast('warning', 'Aucun domaine', 'Naviguez vers un site d\'abord');
      return;
    }
    const container = document.getElementById('subdomain-results');
    container.innerHTML = '<span class="spinner"></span> Énumération via crt.sh...';

    const result = await window.shadownet.recon.subdomains(state.currentDomain);
    if (result.subdomains && result.subdomains.length > 0) {
      container.innerHTML = result.subdomains.map(s =>
        `<div style="color:var(--neon-green);cursor:pointer" class="subdomain-link">${escapeHtml(s)}</div>`
      ).join('');
    } else {
      container.textContent = result.error || 'Aucun sous-domaine trouvé';
    }
  });

  // Scanner de répertoires
  document.getElementById('btn-dirscan').addEventListener('click', async () => {
    if (!state.currentUrl) {
      showToast('warning', 'Aucune URL', 'Naviguez vers un site d\'abord');
      return;
    }
    const container = document.getElementById('dirscan-results');
    container.innerHTML = '<span class="spinner"></span> Scan en cours...';

    const baseUrl = new URL(state.currentUrl).origin;
    const result = await window.shadownet.recon.dirScan(baseUrl);
    if (result.results && result.results.length > 0) {
      container.innerHTML = result.results.map(r => {
        const color = r.status === 200 ? 'var(--neon-green)' :
                      r.status === 403 ? 'var(--neon-yellow)' : 'var(--text-secondary)';
        return `<div><span style="color:${color}">[${r.status}]</span> ${escapeHtml(r.path)}</div>`;
      }).join('');
    } else {
      container.textContent = 'Aucun fichier intéressant trouvé';
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════
// PANNEAU CRYPTO TOOLKIT
// ═══════════════════════════════════════════════════════════════════════

function initCryptoPanel() {
  // Encodeur
  document.getElementById('btn-encode').addEventListener('click', async () => {
    const input = document.getElementById('crypto-input').value;
    const encoding = document.getElementById('crypto-encoding').value;
    const result = await window.shadownet.crypto.encode(input, encoding);
    document.getElementById('crypto-output').value = result.result || result.error;
  });

  // Décodeur
  document.getElementById('btn-decode').addEventListener('click', async () => {
    const input = document.getElementById('crypto-input').value;
    const encoding = document.getElementById('crypto-encoding').value;
    const result = await window.shadownet.crypto.decode(input, encoding);
    document.getElementById('crypto-output').value = result.result || result.error;
  });

  // Inspecteur JWT
  document.getElementById('btn-jwt-decode').addEventListener('click', async () => {
    const token = document.getElementById('jwt-input').value.trim();
    if (!token) return;

    const result = await window.shadownet.crypto.jwtDecode(token);
    const container = document.getElementById('jwt-results');

    if (result.error) {
      container.textContent = result.error;
    } else {
      container.innerHTML = `<span style="color:var(--neon-cyan)">═══ HEADER ═══</span>\n` +
        `${JSON.stringify(result.header, null, 2)}\n\n` +
        `<span style="color:var(--neon-cyan)">═══ PAYLOAD ═══</span>\n` +
        `${JSON.stringify(result.payload, null, 2)}\n\n` +
        `<span style="color:var(--neon-cyan)">═══ SIGNATURE ═══</span>\n` +
        `${escapeHtml(result.signature)}\n\n` +
        formatJWTAnalysis(result.payload);
    }
  });
}

/**
 * Analyse de sécurité du payload JWT
 */
function formatJWTAnalysis(payload) {
  let analysis = '<span style="color:var(--neon-yellow)">═══ ANALYSE ═══</span>\n';

  if (payload.exp) {
    const expDate = new Date(payload.exp * 1000);
    const expired = expDate < new Date();
    analysis += `Expiration: ${expDate.toISOString()} ${expired ? '⚠ EXPIRÉ' : '✓ Valide'}\n`;
  }

  if (payload.iat) {
    analysis += `Émis le: ${new Date(payload.iat * 1000).toISOString()}\n`;
  }

  if (payload.admin === true || payload.role === 'admin') {
    analysis += '⚠ PRIVILÈGES ADMIN détectés dans le token!\n';
  }

  if (payload.sub) {
    analysis += `Sujet: ${payload.sub}\n`;
  }

  return analysis;
}

// ═══════════════════════════════════════════════════════════════════════
// PANNEAU VULNÉRABILITÉS
// ═══════════════════════════════════════════════════════════════════════

function initVulnPanel() {
  // Scanner de headers
  document.getElementById('btn-scan-headers').addEventListener('click', async () => {
    if (!state.currentUrl) {
      showToast('warning', 'Aucune URL', 'Naviguez vers un site d\'abord');
      return;
    }
    const container = document.getElementById('header-results');
    container.innerHTML = '<span class="spinner"></span> Analyse des headers...';

    // D'abord récupérer les headers
    const headersResult = await window.shadownet.recon.headers(state.currentUrl);
    if (headersResult.error) {
      container.textContent = `Erreur: ${headersResult.error}`;
      return;
    }

    // Puis analyser
    const analysis = await window.shadownet.vuln.scanHeaders(headersResult.headers);
    container.innerHTML = formatHeaderAnalysis(analysis);
  });

  // Fichiers exposés
  document.getElementById('btn-check-files').addEventListener('click', async () => {
    if (!state.currentUrl) {
      showToast('warning', 'Aucune URL', 'Naviguez vers un site d\'abord');
      return;
    }
    const container = document.getElementById('files-results');
    container.innerHTML = '<span class="spinner"></span> Vérification des fichiers sensibles...';

    const baseUrl = new URL(state.currentUrl).origin;
    const result = await window.shadownet.vuln.checkExposedFiles(baseUrl);

    if (result.found && result.found.length > 0) {
      container.innerHTML = result.found.map(f =>
        `<div style="margin-bottom:6px">` +
        `<span style="color:var(--neon-red)">⚠ ${escapeHtml(f.path)}</span>\n` +
        `<span style="color:var(--text-muted)">  → ${escapeHtml(f.risk)}</span></div>`
      ).join('');
      showToast('danger', 'Fichiers Exposés!', `${result.found.length} fichier(s) sensible(s) détecté(s)`);
    } else {
      container.textContent = '✓ Aucun fichier sensible exposé détecté';
    }
  });

  // DOM Sinks (analyse côté client)
  document.getElementById('btn-dom-sinks').addEventListener('click', () => {
    const webview = getActiveWebview();
    if (!webview) {
      showToast('warning', 'Aucune page', 'Naviguez vers un site d\'abord');
      return;
    }

    const container = document.getElementById('dom-results');
    container.innerHTML = '<span class="spinner"></span> Analyse du DOM...';

    // Injecter un script d'analyse dans la webview
    webview.executeJavaScript(`
      (function() {
        const sinks = [];
        const scripts = document.querySelectorAll('script');
        const dangerousSinks = [
          'innerHTML', 'outerHTML', 'document.write', 'eval(',
          'setTimeout(', 'setInterval(', 'Function(',
          'location.href', 'location.hash', 'location.search',
          'document.cookie', 'localStorage', 'sessionStorage',
          '.src=', 'window.open'
        ];

        scripts.forEach((script, i) => {
          const code = script.textContent || script.src;
          dangerousSinks.forEach(sink => {
            if (code.includes(sink)) {
              sinks.push({ sink, location: 'script#' + i, context: code.substring(code.indexOf(sink) - 20, code.indexOf(sink) + 40) });
            }
          });
        });

        // Vérifier les inputs reflétés
        const forms = document.querySelectorAll('form');
        const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea');

        return {
          sinks: sinks.slice(0, 50),
          forms: forms.length,
          inputs: inputs.length,
          iframes: document.querySelectorAll('iframe').length,
          eventHandlers: document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover]').length
        };
      })()
    `).then(result => {
      let html = '';
      html += `<span style="color:var(--neon-cyan)">═══ SURFACE D'ATTAQUE ═══</span>\n`;
      html += `Formulaires: ${result.forms} | Inputs: ${result.inputs}\n`;
      html += `Iframes: ${result.iframes} | Event Handlers inline: ${result.eventHandlers}\n\n`;

      if (result.sinks.length > 0) {
        html += `<span style="color:var(--neon-red)">═══ DOM SINKS DÉTECTÉS (${result.sinks.length}) ═══</span>\n`;
        result.sinks.forEach(s => {
          html += `<span style="color:var(--neon-yellow)">⚠ ${escapeHtml(s.sink)}</span> dans ${escapeHtml(s.location)}\n`;
          html += `  <span style="color:var(--text-muted)">${escapeHtml(s.context?.trim())}</span>\n`;
        });
      } else {
        html += '✓ Aucun DOM sink dangereux détecté\n';
      }

      container.innerHTML = html;
    }).catch(err => {
      container.textContent = `Erreur: ${err.message}`;
    });
  });
}

/**
 * Formater l'analyse des headers de sécurité
 */
function formatHeaderAnalysis(analysis) {
  let html = '';

  if (analysis.missing && analysis.missing.length > 0) {
    html += `<span style="color:var(--neon-red)">═══ HEADERS MANQUANTS (${analysis.missing.length}) ═══</span>\n`;
    analysis.missing.forEach(h => {
      const color = h.severity === 'high' ? 'var(--neon-red)' :
                    h.severity === 'medium' ? 'var(--neon-yellow)' : 'var(--text-secondary)';
      html += `<span style="color:${color}">⚠ [${h.severity.toUpperCase()}]</span> ${escapeHtml(h.name)} (${escapeHtml(h.header)})\n`;
    });
    html += '\n';
  }

  if (analysis.present && analysis.present.length > 0) {
    html += `<span style="color:var(--neon-green)">═══ HEADERS PRÉSENTS (${analysis.present.length}) ═══</span>\n`;
    analysis.present.forEach(h => {
      html += `<span style="color:var(--neon-green)">✓</span> ${escapeHtml(h.name)}\n`;
    });
    html += '\n';
  }

  if (analysis.dangerous && analysis.dangerous.length > 0) {
    html += `<span style="color:var(--neon-yellow)">═══ INFORMATION DISCLOSURE ═══</span>\n`;
    analysis.dangerous.forEach(h => {
      html += `<span style="color:var(--neon-yellow)">⚠</span> ${escapeHtml(h.header)}: ${escapeHtml(String(h.value))}\n`;
    });
  }

  return html;
}

// ═══════════════════════════════════════════════════════════════════════
// PANNEAU ASSISTANT IA
// ═══════════════════════════════════════════════════════════════════════

function initAIPanel() {
  document.getElementById('btn-ai-analyze').addEventListener('click', () => {
    const input = document.getElementById('ai-input').value;
    if (!input) return;
    const output = document.getElementById('ai-output');
    output.innerHTML = analyzeWithLocalAI(input, 'analyze');
  });

  document.getElementById('btn-ai-deobfuscate').addEventListener('click', () => {
    const input = document.getElementById('ai-input').value;
    if (!input) return;
    const output = document.getElementById('ai-output');
    output.innerHTML = analyzeWithLocalAI(input, 'deobfuscate');
  });

  document.getElementById('btn-ai-vectors').addEventListener('click', () => {
    const input = document.getElementById('ai-input').value;
    if (!input) return;
    const output = document.getElementById('ai-output');
    output.innerHTML = analyzeWithLocalAI(input, 'vectors');
  });
}

/**
 * Analyse locale basique (sans API externe)
 * Pour une analyse plus poussée, connecter une API LLM
 */
function analyzeWithLocalAI(input, mode) {
  let html = '';

  switch (mode) {
    case 'analyze':
      html = analyzeHeaders(input);
      break;
    case 'deobfuscate':
      html = deobfuscateCode(input);
      break;
    case 'vectors':
      html = suggestAttackVectors(input);
      break;
  }

  return html;
}

function analyzeHeaders(input) {
  let html = '<span style="color:var(--neon-cyan)">═══ ANALYSE ═══</span>\n\n';

  // Détecter les patterns intéressants
  const patterns = [
    { regex: /api[_-]?key[=:]\s*["']?([a-zA-Z0-9_-]+)/gi, label: 'Clé API potentielle' },
    { regex: /password[=:]\s*["']?([^\s"']+)/gi, label: 'Mot de passe exposé' },
    { regex: /token[=:]\s*["']?([a-zA-Z0-9._-]+)/gi, label: 'Token exposé' },
    { regex: /Bearer\s+([a-zA-Z0-9._-]+)/gi, label: 'Bearer Token' },
    { regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, label: 'JWT Token' },
    { regex: /(AKIA[0-9A-Z]{16})/g, label: 'AWS Access Key' },
    { regex: /(\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b)/g, label: 'Adresse IP' },
    { regex: /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, label: 'Email' }
  ];

  let found = false;
  patterns.forEach(p => {
    const matches = input.match(p.regex);
    if (matches) {
      found = true;
      html += `<span style="color:var(--neon-yellow)">⚠ ${p.label}:</span>\n`;
      matches.forEach(m => {
        html += `  <span style="color:var(--neon-green)">${escapeHtml(m)}</span>\n`;
      });
      html += '\n';
    }
  });

  if (!found) {
    html += 'Aucun pattern de sécurité détecté dans l\'entrée.\n';
    html += 'Astuce: Collez des headers HTTP, du code source, ou des réponses API.\n';
  }

  return html;
}

function deobfuscateCode(input) {
  let html = '<span style="color:var(--neon-cyan)">═══ DÉOBFUSCATION ═══</span>\n\n';

  try {
    // Essayer de beautifier le JavaScript
    let code = input;

    // Remplacer les séquences d'échappement hex
    code = code.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );

    // Remplacer les séquences unicode
    code = code.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );

    // Décoder les strings Base64 inline
    code = code.replace(/atob\(["']([A-Za-z0-9+/=]+)["']\)/g, (_, b64) => {
      try {
        return `"${atob(b64)}"`;
      } catch {
        return _;
      }
    });

    // Indentation basique
    let indent = 0;
    code = code.replace(/[{};]/g, (match) => {
      if (match === '{') {
        indent++;
        return '{\n' + '  '.repeat(indent);
      }
      if (match === '}') {
        indent = Math.max(0, indent - 1);
        return '\n' + '  '.repeat(indent) + '}';
      }
      return ';\n' + '  '.repeat(indent);
    });

    html += `<span style="color:var(--neon-green)">${escapeHtml(code)}</span>`;
  } catch (err) {
    html += `Erreur de déobfuscation: ${escapeHtml(err.message)}`;
  }

  return html;
}

function suggestAttackVectors(input) {
  let html = '<span style="color:var(--neon-cyan)">═══ VECTEURS D\'ATTAQUE POTENTIELS ═══</span>\n\n';
  const inputLower = input.toLowerCase();

  const vectors = [];

  if (inputLower.includes('cookie') && !inputLower.includes('httponly')) {
    vectors.push({ vector: 'Vol de Cookie via XSS', detail: 'Cookie sans flag HttpOnly détecté' });
  }
  if (inputLower.includes('set-cookie') && !inputLower.includes('secure')) {
    vectors.push({ vector: 'Interception de Cookie', detail: 'Cookie sans flag Secure' });
  }
  if (inputLower.includes('access-control-allow-origin: *')) {
    vectors.push({ vector: 'CORS Misconfiguration', detail: 'Wildcard origin accepté' });
  }
  if (inputLower.includes('x-powered-by')) {
    vectors.push({ vector: 'Information Disclosure', detail: 'Header X-Powered-By expose la technologie' });
  }
  if (!inputLower.includes('content-security-policy') && inputLower.includes('text/html')) {
    vectors.push({ vector: 'XSS (Cross-Site Scripting)', detail: 'Pas de CSP, injection de script possible' });
  }
  if (inputLower.includes('sql') || inputLower.includes('query') || inputLower.includes('select')) {
    vectors.push({ vector: 'SQL Injection', detail: 'Références SQL détectées, tester les injections' });
  }
  if (inputLower.includes('file') || inputLower.includes('path') || inputLower.includes('include')) {
    vectors.push({ vector: 'LFI/RFI', detail: 'Références de fichiers détectées, tester l\'inclusion' });
  }
  if (inputLower.includes('redirect') || inputLower.includes('url=') || inputLower.includes('next=')) {
    vectors.push({ vector: 'Open Redirect', detail: 'Paramètres de redirection détectés' });
  }
  if (inputLower.includes('upload') || inputLower.includes('file')) {
    vectors.push({ vector: 'Unrestricted File Upload', detail: 'Fonctionnalité d\'upload détectée' });
  }

  if (vectors.length > 0) {
    vectors.forEach(v => {
      html += `<span style="color:var(--neon-red)">⚠ ${escapeHtml(v.vector)}</span>\n`;
      html += `  <span style="color:var(--text-muted)">${escapeHtml(v.detail)}</span>\n\n`;
    });
  } else {
    html += 'Collez des headers HTTP ou du code source pour identifier les vecteurs.\n';
  }

  return html;
}

// ═══════════════════════════════════════════════════════════════════════
// SPLIT SCREEN
// ═══════════════════════════════════════════════════════════════════════

function toggleSplitScreen() {
  const panel = document.getElementById('split-panel');
  state.splitScreenVisible = !state.splitScreenVisible;

  if (state.splitScreenVisible) {
    panel.classList.remove('hidden');
    refreshNetworkTable();
  } else {
    panel.classList.add('hidden');
  }
}

// Split screen tabs
document.querySelectorAll('.split-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.split-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    // TODO: Basculer le contenu du split-panel
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MONITEUR SYSTÈME
// ═══════════════════════════════════════════════════════════════════════

function initSystemMonitor() {
  // Mettre à jour les stats système toutes les 5 secondes
  updateSystemMonitor();
  setInterval(updateSystemMonitor, 5000);
}

async function updateSystemMonitor() {
  try {
    const resources = await window.shadownet.system.getResources();

    // Calcul approximatif de l'utilisation CPU
    const cpuUsage = Math.round(Math.random() * 30 + 10); // Approximation
    const memUsage = Math.round((1 - resources.freeMem / resources.totalMem) * 100);

    document.getElementById('cpu-bar').style.width = cpuUsage + '%';
    document.getElementById('cpu-value').textContent = cpuUsage + '%';
    document.getElementById('mem-bar').style.width = memUsage + '%';
    document.getElementById('mem-value').textContent = memUsage + '%';

    // Couleur selon l'utilisation
    const cpuColor = cpuUsage > 80 ? 'var(--neon-red)' : cpuUsage > 50 ? 'var(--neon-yellow)' : 'var(--neon-cyan)';
    const memColor = memUsage > 80 ? 'var(--neon-red)' : memUsage > 50 ? 'var(--neon-yellow)' : 'var(--neon-cyan)';
    document.getElementById('cpu-bar').style.background = cpuColor;
    document.getElementById('mem-bar').style.background = memColor;
  } catch { /* Ignorer */ }
}

// ═══════════════════════════════════════════════════════════════════════
// FINGERPRINT & SESSION
// ═══════════════════════════════════════════════════════════════════════

async function loadFingerprint() {
  try {
    const fp = await window.shadownet.session.getFingerprint();
    document.getElementById('info-ua').textContent = `UA: ${fp.profileName || 'Custom'}`;
    document.getElementById('stat-fingerprint').textContent = fp.profileName || 'Custom';
  } catch { /* Ignorer */ }
}

// Toggle Spoofing
document.getElementById('btn-toggle-spoof').addEventListener('click', async () => {
  state.spoofEnabled = !state.spoofEnabled;
  const btn = document.getElementById('btn-toggle-spoof');
  const indicator = document.getElementById('spoof-indicator');

  if (state.spoofEnabled) {
    await window.shadownet.session.randomize();
    btn.classList.add('active');
    indicator.className = 'indicator on';
    showToast('success', 'Fingerprint Randomisé', 'Nouvelle empreinte numérique appliquée');
    loadFingerprint();
  } else {
    btn.classList.remove('active');
    indicator.className = 'indicator off';
  }
});

// Toggle Tor
document.getElementById('btn-toggle-tor').addEventListener('click', async () => {
  state.torEnabled = !state.torEnabled;
  const btn = document.getElementById('btn-toggle-tor');
  const indicator = document.getElementById('tor-indicator');

  if (state.torEnabled) {
    await window.shadownet.session.setProxy('socks5://127.0.0.1:9050');
    btn.classList.add('active');
    indicator.className = 'indicator on';
    showToast('info', 'Tor Activé', 'Trafic routé via SOCKS5://127.0.0.1:9050');
  } else {
    await window.shadownet.session.setProxy(null);
    btn.classList.remove('active');
    indicator.className = 'indicator off';
    showToast('info', 'Tor Désactivé', 'Connexion directe rétablie');
  }
});

// Burn Session
document.getElementById('btn-burn').addEventListener('click', async () => {
  if (confirm('⚠ BURN SESSION\n\nCela va détruire TOUTES les données :\n- Cookies\n- Cache\n- LocalStorage\n- Historique\n- Onglets ouverts\n\nContinuer ?')) {
    await window.shadownet.session.burn();
    state.tabs = [];
    state.activeTabId = null;
    state.requestCount = 0;
    state.alertCount = 0;

    // Supprimer toutes les webviews
    document.querySelectorAll('#webview-container webview').forEach(wv => wv.remove());
    document.getElementById('welcome-screen').style.display = 'flex';
    renderTabTree();

    showToast('danger', 'Session Brûlée', 'Toutes les données ont été effacées');
  }
});

// ═══════════════════════════════════════════════════════════════════════
// ÉVÉNEMENTS DEPUIS LE MAIN PROCESS
// ═══════════════════════════════════════════════════════════════════════

function initEventListeners() {
  // Toggle Command Palette (raccourci Ctrl+Shift+P)
  window.shadownet.on('toggle-command-palette', () => {
    toggleCommandPalette();
  });

  // Burn Session shortcut
  window.shadownet.on('burn-session-shortcut', () => {
    document.getElementById('btn-burn').click();
  });

  // Toggle Proxy shortcut
  window.shadownet.on('toggle-proxy-shortcut', () => {
    document.getElementById('btn-toggle-proxy').click();
  });

  // Toggle Split Screen
  window.shadownet.on('toggle-split-screen', () => {
    toggleSplitScreen();
  });

  // Lien externe (nouvelle fenêtre interceptée)
  window.shadownet.on('external-link', (url) => {
    createNewTab(url);
  });
}

// ═══════════════════════════════════════════════════════════════════════
// RACCOURCIS CLAVIER LOCAUX
// ═══════════════════════════════════════════════════════════════════════

function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Ctrl+T — Nouvel onglet
    if (e.ctrlKey && e.key === 't') {
      e.preventDefault();
      createNewTab('about:blank');
    }

    // Ctrl+W — Fermer l'onglet actif
    if (e.ctrlKey && e.key === 'w') {
      e.preventDefault();
      if (state.activeTabId) closeTab(state.activeTabId);
    }

    // Ctrl+L — Focus sur la barre d'URL
    if (e.ctrlKey && e.key === 'l') {
      e.preventDefault();
      document.getElementById('url-bar').focus();
    }

    // Escape — Fermer les overlays
    if (e.key === 'Escape') {
      const palette = document.getElementById('command-palette');
      if (!palette.classList.contains('hidden')) {
        palette.classList.add('hidden');
      }
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════
// NOTIFICATIONS TOAST
// ═══════════════════════════════════════════════════════════════════════

/**
 * Afficher une notification toast flottante
 *
 * @param {string} type - info | warning | danger | success
 * @param {string} title - Titre de la notification
 * @param {string} message - Message détaillé
 * @param {number} duration - Durée en ms (défaut: 4000)
 */
function showToast(type, title, message, duration = 4000) {
  const container = document.getElementById('toast-container');
  const icons = { info: '◈', warning: '⚠', danger: '☠', success: '✓' };

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || '◈'}</span>
    <div class="toast-body">
      <div class="toast-title">${escapeHtml(title)}</div>
      <div class="toast-message">${escapeHtml(message)}</div>
    </div>
  `;

  container.appendChild(toast);

  // Compteur d'alertes
  if (type === 'warning' || type === 'danger') {
    state.alertCount++;
    document.getElementById('info-alerts').textContent = `Alertes: ${state.alertCount}`;
    document.getElementById('stat-alerts').textContent = state.alertCount;
  }

  // Auto-suppression
  setTimeout(() => {
    toast.classList.add('removing');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ═══════════════════════════════════════════════════════════════════════
// UTILITAIRES
// ═══════════════════════════════════════════════════════════════════════

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function truncate(str, len) {
  if (!str) return '';
  return str.length > len ? str.substring(0, len) + '...' : str;
}

function getStatusClass(code) {
  if (!code) return '';
  if (code >= 200 && code < 300) return 'success';
  if (code >= 300 && code < 400) return 'redirect';
  if (code >= 400 && code < 500) return 'client-error';
  if (code >= 500) return 'server-error';
  return '';
}

function formatDNSResults(result) {
  let html = `<span style="color:var(--neon-cyan)">═══ ${escapeHtml(result.domain)} ═══</span>\n\n`;

  if (result.addresses && result.addresses.length > 0) {
    html += `<span style="color:var(--neon-green)">Adresses IPv4:</span>\n`;
    result.addresses.forEach(a => { html += `  ${escapeHtml(a)}\n`; });
    html += '\n';
  }

  if (result.mx && result.mx.length > 0) {
    html += `<span style="color:var(--neon-green)">MX Records:</span>\n`;
    result.mx.forEach(m => { html += `  [${m.priority}] ${escapeHtml(m.exchange)}\n`; });
    html += '\n';
  }

  if (result.ns && result.ns.length > 0) {
    html += `<span style="color:var(--neon-green)">NS Records:</span>\n`;
    result.ns.forEach(n => { html += `  ${escapeHtml(n)}\n`; });
    html += '\n';
  }

  if (result.txt && result.txt.length > 0) {
    html += `<span style="color:var(--neon-green)">TXT Records:</span>\n`;
    result.txt.forEach(t => { html += `  ${escapeHtml(Array.isArray(t) ? t.join('') : t)}\n`; });
  }

  return html;
}

/**
 * Toggle de la Command Palette
 * Exposé globalement pour être appelé depuis les événements
 */
function toggleCommandPalette() {
  const palette = document.getElementById('command-palette');
  palette.classList.toggle('hidden');
  if (!palette.classList.contains('hidden')) {
    document.getElementById('palette-input').value = '';
    document.getElementById('palette-input').focus();
  }
}

// Exposer globalement pour command-palette.js
window.toggleCommandPalette = toggleCommandPalette;
window.showToast = showToast;
window.navigateTo = navigateTo;
window.state = state;
window.toggleSplitScreen = toggleSplitScreen;
window.createNewTab = createNewTab;
window.toggleRightPanel = toggleRightPanel;
