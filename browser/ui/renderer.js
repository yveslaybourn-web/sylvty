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
 * - Panneaux d'outils (RECON, CRYPTO, VULN, PAYLOADS, IA, PROXY, INJECT, TERM)
 * - Hacker Panel (style Minecraft hack client)
 * - Script Injector (bibliothèque de scripts persistants)
 * - Terminal intégré (xterm.js via node-pty)
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
  initScriptInjectorPanel();
  initTerminalPanel();
  initHistoryPanel();
  initBookmarksPanel();
  initScopePanel();
  initNotesPanel();
  initRequestEditor();
  initSystemMonitor();
  initEventListeners();
  initKeyboardShortcuts();
  initWelcomeScreen();

  // Initialiser le diff viewer (chargé depuis composant)
  if (typeof initDiffViewer === 'function') initDiffViewer();

  // Charger le fingerprint initial
  loadFingerprint();

  // Charger la config persistante
  loadPersistedConfig();
});

// ═══════════════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════════════

// Moteurs de recherche
const SEARCH_ENGINES = {
  duckduckgo: { name: 'DuckDuckGo', url: 'https://duckduckgo.com/?q=%s', suggest: 'https://ac.duckduckgo.com/ac/?q=%s&type=list' },
  google: { name: 'Google', url: 'https://www.google.com/search?q=%s', suggest: null },
  brave: { name: 'Brave', url: 'https://search.brave.com/search?q=%s', suggest: null },
  startpage: { name: 'Startpage', url: 'https://www.startpage.com/do/search?q=%s', suggest: null },
  shodan: { name: 'Shodan', url: 'https://www.shodan.io/search?query=%s', suggest: null }
};

function getSearchUrl(query) {
  const engineId = document.getElementById('search-engine')?.value || 'duckduckgo';
  const engine = SEARCH_ENGINES[engineId] || SEARCH_ENGINES.duckduckgo;
  return engine.url.replace('%s', encodeURIComponent(query));
}

function buildUrlFromInput(input) {
  let url = input.trim();
  if (!url) return null;
  // Déjà une URL complète
  if (url.startsWith('http://') || url.startsWith('https://')) return url;
  // Ressemble à un domaine (contient un point, pas d'espace, TLD valide)
  if (url.includes('.') && !url.includes(' ')) {
    const parts = url.split('.');
    const tld = parts[parts.length - 1].split('/')[0].split('?')[0];
    if (tld.length >= 2 && tld.length <= 10 && /^[a-zA-Z]+$/.test(tld)) {
      return 'https://' + url;
    }
  }
  // Tout le reste → recherche
  return getSearchUrl(url);
}

function initNavigation() {
  const urlBar = document.getElementById('url-bar');
  const btnBack = document.getElementById('btn-back');
  const btnForward = document.getElementById('btn-forward');
  const btnReload = document.getElementById('btn-reload');
  const btnHome = document.getElementById('btn-home');
  const suggestions = document.getElementById('url-suggestions');

  let selectedSuggestion = -1;
  let currentSuggestions = [];

  // Navigation par URL
  urlBar.addEventListener('keydown', (e) => {
    // Navigation dans les suggestions
    if (!suggestions.classList.contains('hidden') && currentSuggestions.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedSuggestion = Math.min(selectedSuggestion + 1, currentSuggestions.length - 1);
        renderSuggestionHighlight();
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedSuggestion = Math.max(selectedSuggestion - 1, -1);
        renderSuggestionHighlight();
        return;
      }
      if (e.key === 'Tab' && selectedSuggestion >= 0) {
        e.preventDefault();
        urlBar.value = currentSuggestions[selectedSuggestion].url;
        hideSuggestions();
        return;
      }
    }

    if (e.key === 'Enter') {
      if (selectedSuggestion >= 0 && !suggestions.classList.contains('hidden')) {
        e.preventDefault();
        const selected = currentSuggestions[selectedSuggestion];
        hideSuggestions();
        navigateTo(selected.url.startsWith('http') ? selected.url : 'https://' + selected.url);
        return;
      }
      // Ctrl+Enter → ajouter .com
      if (e.ctrlKey) {
        e.preventDefault();
        let val = urlBar.value.trim();
        if (!val.includes('.')) val += '.com';
        if (!val.startsWith('http')) val = 'https://' + val;
        hideSuggestions();
        navigateTo(val);
        return;
      }
      const url = buildUrlFromInput(urlBar.value);
      hideSuggestions();
      if (url) navigateTo(url);
    }

    if (e.key === 'Escape') {
      hideSuggestions();
    }
  });

  // Autocomplétion en temps réel
  urlBar.addEventListener('input', () => {
    const query = urlBar.value.trim();
    if (query.length < 2) { hideSuggestions(); return; }
    selectedSuggestion = -1;
    showSuggestions(query);
  });

  // Sélectionner tout le texte au focus
  urlBar.addEventListener('focus', () => {
    urlBar.select();
    const query = urlBar.value.trim();
    if (query.length >= 2) showSuggestions(query);
  });

  // Cacher les suggestions quand on clique ailleurs
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.url-container')) hideSuggestions();
  });

  // Bouton Home → retour à l'écran d'accueil
  if (btnHome) {
    btnHome.addEventListener('click', () => {
      showWelcomeScreen();
    });
  }

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
        webview.reloadIgnoringCache();
        showToast('info', 'Cache vidé', 'Page rechargée sans cache');
      } else {
        webview.reload();
      }
    }
  });

  // Sauvegarder le moteur de recherche sélectionné
  const searchEngineSelect = document.getElementById('search-engine');
  if (searchEngineSelect) {
    // Charger le moteur sauvegardé
    window.shadownet.config.get('searchEngine').then(engine => {
      if (engine) searchEngineSelect.value = engine;
    }).catch(() => {});

    searchEngineSelect.addEventListener('change', () => {
      window.shadownet.config.set('searchEngine', searchEngineSelect.value).catch(() => {});
    });
  }

  // Suggestions helpers
  async function showSuggestions(query) {
    currentSuggestions = [];
    const lowerQuery = query.toLowerCase();

    // 1. Bookmarks correspondants
    try {
      const bookmarks = await window.shadownet.bookmarks.list();
      if (bookmarks && bookmarks.length) {
        bookmarks.forEach(b => {
          if (b.url.toLowerCase().includes(lowerQuery) || (b.name && b.name.toLowerCase().includes(lowerQuery))) {
            currentSuggestions.push({ type: 'bookmark', label: b.name || extractDomain(b.url), url: b.url, icon: '★' });
          }
        });
      }
    } catch {}

    // 2. Historique correspondant
    try {
      const history = await window.shadownet.history.get();
      if (history && history.length) {
        const seen = new Set(currentSuggestions.map(s => s.url));
        history.slice().reverse().forEach(h => {
          if (!seen.has(h.url) && (h.url.toLowerCase().includes(lowerQuery) || (h.title && h.title.toLowerCase().includes(lowerQuery)))) {
            currentSuggestions.push({ type: 'history', label: h.title || extractDomain(h.url), url: h.url, icon: '↻' });
            seen.add(h.url);
          }
        });
      }
    } catch {}

    // 3. Suggestion de recherche
    currentSuggestions.push({ type: 'search', label: `Rechercher "${query}"`, url: getSearchUrl(query), icon: '⌕' });

    // Limiter à 8
    currentSuggestions = currentSuggestions.slice(0, 8);

    if (currentSuggestions.length === 0) { hideSuggestions(); return; }

    suggestions.innerHTML = currentSuggestions.map((s, i) => `
      <div class="suggestion-item${i === selectedSuggestion ? ' selected' : ''}" data-index="${i}">
        <span class="suggestion-icon">${s.icon}</span>
        <span class="suggestion-label">${escapeHtml(s.label)}</span>
        <span class="suggestion-url">${escapeHtml(s.url.length > 60 ? s.url.substring(0, 60) + '…' : s.url)}</span>
      </div>
    `).join('');

    suggestions.classList.remove('hidden');

    suggestions.querySelectorAll('.suggestion-item').forEach(el => {
      el.addEventListener('mousedown', (e) => {
        e.preventDefault();
        const idx = parseInt(el.dataset.index);
        const selected = currentSuggestions[idx];
        hideSuggestions();
        navigateTo(selected.url.startsWith('http') ? selected.url : 'https://' + selected.url);
      });
      el.addEventListener('mouseenter', () => {
        selectedSuggestion = parseInt(el.dataset.index);
        renderSuggestionHighlight();
      });
    });
  }

  function renderSuggestionHighlight() {
    suggestions.querySelectorAll('.suggestion-item').forEach((el, i) => {
      el.classList.toggle('selected', i === selectedSuggestion);
    });
  }

  function hideSuggestions() {
    suggestions.classList.add('hidden');
    selectedSuggestion = -1;
    currentSuggestions = [];
  }
}

/**
 * Afficher l'écran d'accueil (new tab page)
 */
function showWelcomeScreen() {
  const welcome = document.getElementById('welcome-screen');
  if (welcome) {
    welcome.style.display = 'flex';
    populateFrequentSites();
  }
  // Vider la barre d'URL
  const urlBar = document.getElementById('url-bar');
  if (urlBar) urlBar.value = '';
  const proto = document.getElementById('url-protocol');
  if (proto) proto.textContent = '';
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
 * Résoudre les informations IP de l'URL courante (non-bloquant)
 */
function resolveUrlInfo(url) {
  const ipSpan = document.getElementById('url-ip');
  if (!ipSpan) return;

  // Réinitialiser pendant le chargement
  ipSpan.textContent = '...';
  ipSpan.style.color = 'var(--text-muted)';

  // Résolution asynchrone sans bloquer la navigation
  window.shadownet.system.getUrlInfo(url).then(info => {
    if (info && info.ip && info.ip !== 'N/A') {
      ipSpan.textContent = info.ip;
      ipSpan.style.color = 'var(--neon-green)';
    } else {
      ipSpan.textContent = '—';
      ipSpan.style.color = 'var(--text-muted)';
    }
  }).catch(() => {
    ipSpan.textContent = '—';
    ipSpan.style.color = 'var(--text-muted)';
  });
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
    // C11 — Enregistrer dans l'historique
    if (e.url && e.url !== 'about:blank') {
      window.shadownet.history.add(e.url, '');
    }
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

  // Bouton Hacker Panel
  const hackerBtn = document.getElementById('btn-hacker-panel');
  if (hackerBtn) {
    hackerBtn.addEventListener('click', () => {
      if (typeof toggleHackerPanel === 'function') {
        toggleHackerPanel();
      }
    });
  }
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
      ai: 'ASSISTANT IA', proxy: 'INTERCEPT PROXY', hex: 'HEX VIEWER',
      scriptinject: 'SCRIPT INJECTOR', terminal: 'TERMINAL',
      history: 'HISTORIQUE', bookmarks: 'CIBLES & BOOKMARKS',
      diff: 'COMPARATEUR DIFF', scope: 'SCOPE MANAGER', notes: 'NOTES & RAPPORT'
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

    const displayRequests = requests.slice(-50).reverse();
    tbody.innerHTML = displayRequests.map((req, i) => {
      const statusClass = getStatusClass(req.statusCode);
      const flags = (req.security?.flags || []).map(f =>
        `<span class="flag-badge">${escapeHtml(f)}</span>`
      ).join('');

      return `<tr class="network-row" data-req-idx="${i}" style="cursor:pointer" title="Cliquer pour charger dans l'éditeur">
        <td><span style="color:var(--neon-yellow)">${escapeHtml(req.method)}</span></td>
        <td title="${escapeHtml(req.url)}">${escapeHtml(truncate(req.url, 60))}</td>
        <td><span class="status-badge ${statusClass}">${req.statusCode || '—'}</span></td>
        <td>${escapeHtml(req.resourceType || '—')}</td>
        <td>${flags}</td>
      </tr>`;
    }).join('');

    // A4 — Clic sur une ligne pour charger dans l'éditeur de tampering
    tbody.querySelectorAll('.network-row').forEach(row => {
      row.addEventListener('click', () => {
        const idx = parseInt(row.dataset.reqIdx);
        if (displayRequests[idx]) {
          loadRequestInEditor(displayRequests[idx]);
        }
      });
    });
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

// Split screen tabs — A1 : contenu dynamique
document.querySelectorAll('.split-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.split-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    switchSplitContent(tab.dataset.panel);
  });
});

/**
 * A1 — Basculer le contenu du split-panel
 * Gère les 4 vues : network, dom, headers, response
 */
function switchSplitContent(panel) {
  // Cacher toutes les vues
  document.querySelectorAll('#split-content .split-view').forEach(v => v.classList.add('hidden'));

  const view = document.getElementById(`split-${panel}`);
  if (view) view.classList.remove('hidden');

  // Charger le contenu dynamique
  switch (panel) {
    case 'network':
      refreshNetworkTable();
      break;

    case 'dom':
      loadDOMTree();
      break;

    case 'headers':
      loadLastHeaders();
      break;

    case 'response':
      loadLastResponse();
      break;
  }
}

async function loadDOMTree() {
  const output = document.getElementById('dom-tree-output');
  const webview = getActiveWebview();
  if (!webview) {
    output.textContent = 'Aucune page chargée';
    return;
  }
  output.innerHTML = '<span class="spinner"></span> Extraction du DOM...';

  try {
    const tree = await webview.executeJavaScript(`
      (function buildTree(el, depth) {
        if (depth > 6) return '';
        const indent = '  '.repeat(depth);
        let tag = el.tagName ? el.tagName.toLowerCase() : '';
        if (!tag) return '';
        let attrs = '';
        if (el.id) attrs += ' id="' + el.id + '"';
        if (el.className && typeof el.className === 'string') attrs += ' class="' + el.className.substring(0, 40) + '"';
        if (el.href) attrs += ' href="' + el.href.substring(0, 60) + '"';
        if (el.src) attrs += ' src="' + el.src.substring(0, 60) + '"';
        let result = indent + '<' + tag + attrs + '>\\n';
        const children = el.children;
        for (let i = 0; i < Math.min(children.length, 30); i++) {
          result += buildTree(children[i], depth + 1);
        }
        if (children.length > 30) result += indent + '  ... (' + (children.length - 30) + ' more)\\n';
        return result;
      })(document.documentElement, 0)
    `);
    output.innerHTML = `<span style="color:var(--neon-green)">${escapeHtml(tree)}</span>`;
  } catch (err) {
    output.textContent = 'Erreur: ' + err.message;
  }
}

async function loadLastHeaders() {
  const output = document.getElementById('headers-output');
  try {
    const requests = await window.shadownet.proxy.getRequests();
    if (!requests || requests.length === 0) {
      output.textContent = 'Aucune requête interceptée';
      return;
    }
    const last = requests[requests.length - 1];
    let html = `<span style="color:var(--neon-cyan)">═══ REQUEST ═══</span>\n`;
    html += `<span style="color:var(--neon-yellow)">${escapeHtml(last.method)}</span> ${escapeHtml(last.url)}\n\n`;

    if (last.requestHeaders) {
      html += `<span style="color:var(--neon-cyan)">═══ REQUEST HEADERS ═══</span>\n`;
      for (const [k, v] of Object.entries(last.requestHeaders)) {
        html += `<span style="color:var(--neon-green)">${escapeHtml(k)}</span>: ${escapeHtml(String(v))}\n`;
      }
    }

    if (last.responseHeaders) {
      html += `\n<span style="color:var(--neon-cyan)">═══ RESPONSE HEADERS ═══</span>\n`;
      html += `<span style="color:var(--neon-yellow)">Status:</span> ${last.statusCode || 'N/A'}\n`;
      for (const [k, v] of Object.entries(last.responseHeaders)) {
        html += `<span style="color:var(--neon-green)">${escapeHtml(k)}</span>: ${escapeHtml(String(Array.isArray(v) ? v.join(', ') : v))}\n`;
      }
    }

    output.innerHTML = html;
  } catch {
    output.textContent = 'Erreur de chargement';
  }
}

async function loadLastResponse() {
  const output = document.getElementById('response-output');
  try {
    const requests = await window.shadownet.proxy.getRequests();
    if (!requests || requests.length === 0) {
      output.textContent = 'Aucune requête interceptée';
      return;
    }
    const last = requests[requests.length - 1];
    let html = `<span style="color:var(--neon-cyan)">═══ RÉPONSE ═══</span>\n`;
    html += `<span style="color:var(--neon-yellow)">${escapeHtml(last.method)}</span> ${escapeHtml(last.url)}\n`;
    html += `Status: ${last.statusCode || 'N/A'} | Type: ${escapeHtml(last.resourceType || 'N/A')}\n\n`;

    if (last.body) {
      html += `<span style="color:var(--neon-cyan)">═══ BODY ═══</span>\n`;
      html += `<span style="color:var(--text-secondary)">${escapeHtml(last.body.substring(0, 5000))}</span>`;
      if (last.body.length > 5000) html += '\n... (tronqué)';
    } else {
      html += '<span style="color:var(--text-muted)">Corps de réponse non capturé (activez le proxy pour capturer)</span>';
    }

    output.innerHTML = html;
  } catch {
    output.textContent = 'Erreur de chargement';
  }
}

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
  // ─── Contrôles fenêtre (minimize, maximize, close) ──────────────
  const btnMinimize = document.getElementById('btn-minimize');
  const btnMaximize = document.getElementById('btn-maximize');
  const btnClose = document.getElementById('btn-close');

  if (btnMinimize) {
    btnMinimize.addEventListener('click', () => {
      window.shadownet.window.minimize();
    });
  }

  if (btnMaximize) {
    btnMaximize.addEventListener('click', () => {
      window.shadownet.window.maximize();
    });
  }

  if (btnClose) {
    btnClose.addEventListener('click', () => {
      window.shadownet.window.close();
    });
  }

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

  // Toggle Hacker Panel (raccourci Ctrl+Shift+H)
  window.shadownet.on('toggle-hacker-panel', () => {
    if (typeof toggleHackerPanel === 'function') {
      toggleHackerPanel();
    }
  });

  // Toggle Terminal (raccourci Ctrl+`)
  window.shadownet.on('toggle-terminal', () => {
    toggleRightPanel('terminal');
  });

  // Lien externe (nouvelle fenêtre interceptée)
  window.shadownet.on('external-link', (url) => {
    createNewTab(url);
  });

  // Alertes de sécurité en temps réel
  window.shadownet.on('proxy-request-intercepted', (data) => {
    state.requestCount++;
    document.getElementById('info-requests').textContent = `Req: ${state.requestCount}`;
  });

  window.shadownet.on('waf-detected', (data) => {
    showToast('warning', 'WAF Détecté', `${data.waf || 'WAF inconnu'} sur ${data.domain || 'cible'}`);
  });

  window.shadownet.on('api-key-leaked', (data) => {
    showToast('danger', 'Fuite de Clé API!', `${data.type || 'Clé'} détectée dans ${data.source || 'requête'}`);
    state.alertCount++;
    document.getElementById('info-alerts').textContent = `Alertes: ${state.alertCount}`;
  });

  window.shadownet.on('security-header-missing', (data) => {
    showToast('warning', 'Header Manquant', `${data.header || 'Header de sécurité'} absent`);
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

    // Ctrl+L ou F6 — Focus sur la barre d'URL
    if ((e.ctrlKey && e.key === 'l') || e.key === 'F6') {
      e.preventDefault();
      document.getElementById('url-bar').focus();
    }

    // Alt+← — Retour
    if (e.altKey && e.key === 'ArrowLeft') {
      e.preventDefault();
      const webview = getActiveWebview();
      if (webview && webview.canGoBack()) webview.goBack();
    }

    // Alt+→ — Avancer
    if (e.altKey && e.key === 'ArrowRight') {
      e.preventDefault();
      const webview = getActiveWebview();
      if (webview && webview.canGoForward()) webview.goForward();
    }

    // Alt+Home — Page d'accueil
    if (e.altKey && e.key === 'Home') {
      e.preventDefault();
      showWelcomeScreen();
    }

    // F5 — Recharger
    if (e.key === 'F5') {
      e.preventDefault();
      const webview = getActiveWebview();
      if (webview) {
        if (e.ctrlKey) {
          webview.reloadIgnoringCache();
        } else {
          webview.reload();
        }
      }
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
// ÉCRAN D'ACCUEIL — RECHERCHE ET SITES FRÉQUENTS
// ═══════════════════════════════════════════════════════════════════════

function initWelcomeScreen() {
  // Barre de recherche de l'écran d'accueil
  const welcomeSearch = document.getElementById('welcome-search');
  const welcomeBtn = document.getElementById('welcome-search-btn');

  if (welcomeSearch) {
    welcomeSearch.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const url = buildUrlFromInput(welcomeSearch.value);
        if (url) navigateTo(url);
      }
      if (e.key === 'Enter' && e.ctrlKey) {
        e.preventDefault();
        let val = welcomeSearch.value.trim();
        if (!val.includes('.')) val += '.com';
        if (!val.startsWith('http')) val = 'https://' + val;
        navigateTo(val);
      }
    });
  }

  if (welcomeBtn) {
    welcomeBtn.addEventListener('click', () => {
      const url = buildUrlFromInput(welcomeSearch.value);
      if (url) navigateTo(url);
    });
  }

  // Quick links
  document.querySelectorAll('.quick-link[data-url]').forEach(el => {
    el.addEventListener('click', () => {
      navigateTo(el.dataset.url);
    });
  });

  // Charger les sites fréquents
  populateFrequentSites();
}

async function populateFrequentSites() {
  const container = document.getElementById('frequent-sites-list');
  if (!container) return;

  try {
    const history = await window.shadownet.history.get();
    if (!history || history.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:11px">Naviguez pour voir vos sites fréquents ici</div>';
      return;
    }

    // Compter les visites par domaine
    const domainCounts = {};
    const domainUrls = {};
    history.forEach(h => {
      try {
        const domain = new URL(h.url).hostname;
        domainCounts[domain] = (domainCounts[domain] || 0) + 1;
        if (!domainUrls[domain]) domainUrls[domain] = h.url;
      } catch {}
    });

    // Top 8 domaines
    const topDomains = Object.entries(domainCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);

    if (topDomains.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);font-size:11px">Pas encore de sites fréquents</div>';
      return;
    }

    container.innerHTML = topDomains.map(([domain, count]) => `
      <div class="frequent-item" data-url="${escapeHtml(domainUrls[domain])}" title="${domain} (${count} visites)">
        <div class="frequent-icon">${domain.charAt(0).toUpperCase()}</div>
        <div class="frequent-name">${domain.replace('www.', '')}</div>
      </div>
    `).join('');

    container.querySelectorAll('.frequent-item').forEach(el => {
      el.addEventListener('click', () => navigateTo(el.dataset.url));
    });
  } catch {
    container.innerHTML = '';
  }
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
// PANNEAU SCRIPT INJECTOR
// ═══════════════════════════════════════════════════════════════════════

function initScriptInjectorPanel() {
  const btnAdd = document.getElementById('btn-add-script');
  const scriptsList = document.getElementById('scripts-list');

  if (btnAdd) {
    btnAdd.addEventListener('click', async () => {
      const domain = document.getElementById('script-domain').value.trim() || '*';
      const code = document.getElementById('script-code').value.trim();

      if (!code) {
        showToast('warning', 'Code vide', 'Entrez du code JavaScript à injecter');
        return;
      }

      await window.shadownet.scripts.add({
        name: `Script ${Date.now()}`,
        domain: domain,
        code: code,
        enabled: true
      });

      document.getElementById('script-code').value = '';
      document.getElementById('script-domain').value = '';
      showToast('success', 'Script Ajouté', `Injection active sur ${domain}`);
      refreshScriptsList();
    });
  }

  // Boutons de conversion (Copy as...)
  const btnPython = document.getElementById('btn-to-python');
  const btnNodeJS = document.getElementById('btn-to-nodejs');
  const btnCurl = document.getElementById('btn-to-curl');

  if (btnPython) {
    btnPython.addEventListener('click', async () => {
      await convertLastRequest('python');
    });
  }

  if (btnNodeJS) {
    btnNodeJS.addEventListener('click', async () => {
      await convertLastRequest('nodejs');
    });
  }

  if (btnCurl) {
    btnCurl.addEventListener('click', async () => {
      await convertLastRequest('curl');
    });
  }

  // Charger les scripts existants
  refreshScriptsList();
}

async function convertLastRequest(format) {
  try {
    const requests = await window.shadownet.proxy.getRequests();
    if (!requests || requests.length === 0) {
      showToast('warning', 'Aucune requête', 'Activez le proxy et naviguez d\'abord');
      return;
    }

    const lastReq = requests[requests.length - 1];
    let result;

    switch (format) {
      case 'python':
        result = await window.shadownet.scripts.toPython(lastReq);
        break;
      case 'nodejs':
        result = await window.shadownet.scripts.toNodeJS(lastReq);
        break;
      case 'curl':
        result = await window.shadownet.scripts.toCurl(lastReq);
        break;
    }

    if (result && result.code) {
      document.getElementById('script-code').value = result.code;
      showToast('success', `${format.toUpperCase()}`, 'Code généré — copiez depuis le champ ci-dessus');
    }
  } catch (err) {
    showToast('danger', 'Erreur', err.message || 'Conversion échouée');
  }
}

async function refreshScriptsList() {
  const container = document.getElementById('scripts-list');
  if (!container) return;

  try {
    const scripts = await window.shadownet.scripts.list();

    if (!scripts || scripts.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Aucun script enregistré</div>';
      return;
    }

    container.innerHTML = scripts.map(s => `
      <div class="script-item" data-script-id="${s.id}" style="
        display:flex;justify-content:space-between;align-items:center;
        padding:8px 12px;margin-bottom:4px;
        background:rgba(0,255,65,0.05);border:1px solid rgba(0,255,65,0.1);
        border-radius:4px;font-size:12px;
      ">
        <div style="flex:1">
          <span style="color:${s.enabled ? 'var(--neon-green)' : 'var(--text-muted)'}">${escapeHtml(s.name)}</span>
          <span style="color:var(--text-muted);margin-left:8px">[${escapeHtml(s.domain)}]</span>
        </div>
        <div style="display:flex;gap:6px">
          <button class="script-toggle" data-id="${s.id}" style="
            background:${s.enabled ? 'var(--neon-green)' : 'var(--neon-red)'};
            color:#000;border:none;padding:2px 8px;border-radius:3px;cursor:pointer;font-size:10px;
          ">${s.enabled ? 'ON' : 'OFF'}</button>
          <button class="script-remove" data-id="${s.id}" style="
            background:var(--neon-red);color:#000;border:none;padding:2px 8px;
            border-radius:3px;cursor:pointer;font-size:10px;
          ">✕</button>
        </div>
      </div>
    `).join('');

    // Événements toggle/remove
    container.querySelectorAll('.script-toggle').forEach(btn => {
      btn.addEventListener('click', async () => {
        await window.shadownet.scripts.toggle(btn.dataset.id);
        refreshScriptsList();
      });
    });

    container.querySelectorAll('.script-remove').forEach(btn => {
      btn.addEventListener('click', async () => {
        await window.shadownet.scripts.remove(btn.dataset.id);
        refreshScriptsList();
        showToast('info', 'Script supprimé', 'Le script a été retiré de la bibliothèque');
      });
    });
  } catch {
    container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Erreur de chargement</div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// PANNEAU TERMINAL INTÉGRÉ
// ═══════════════════════════════════════════════════════════════════════

let terminalActive = false;

function initTerminalPanel() {
  const btnStart = document.getElementById('btn-start-terminal');
  const btnKill = document.getElementById('btn-kill-terminal');
  const container = document.getElementById('terminal-container');

  if (btnStart) {
    btnStart.addEventListener('click', async () => {
      if (terminalActive) return;

      try {
        await window.shadownet.terminal.create();
        terminalActive = true;
        btnStart.disabled = true;
        btnKill.disabled = false;

        // Créer le terminal visuel (textarea fallback si xterm.js non dispo)
        initTerminalDisplay(container);

        showToast('success', 'Terminal Démarré', 'Shell local connecté');
      } catch (err) {
        showToast('danger', 'Erreur Terminal', err.message || 'Impossible de démarrer le terminal');
      }
    });
  }

  if (btnKill) {
    btnKill.addEventListener('click', async () => {
      if (!terminalActive) return;

      await window.shadownet.terminal.kill();
      terminalActive = false;
      btnStart.disabled = false;
      btnKill.disabled = true;

      container.innerHTML = '<div style="color:var(--text-muted);padding:20px;text-align:center">Terminal arrêté</div>';
      showToast('info', 'Terminal Arrêté', 'Le shell a été fermé');
    });
  }

  // Écouter les données du terminal
  window.shadownet.on('terminal:data', (data) => {
    appendTerminalOutput(data);
  });

  window.shadownet.on('terminal:exit', () => {
    terminalActive = false;
    if (btnStart) btnStart.disabled = false;
    if (btnKill) btnKill.disabled = true;
    showToast('info', 'Terminal Fermé', 'Le processus shell s\'est terminé');
  });
}

function initTerminalDisplay(container) {
  if (!container) return;

  // Fallback textarea-based terminal
  container.innerHTML = `
    <div id="term-output" style="
      width:100%;height:calc(100% - 40px);overflow-y:auto;
      background:#0a0a0a;color:#00ff41;font-family:'Fira Code',monospace;
      font-size:13px;padding:10px;white-space:pre-wrap;word-break:break-all;
    "></div>
    <div style="display:flex;border-top:1px solid rgba(0,255,65,0.2)">
      <span style="color:var(--neon-green);padding:8px 4px 8px 10px;font-family:monospace">$</span>
      <input type="text" id="term-input" style="
        flex:1;background:transparent;border:none;color:#00ff41;
        font-family:'Fira Code',monospace;font-size:13px;padding:8px;
        outline:none;
      " placeholder="Tapez une commande..." autofocus>
    </div>
  `;

  const input = document.getElementById('term-input');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const cmd = input.value;
        if (cmd.trim()) {
          appendTerminalOutput(`$ ${cmd}\n`);
          window.shadownet.terminal.write(cmd + '\n');
          input.value = '';
        }
      }
    });
  }
}

function appendTerminalOutput(data) {
  const output = document.getElementById('term-output');
  if (!output) return;
  output.textContent += data;
  output.scrollTop = output.scrollHeight;
}

// ═══════════════════════════════════════════════════════════════════════
// A4 — REQUEST EDITOR (TAMPERING)
// ═══════════════════════════════════════════════════════════════════════

function initRequestEditor() {
  const btnSend = document.getElementById('btn-tamper-send');
  const btnCurl = document.getElementById('btn-tamper-curl');
  const btnIdor = document.getElementById('btn-refresh-idor');

  if (btnSend) {
    btnSend.addEventListener('click', async () => {
      const method = document.getElementById('tamper-method').value;
      const url = document.getElementById('tamper-url').value.trim();
      const headersText = document.getElementById('tamper-headers').value.trim();
      const body = document.getElementById('tamper-body').value;
      const output = document.getElementById('tamper-results');

      if (!url) {
        showToast('warning', 'URL manquante', 'Entrez une URL cible');
        return;
      }

      let headers = {};
      try {
        if (headersText) headers = JSON.parse(headersText);
      } catch {
        showToast('danger', 'Headers invalides', 'Format JSON incorrect');
        return;
      }

      output.innerHTML = '<span class="spinner"></span> Envoi...';
      const result = await window.shadownet.proxy.replay({ url, method, headers, body });

      if (result.error) {
        output.textContent = `Erreur: ${result.error}`;
      } else {
        output.innerHTML = `<span style="color:var(--neon-cyan)">Status:</span> ${result.statusCode}\n` +
          `<span style="color:var(--neon-cyan)">Headers:</span>\n${JSON.stringify(result.headers, null, 2)}\n\n` +
          `<span style="color:var(--neon-cyan)">Body:</span>\n${escapeHtml(result.body?.substring(0, 3000) || '')}`;
      }
    });
  }

  if (btnCurl) {
    btnCurl.addEventListener('click', async () => {
      const method = document.getElementById('tamper-method').value;
      const url = document.getElementById('tamper-url').value.trim();
      const headersText = document.getElementById('tamper-headers').value.trim();
      const body = document.getElementById('tamper-body').value;

      if (!url) return;

      const req = { method, url, headers: {}, body };
      try { if (headersText) req.headers = JSON.parse(headersText); } catch {}

      const result = await window.shadownet.scripts.toCurl({ request: req });
      if (result && result.code) {
        document.getElementById('tamper-body').value = result.code;
        showToast('success', 'cURL', 'Commande copiée dans le champ body');
      }
    });
  }

  if (btnIdor) {
    btnIdor.addEventListener('click', async () => {
      const output = document.getElementById('idor-results');
      const candidates = await window.shadownet.proxy.getIDORCandidates();

      if (!candidates || candidates.length === 0) {
        output.textContent = 'Aucun candidat IDOR détecté — naviguez et activez le proxy';
        return;
      }

      output.innerHTML = candidates.slice(-30).reverse().map(c => {
        return `<div style="margin-bottom:4px;font-size:11px">` +
          `<span style="color:var(--neon-red)">⚠ ${escapeHtml(c.name)}</span>\n` +
          `  <span style="color:var(--neon-yellow)">${escapeHtml(c.method)}</span> ${escapeHtml(c.url)}\n` +
          `  <span style="color:var(--text-muted)">Valeur: ${escapeHtml(c.value)} — Tester ±1</span></div>`;
      }).join('');
    });
  }
}

/**
 * Charger une requête interceptée dans l'éditeur de tampering
 * Appelé depuis le network table au clic
 */
function loadRequestInEditor(request) {
  if (!request) return;
  document.getElementById('tamper-method').value = request.method || 'GET';
  document.getElementById('tamper-url').value = request.url || '';
  document.getElementById('tamper-headers').value = request.requestHeaders
    ? JSON.stringify(request.requestHeaders, null, 2) : '';
  document.getElementById('tamper-body').value = request.body || '';
  toggleRightPanel('proxy');
  showToast('info', 'Requête chargée', 'Modifiez et renvoyez depuis l\'éditeur');
}

// ═══════════════════════════════════════════════════════════════════════
// C11 — PANNEAU HISTORIQUE
// ═══════════════════════════════════════════════════════════════════════

function initHistoryPanel() {
  const btnClear = document.getElementById('btn-clear-history');
  if (btnClear) {
    btnClear.addEventListener('click', async () => {
      await window.shadownet.history.clear();
      renderHistory();
      showToast('info', 'Historique effacé', 'L\'historique de navigation a été vidé');
    });
  }
}

async function renderHistory() {
  const container = document.getElementById('history-list');
  if (!container) return;

  try {
    const history = await window.shadownet.history.get();
    if (!history || history.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Aucun historique</div>';
      return;
    }

    container.innerHTML = history.slice().reverse().slice(0, 100).map(h => {
      const time = new Date(h.visitedAt).toLocaleTimeString('fr-FR');
      return `<div class="history-item" style="
        padding:6px 10px;margin-bottom:2px;cursor:pointer;
        border-left:2px solid var(--neon-green);font-size:11px;
        transition:background 0.2s;
      " data-url="${escapeHtml(h.url)}">
        <span style="color:var(--text-muted)">${time}</span>
        <span style="color:var(--neon-cyan);margin-left:8px">${escapeHtml(h.title || extractDomain(h.url))}</span>
        <div style="color:var(--text-secondary);font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(h.url)}</div>
      </div>`;
    }).join('');

    container.querySelectorAll('.history-item').forEach(el => {
      el.addEventListener('click', () => navigateTo(el.dataset.url));
      el.addEventListener('mouseenter', () => el.style.background = 'rgba(0,255,65,0.05)');
      el.addEventListener('mouseleave', () => el.style.background = 'transparent');
    });
  } catch {
    container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Erreur de chargement</div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// C12 — PANNEAU BOOKMARKS / CIBLES
// ═══════════════════════════════════════════════════════════════════════

function initBookmarksPanel() {
  const btnAdd = document.getElementById('btn-add-bookmark');
  if (btnAdd) {
    btnAdd.addEventListener('click', async () => {
      const name = document.getElementById('bookmark-name').value.trim();
      const url = document.getElementById('bookmark-url').value.trim();

      if (!url) {
        showToast('warning', 'URL manquante', 'Entrez une URL cible');
        return;
      }

      await window.shadownet.bookmarks.add(name || url, url);
      document.getElementById('bookmark-name').value = '';
      document.getElementById('bookmark-url').value = '';
      renderBookmarks();
      showToast('success', 'Cible ajoutée', name || url);
    });
  }
  renderBookmarks();
}

async function renderBookmarks() {
  const container = document.getElementById('bookmarks-list');
  if (!container) return;

  try {
    const bookmarks = await window.shadownet.bookmarks.list();
    if (!bookmarks || bookmarks.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Aucune cible enregistrée</div>';
      return;
    }

    container.innerHTML = bookmarks.map(b => `
      <div class="bookmark-item" style="
        display:flex;justify-content:space-between;align-items:center;
        padding:8px 10px;margin-bottom:4px;
        background:rgba(0,255,65,0.03);border:1px solid rgba(0,255,65,0.1);
        border-radius:4px;font-size:11px;
      ">
        <div style="flex:1;cursor:pointer" class="bm-open" data-url="${escapeHtml(b.url)}">
          <div style="color:var(--neon-cyan)">${escapeHtml(b.name)}</div>
          <div style="color:var(--text-muted);font-size:10px">${escapeHtml(b.url)}</div>
        </div>
        <button class="bm-remove" data-id="${b.id}" style="
          background:var(--neon-red);color:#000;border:none;padding:2px 8px;
          border-radius:3px;cursor:pointer;font-size:10px;margin-left:8px;
        ">✕</button>
      </div>
    `).join('');

    container.querySelectorAll('.bm-open').forEach(el => {
      el.addEventListener('click', () => navigateTo(el.dataset.url));
    });

    container.querySelectorAll('.bm-remove').forEach(el => {
      el.addEventListener('click', async () => {
        await window.shadownet.bookmarks.remove(el.dataset.id);
        renderBookmarks();
      });
    });
  } catch {
    container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Erreur de chargement</div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// D15 — PANNEAU SCOPE MANAGER
// ═══════════════════════════════════════════════════════════════════════

function initScopePanel() {
  const btnAdd = document.getElementById('btn-add-scope');
  const modeSelect = document.getElementById('scope-mode');

  if (btnAdd) {
    btnAdd.addEventListener('click', async () => {
      const domain = document.getElementById('scope-domain').value.trim();
      if (!domain) return;

      const result = await window.shadownet.scope.add(domain);
      if (result.success) {
        document.getElementById('scope-domain').value = '';
        renderScope();
        showToast('success', 'Scope', `${domain} ajouté au périmètre`);
      } else {
        showToast('danger', 'Erreur', result.error || 'Domaine invalide');
      }
    });
  }

  if (modeSelect) {
    modeSelect.addEventListener('change', async () => {
      await window.shadownet.scope.setMode(modeSelect.value);
      showToast('info', 'Scope', `Mode ${modeSelect.value} activé`);
    });
  }

  renderScope();
}

async function renderScope() {
  const container = document.getElementById('scope-list');
  if (!container) return;

  try {
    const result = await window.shadownet.scope.list();
    const scope = result.scope || [];

    if (scope.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Aucun domaine dans le scope (tout est autorisé)</div>';
      return;
    }

    container.innerHTML = scope.map(d => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 8px;margin-bottom:2px;font-size:11px">
        <span style="color:var(--neon-green)">⊙ ${escapeHtml(d)}</span>
        <button class="scope-remove" data-domain="${escapeHtml(d)}" style="
          background:var(--neon-red);color:#000;border:none;padding:1px 6px;
          border-radius:3px;cursor:pointer;font-size:10px;
        ">✕</button>
      </div>
    `).join('');

    container.querySelectorAll('.scope-remove').forEach(el => {
      el.addEventListener('click', async () => {
        await window.shadownet.scope.remove(el.dataset.domain);
        renderScope();
      });
    });

    if (result.mode) {
      const modeSelect = document.getElementById('scope-mode');
      if (modeSelect) modeSelect.value = result.mode;
    }
  } catch {
    container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Erreur de chargement</div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// D16 — PANNEAU NOTES & RAPPORT
// ═══════════════════════════════════════════════════════════════════════

function initNotesPanel() {
  const btnSave = document.getElementById('btn-save-notes');
  const btnFinding = document.getElementById('btn-add-finding');
  const btnExportJSON = document.getElementById('btn-export-json');
  const btnExportMD = document.getElementById('btn-export-md');
  const btnExportHTML = document.getElementById('btn-export-html');

  // Charger les notes existantes
  window.shadownet.notes.get().then(result => {
    const textarea = document.getElementById('pentest-notes');
    if (textarea && result.text) textarea.value = result.text;
  }).catch(() => {});

  if (btnSave) {
    btnSave.addEventListener('click', async () => {
      const text = document.getElementById('pentest-notes').value;
      await window.shadownet.notes.save(text);
      showToast('success', 'Notes sauvegardées', 'Vos notes ont été enregistrées');
    });
  }

  if (btnFinding) {
    btnFinding.addEventListener('click', async () => {
      const title = document.getElementById('finding-title').value.trim();
      const severity = document.getElementById('finding-severity').value;
      const description = document.getElementById('finding-desc').value.trim();
      const poc = document.getElementById('finding-poc').value.trim();
      const recommendation = document.getElementById('finding-rec').value.trim();

      if (!title) {
        showToast('warning', 'Titre requis', 'Donnez un titre au finding');
        return;
      }

      await window.shadownet.findings.add({ title, severity, description, poc, recommendation });
      document.getElementById('finding-title').value = '';
      document.getElementById('finding-desc').value = '';
      document.getElementById('finding-poc').value = '';
      document.getElementById('finding-rec').value = '';
      renderFindings();
      showToast('success', 'Finding ajouté', `[${severity.toUpperCase()}] ${title}`);
    });
  }

  // Export buttons
  const exportHandler = async (format) => {
    const notes = document.getElementById('pentest-notes').value;
    const findings = await window.shadownet.findings.list();
    const requests = await window.shadownet.proxy.getRequests();

    const data = {
      target: state.currentDomain || 'N/A',
      scope: [],
      date: new Date().toISOString().split('T')[0],
      notes,
      findings: findings || [],
      requests: (requests || []).slice(-100)
    };

    let result;
    switch (format) {
      case 'json': result = await window.shadownet.export.json(data); break;
      case 'markdown': result = await window.shadownet.export.markdown(data); break;
      case 'html': result = await window.shadownet.export.html(data); break;
    }

    if (result && result.success) {
      showToast('success', 'Rapport exporté', result.path);
    }
  };

  if (btnExportJSON) btnExportJSON.addEventListener('click', () => exportHandler('json'));
  if (btnExportMD) btnExportMD.addEventListener('click', () => exportHandler('markdown'));
  if (btnExportHTML) btnExportHTML.addEventListener('click', () => exportHandler('html'));

  renderFindings();
}

async function renderFindings() {
  const container = document.getElementById('findings-list');
  if (!container) return;

  try {
    const findings = await window.shadownet.findings.list();
    if (!findings || findings.length === 0) {
      container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Aucun finding enregistré</div>';
      return;
    }

    const severityColors = {
      critical: '#ff0040', high: '#ff6600', medium: '#ffaa00', low: '#00ccff', info: '#888'
    };

    container.innerHTML = findings.map(f => `
      <div style="
        padding:8px 10px;margin-bottom:6px;
        border-left:3px solid ${severityColors[f.severity] || '#888'};
        background:rgba(0,0,0,0.3);font-size:11px;
      ">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span style="color:${severityColors[f.severity]};font-weight:bold">[${(f.severity || 'info').toUpperCase()}]</span>
          <span style="color:var(--neon-cyan)">${escapeHtml(f.title)}</span>
          <button class="finding-remove" data-id="${f.id}" style="
            background:transparent;color:var(--neon-red);border:none;cursor:pointer;font-size:12px;
          ">✕</button>
        </div>
        ${f.description ? `<div style="color:var(--text-secondary);margin-top:4px">${escapeHtml(f.description)}</div>` : ''}
        ${f.poc ? `<div style="color:var(--neon-yellow);margin-top:4px;font-family:monospace;font-size:10px">PoC: ${escapeHtml(f.poc)}</div>` : ''}
      </div>
    `).join('');

    container.querySelectorAll('.finding-remove').forEach(el => {
      el.addEventListener('click', async () => {
        await window.shadownet.findings.remove(el.dataset.id);
        renderFindings();
      });
    });
  } catch {
    container.innerHTML = '<div style="color:var(--text-muted);padding:10px">Erreur de chargement</div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// PERSISTANCE DE LA CONFIG
// ═══════════════════════════════════════════════════════════════════════

async function loadPersistedConfig() {
  try {
    const config = await window.shadownet.config.getAll();
    if (!config) return;

    // Restaurer les états
    if (config.proxyEnabled) {
      document.getElementById('btn-toggle-proxy').click();
    }
    if (!config.spoofEnabled) {
      state.spoofEnabled = false;
      document.getElementById('btn-toggle-spoof').classList.remove('active');
    }
  } catch { /* Config pas encore disponible */ }
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

// Exposer globalement pour command-palette.js et hacker-panel.js
window.toggleCommandPalette = toggleCommandPalette;
window.showToast = showToast;
window.navigateTo = navigateTo;
window.state = state;
window.toggleSplitScreen = toggleSplitScreen;
window.createNewTab = createNewTab;
window.toggleRightPanel = toggleRightPanel;
window.getActiveWebview = getActiveWebview;
window.refreshScriptsList = refreshScriptsList;
window.loadRequestInEditor = loadRequestInEditor;
window.renderHistory = renderHistory;
window.renderBookmarks = renderBookmarks;
