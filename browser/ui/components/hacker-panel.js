/**
 * ========================================================================
 * ShadowNet Browser — Hacker Panel (Style Minecraft Hack Client)
 * ========================================================================
 *
 * Panneau flottant draggable inspiré des hack clients Minecraft.
 * Chaque module peut être activé/désactivé par un simple clic.
 * Le panneau affiche l'état en temps réel de tous les modules.
 *
 * Toggle: Ctrl+Shift+H ou clic droit sur la barre de titre
 *
 * Catégories de modules :
 * - STEALTH : Évasion, anti-fingerprinting, proxy rotation
 * - OFFENSE : Secrets hunter, IDOR scanner, script injector
 * - RECON   : Tech detection, subdomain enum, dir scan
 * - FORENSIC: Zero-disk, DOM tracker, RAM-only mode
 */

(function() {
  'use strict';

  // ═══════════════════════════════════════════════════════════════════
  // ÉTAT DU HACKER PANEL
  // ═══════════════════════════════════════════════════════════════════

  const panelState = {
    visible: false,
    collapsed: {},
    modules: {
      // ─── STEALTH ──────────────────────────────────────────────
      'ja3-randomizer': {
        name: 'JA3 Randomizer',
        category: 'STEALTH',
        enabled: false,
        icon: '◈',
        description: 'Randomise le TLS fingerprint (JA3) pour contourner les WAF avancés',
        statusText: () => 'Cipher suites randomisées'
      },
      'proxy-rotation': {
        name: 'Proxy Rotation',
        category: 'STEALTH',
        enabled: false,
        icon: '⟳',
        description: 'Rotation automatique de proxies SOCKS5/HTTP par onglet',
        statusText: () => `${panelState.proxyPool.length} proxies chargés`
      },
      'canvas-noise': {
        name: 'Canvas Noise',
        category: 'STEALTH',
        enabled: true,
        icon: '▦',
        description: 'Injection de bruit dans le Canvas pour casser le fingerprint',
        statusText: () => 'Bruit imperceptible actif'
      },
      'webgl-spoof': {
        name: 'WebGL Spoof',
        category: 'STEALTH',
        enabled: true,
        icon: '◬',
        description: 'Spoofing du vendor/renderer WebGL',
        statusText: () => 'GPU profile spoofé'
      },
      'audio-noise': {
        name: 'Audio Noise',
        category: 'STEALTH',
        enabled: true,
        icon: '♫',
        description: 'Bruit AudioContext pour empêcher le fingerprinting audio',
        statusText: () => 'Noise injection active'
      },
      'webrtc-block': {
        name: 'WebRTC Block',
        category: 'STEALTH',
        enabled: true,
        icon: '⊘',
        description: 'Blocage strict des fuites IP via WebRTC STUN/TURN',
        statusText: () => 'STUN/TURN bloqués'
      },
      'ua-rotate': {
        name: 'UA Rotate',
        category: 'STEALTH',
        enabled: true,
        icon: '⟲',
        description: 'Rotation automatique du User-Agent toutes les N requêtes',
        statusText: () => 'Rotation automatique'
      },

      // ─── OFFENSE ──────────────────────────────────────────────
      'secrets-hunter': {
        name: 'Secrets Hunter',
        category: 'OFFENSE',
        enabled: false,
        icon: '🔑',
        description: 'Scan regex en fond pour API Keys (AWS, Stripe, Firebase), credentials, IPs internes',
        statusText: () => `${panelState.secretsFound} secrets trouvés`
      },
      'idor-scanner': {
        name: 'IDOR Scanner',
        category: 'OFFENSE',
        enabled: false,
        icon: '🎯',
        description: 'Détecte les patterns IDOR dans les URLs et requêtes XHR',
        statusText: () => `${panelState.idorPatterns} patterns IDOR`
      },
      'script-injector': {
        name: 'Script Injector',
        category: 'OFFENSE',
        enabled: false,
        icon: '💉',
        description: 'Injecte automatiquement des scripts JS personnalisés sur les domaines configurés',
        statusText: () => `${panelState.injectedScripts} scripts actifs`
      },
      'copy-as-code': {
        name: 'Copy as Code',
        category: 'OFFENSE',
        enabled: true,
        icon: '📋',
        description: 'Convertit les requêtes interceptées en scripts Python/Node.js/cURL',
        statusText: () => 'Clic droit sur requête → Export'
      },
      'auto-xss-probe': {
        name: 'XSS Probe',
        category: 'OFFENSE',
        enabled: false,
        icon: '⚡',
        description: 'Injecte automatiquement des probes XSS dans les inputs reflétés',
        statusText: () => 'Probing passif'
      },

      // ─── RECON ────────────────────────────────────────────────
      'tech-detect': {
        name: 'Tech Detect',
        category: 'RECON',
        enabled: true,
        icon: '⌕',
        description: 'Détection automatique de la stack technologique',
        statusText: () => 'Wappalyzer-style'
      },
      'header-analyzer': {
        name: 'Header Analyzer',
        category: 'RECON',
        enabled: true,
        icon: '📊',
        description: 'Analyse continue des headers de sécurité',
        statusText: () => 'Monitoring actif'
      },
      'waf-detector': {
        name: 'WAF Detector',
        category: 'RECON',
        enabled: true,
        icon: '🛡',
        description: 'Détecte les WAF (Cloudflare, AWS, ModSec, Sucuri, etc.)',
        statusText: () => 'Signatures: 12 WAFs'
      },

      // ─── FORENSIC ─────────────────────────────────────────────
      'zero-disk': {
        name: 'Zero-Disk Mode',
        category: 'FORENSIC',
        enabled: false,
        icon: '💀',
        description: 'Toutes les données en RAM uniquement — Wipe multi-pass à la fermeture',
        statusText: () => panelState.modules['zero-disk'].enabled ? 'RAM ONLY — Aucune écriture disque' : 'Désactivé'
      },
      'dom-tracker': {
        name: 'DOM Tracker',
        category: 'FORENSIC',
        enabled: false,
        icon: '👁',
        description: 'Highlight les éléments DOM modifiés depuis le dernier refresh',
        statusText: () => `${panelState.domChanges} mutations détectées`
      },
      'ram-monitor': {
        name: 'RAM Monitor',
        category: 'FORENSIC',
        enabled: true,
        icon: '📈',
        description: 'Moniteur de consommation mémoire en temps réel',
        statusText: () => 'Usage mémoire surveillé'
      }
    },
    // Compteurs d'état
    secretsFound: 0,
    idorPatterns: 0,
    injectedScripts: 0,
    domChanges: 0,
    proxyPool: [],
    activeProxyIndex: 0
  };

  // ═══════════════════════════════════════════════════════════════════
  // CRÉATION DU DOM DU PANNEAU
  // ═══════════════════════════════════════════════════════════════════

  function createHackerPanel() {
    const panel = document.createElement('div');
    panel.id = 'hacker-panel';
    panel.className = 'hacker-panel hidden';
    panel.innerHTML = buildPanelHTML();
    document.body.appendChild(panel);

    // Rendre le panneau draggable
    makeDraggable(panel);

    // Événements sur les modules
    bindModuleEvents(panel);

    // Événements sur les catégories (toggle collapse)
    bindCategoryEvents(panel);

    return panel;
  }

  function buildPanelHTML() {
    const categories = {};
    for (const [id, mod] of Object.entries(panelState.modules)) {
      if (!categories[mod.category]) categories[mod.category] = [];
      categories[mod.category].push({ id, ...mod });
    }

    const categoryIcons = {
      'STEALTH': '🕶',
      'OFFENSE': '⚔',
      'RECON': '🔍',
      'FORENSIC': '🔬'
    };

    const categoryColors = {
      'STEALTH': 'var(--neon-cyan)',
      'OFFENSE': 'var(--neon-red)',
      'RECON': 'var(--neon-green)',
      'FORENSIC': 'var(--neon-magenta)'
    };

    let html = `
      <div class="hp-titlebar">
        <span class="hp-title">◈ SHADOWNET MODULES</span>
        <div class="hp-controls">
          <span class="hp-counter" id="hp-active-count">0 actifs</span>
          <button class="hp-btn" id="hp-minimize">─</button>
          <button class="hp-btn hp-close" id="hp-close">✕</button>
        </div>
      </div>
      <div class="hp-body" id="hp-body">
        <div class="hp-search-bar">
          <input type="text" id="hp-search" class="hp-search" placeholder="Filtrer modules..." spellcheck="false">
        </div>
    `;

    for (const [cat, mods] of Object.entries(categories)) {
      const color = categoryColors[cat] || 'var(--neon-cyan)';
      const icon = categoryIcons[cat] || '◈';
      const collapsed = panelState.collapsed[cat] ? 'collapsed' : '';

      html += `
        <div class="hp-category ${collapsed}" data-category="${cat}">
          <div class="hp-category-header" data-cat-toggle="${cat}" style="--cat-color: ${color}">
            <span class="hp-cat-icon">${icon}</span>
            <span class="hp-cat-name">${cat}</span>
            <span class="hp-cat-count">${mods.filter(m => m.enabled).length}/${mods.length}</span>
            <span class="hp-cat-arrow">▾</span>
          </div>
          <div class="hp-module-list">
      `;

      for (const mod of mods) {
        const enabledClass = mod.enabled ? 'enabled' : '';
        const statusText = mod.statusText();
        html += `
          <div class="hp-module ${enabledClass}" data-module-id="${mod.id}" title="${escapeHtml(mod.description)}">
            <div class="hp-module-left">
              <span class="hp-module-icon">${mod.icon}</span>
              <div class="hp-module-info">
                <span class="hp-module-name">${escapeHtml(mod.name)}</span>
                <span class="hp-module-status">${escapeHtml(statusText)}</span>
              </div>
            </div>
            <div class="hp-module-toggle">
              <div class="hp-toggle-switch ${enabledClass}">
                <div class="hp-toggle-knob"></div>
              </div>
            </div>
          </div>
        `;
      }

      html += `
          </div>
        </div>
      `;
    }

    html += `
        <div class="hp-footer">
          <span class="hp-footer-text">Ctrl+Shift+H pour toggle</span>
          <div class="hp-footer-actions">
            <button class="hp-footer-btn" id="hp-enable-all">Tout ON</button>
            <button class="hp-footer-btn" id="hp-disable-all">Tout OFF</button>
          </div>
        </div>
      </div>
    `;

    return html;
  }

  // ═══════════════════════════════════════════════════════════════════
  // DRAG & DROP
  // ═══════════════════════════════════════════════════════════════════

  function makeDraggable(panel) {
    const titlebar = panel.querySelector('.hp-titlebar');
    let isDragging = false;
    let startX, startY, startLeft, startTop;

    titlebar.addEventListener('mousedown', (e) => {
      if (e.target.closest('.hp-btn')) return; // Ne pas drag sur les boutons
      isDragging = true;
      startX = e.clientX;
      startY = e.clientY;
      const rect = panel.getBoundingClientRect();
      startLeft = rect.left;
      startTop = rect.top;
      panel.style.transition = 'none';
    });

    document.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      const dx = e.clientX - startX;
      const dy = e.clientY - startY;
      panel.style.left = (startLeft + dx) + 'px';
      panel.style.top = (startTop + dy) + 'px';
      panel.style.right = 'auto';
    });

    document.addEventListener('mouseup', () => {
      isDragging = false;
      panel.style.transition = '';
    });
  }

  // ═══════════════════════════════════════════════════════════════════
  // ÉVÉNEMENTS
  // ═══════════════════════════════════════════════════════════════════

  function bindModuleEvents(panel) {
    panel.querySelectorAll('.hp-module').forEach(el => {
      el.addEventListener('click', () => {
        const modId = el.dataset.moduleId;
        toggleModule(modId);
      });
    });

    // Boutons de contrôle
    panel.querySelector('#hp-close').addEventListener('click', () => {
      toggleHackerPanel();
    });

    panel.querySelector('#hp-minimize').addEventListener('click', () => {
      const body = panel.querySelector('#hp-body');
      body.classList.toggle('minimized');
    });

    panel.querySelector('#hp-enable-all').addEventListener('click', () => {
      for (const id of Object.keys(panelState.modules)) {
        panelState.modules[id].enabled = true;
      }
      refreshPanel();
      applyModuleEffects();
      window.showToast('success', 'Tous les modules activés', 'Toutes les fonctionnalités sont actives');
    });

    panel.querySelector('#hp-disable-all').addEventListener('click', () => {
      for (const id of Object.keys(panelState.modules)) {
        panelState.modules[id].enabled = false;
      }
      refreshPanel();
      applyModuleEffects();
      window.showToast('info', 'Tous les modules désactivés', 'Toutes les fonctionnalités sont inactives');
    });

    // Filtre de recherche
    panel.querySelector('#hp-search').addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase();
      panel.querySelectorAll('.hp-module').forEach(el => {
        const modId = el.dataset.moduleId;
        const mod = panelState.modules[modId];
        const match = mod.name.toLowerCase().includes(query) ||
                      mod.category.toLowerCase().includes(query) ||
                      mod.description.toLowerCase().includes(query);
        el.style.display = match ? '' : 'none';
      });
    });
  }

  function bindCategoryEvents(panel) {
    panel.querySelectorAll('.hp-category-header').forEach(header => {
      header.addEventListener('click', () => {
        const cat = header.dataset.catToggle;
        const category = header.closest('.hp-category');
        category.classList.toggle('collapsed');
        panelState.collapsed[cat] = category.classList.contains('collapsed');
      });
    });
  }

  // ═══════════════════════════════════════════════════════════════════
  // TOGGLE MODULE
  // ═══════════════════════════════════════════════════════════════════

  function toggleModule(moduleId) {
    const mod = panelState.modules[moduleId];
    if (!mod) return;

    mod.enabled = !mod.enabled;
    refreshPanel();
    applyModuleEffects(moduleId);

    const status = mod.enabled ? 'activé' : 'désactivé';
    window.showToast(mod.enabled ? 'success' : 'info',
      `${mod.name} ${status}`,
      mod.description
    );
  }

  /**
   * Appliquer les effets d'un module activé/désactivé
   */
  function applyModuleEffects(moduleId) {
    const mod = panelState.modules[moduleId];
    if (!mod) return;

    switch (moduleId) {
      case 'secrets-hunter':
        if (mod.enabled) startSecretsHunter();
        break;
      case 'idor-scanner':
        if (mod.enabled) startIDORScanner();
        break;
      case 'dom-tracker':
        if (mod.enabled) startDOMTracker();
        break;
      case 'zero-disk':
        if (mod.enabled) {
          window.showToast('danger', 'ZERO-DISK MODE', 'Toutes les données sont maintenant en RAM uniquement. Wipe multi-pass à la fermeture.');
        }
        break;
      case 'script-injector':
        if (mod.enabled) window.toggleRightPanel?.('scriptinject');
        break;
      case 'ja3-randomizer':
        if (mod.enabled) {
          window.showToast('info', 'JA3 Randomizer', 'TLS cipher suites randomisées pour contourner les WAF');
        }
        break;
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // SECRETS HUNTER — Scan regex en fond
  // ═══════════════════════════════════════════════════════════════════

  let secretsInterval = null;

  function startSecretsHunter() {
    if (secretsInterval) return;

    const patterns = [
      { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
      { name: 'AWS Secret Key', regex: /(?:aws)?_?(?:secret)?_?(?:access)?_?key["'\s:=]+([A-Za-z0-9/+=]{40})/gi, severity: 'critical' },
      { name: 'Stripe API Key', regex: /sk_(?:live|test)_[a-zA-Z0-9]{24,}/g, severity: 'critical' },
      { name: 'Stripe Publishable', regex: /pk_(?:live|test)_[a-zA-Z0-9]{24,}/g, severity: 'medium' },
      { name: 'Firebase API Key', regex: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high' },
      { name: 'Google OAuth', regex: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/g, severity: 'high' },
      { name: 'GitHub Token', regex: /gh[ps]_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
      { name: 'Slack Token', regex: /xox[bpors]-[0-9a-zA-Z-]{10,}/g, severity: 'critical' },
      { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: 'medium' },
      { name: 'Private Key', regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
      { name: 'Internal IPv4', regex: /(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g, severity: 'low' },
      { name: 'Hardcoded Password', regex: /(?:password|passwd|pwd)["'\s:=]+["']([^"']{4,})["']/gi, severity: 'high' },
      { name: 'SendGrid API Key', regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: 'critical' },
      { name: 'Twilio API Key', regex: /SK[a-f0-9]{32}/g, severity: 'high' },
      { name: 'Mailgun API Key', regex: /key-[a-f0-9]{32}/g, severity: 'high' },
    ];

    secretsInterval = setInterval(async () => {
      if (!panelState.modules['secrets-hunter'].enabled) {
        clearInterval(secretsInterval);
        secretsInterval = null;
        return;
      }

      const webview = document.querySelector(`#webview-${window.state?.activeTabId}`);
      if (!webview) return;

      try {
        // Scanner le HTML et les scripts de la page
        const pageContent = await webview.executeJavaScript(`
          (function() {
            let content = document.documentElement.outerHTML;
            const scripts = document.querySelectorAll('script[src]');
            return content;
          })()
        `);

        let totalFound = 0;
        for (const pattern of patterns) {
          const matches = pageContent.match(pattern.regex);
          if (matches) {
            totalFound += matches.length;
            // Notifier seulement les nouvelles découvertes critiques
            if (pattern.severity === 'critical' && totalFound > panelState.secretsFound) {
              window.showToast('danger', `🔑 ${pattern.name} détecté!`,
                `${matches.length} occurrence(s) — ${matches[0].substring(0, 30)}...`);
            }
          }
        }
        panelState.secretsFound = totalFound;
        refreshModuleStatus('secrets-hunter');

        // Mettre à jour les indicateurs UI
        const secretsInfo = document.getElementById('info-secrets');
        if (secretsInfo) secretsInfo.textContent = totalFound > 0 ? `Secrets: ${totalFound}` : '';
        const secretsIndicator = document.getElementById('secrets-indicator');
        if (secretsIndicator) secretsIndicator.className = totalFound > 0 ? 'indicator on' : 'indicator off';
      } catch { /* Page non accessible */ }
    }, 5000);
  }

  // ═══════════════════════════════════════════════════════════════════
  // IDOR SCANNER — Détection de patterns IDOR
  // ═══════════════════════════════════════════════════════════════════

  function startIDORScanner() {
    // Patterns IDOR typiques dans les URLs
    const idorPatterns = [
      /\/(?:user|account|profile|order|invoice|document|file|report)s?\/(\d+)/gi,
      /[?&](?:id|user_id|account_id|order_id|doc_id)=(\d+)/gi,
      /\/api\/v\d+\/\w+\/(\d+)/gi,
      /\/(?:download|view|edit|delete)\/(\d+)/gi,
      /[?&](?:ref|token|key)=([a-f0-9]{8,})/gi,
    ];

    // Observer les requêtes réseau pour les patterns IDOR
    const checkInterval = setInterval(async () => {
      if (!panelState.modules['idor-scanner'].enabled) {
        clearInterval(checkInterval);
        return;
      }

      try {
        // Utiliser le backend IDOR detection + scan local
        const candidates = await window.shadownet.proxy.getIDORCandidates();
        const requests = await window.shadownet.proxy.getRequests();
        let idorCount = candidates ? candidates.length : 0;

        // Scan additionnel côté renderer
        for (const req of requests) {
          for (const pattern of idorPatterns) {
            pattern.lastIndex = 0;
            if (pattern.test(req.url)) {
              idorCount++;
              break;
            }
          }
        }

        if (idorCount > panelState.idorPatterns) {
          const newCount = idorCount - panelState.idorPatterns;
          panelState.idorPatterns = idorCount;
          refreshModuleStatus('idor-scanner');
          if (newCount > 0) {
            window.showToast('warning', 'IDOR Détecté', `${newCount} nouveau(x) pattern(s) IDOR — vérifiez le panneau Proxy`);
          }
        }
      } catch { /* Ignorer */ }
    }, 8000);
  }

  // ═══════════════════════════════════════════════════════════════════
  // DOM TRACKER — Suivi des mutations DOM
  // ═══════════════════════════════════════════════════════════════════

  function startDOMTracker() {
    const webview = document.querySelector(`#webview-${window.state?.activeTabId}`);
    if (!webview) return;

    webview.executeJavaScript(`
      (function() {
        if (window.__shadownet_dom_tracker) return;
        window.__shadownet_dom_tracker = true;
        window.__shadownet_mutations = 0;

        const observer = new MutationObserver((mutations) => {
          mutations.forEach(m => {
            window.__shadownet_mutations++;
            // Highlight les éléments modifiés
            if (m.type === 'childList') {
              m.addedNodes.forEach(node => {
                if (node.style) {
                  node.style.outline = '2px solid rgba(255, 0, 255, 0.5)';
                  node.style.outlineOffset = '-2px';
                  setTimeout(() => {
                    if (node.style) {
                      node.style.outline = '';
                      node.style.outlineOffset = '';
                    }
                  }, 3000);
                }
              });
            }
            if (m.type === 'attributes' && m.target.style) {
              m.target.style.outline = '2px solid rgba(0, 255, 65, 0.4)';
              setTimeout(() => {
                if (m.target.style) m.target.style.outline = '';
              }, 2000);
            }
          });
        });

        observer.observe(document.body, {
          childList: true, subtree: true,
          attributes: true, characterData: true
        });
      })()
    `).catch(() => {});

    // Polling pour récupérer le compteur de mutations
    const pollInterval = setInterval(async () => {
      if (!panelState.modules['dom-tracker'].enabled) {
        clearInterval(pollInterval);
        return;
      }
      try {
        const count = await webview.executeJavaScript('window.__shadownet_mutations || 0');
        panelState.domChanges = count;
        refreshModuleStatus('dom-tracker');
      } catch { /* Ignorer */ }
    }, 3000);
  }

  // ═══════════════════════════════════════════════════════════════════
  // RAFRAÎCHISSEMENT DE L'UI
  // ═══════════════════════════════════════════════════════════════════

  function refreshPanel() {
    const panel = document.getElementById('hacker-panel');
    if (!panel) return;

    // Mettre à jour chaque module
    for (const [id, mod] of Object.entries(panelState.modules)) {
      const el = panel.querySelector(`[data-module-id="${id}"]`);
      if (!el) continue;

      const toggle = el.querySelector('.hp-toggle-switch');
      if (mod.enabled) {
        el.classList.add('enabled');
        toggle.classList.add('enabled');
      } else {
        el.classList.remove('enabled');
        toggle.classList.remove('enabled');
      }

      const status = el.querySelector('.hp-module-status');
      if (status) status.textContent = mod.statusText();
    }

    // Mettre à jour les compteurs de catégorie
    panel.querySelectorAll('.hp-category').forEach(cat => {
      const catName = cat.dataset.category;
      const mods = Object.values(panelState.modules).filter(m => m.category === catName);
      const active = mods.filter(m => m.enabled).length;
      cat.querySelector('.hp-cat-count').textContent = `${active}/${mods.length}`;
    });

    // Compteur total
    const totalActive = Object.values(panelState.modules).filter(m => m.enabled).length;
    const counter = panel.querySelector('#hp-active-count');
    if (counter) counter.textContent = `${totalActive} actifs`;
  }

  function refreshModuleStatus(moduleId) {
    const panel = document.getElementById('hacker-panel');
    if (!panel) return;
    const el = panel.querySelector(`[data-module-id="${moduleId}"]`);
    if (!el) return;
    const status = el.querySelector('.hp-module-status');
    if (status) status.textContent = panelState.modules[moduleId].statusText();
  }

  // ═══════════════════════════════════════════════════════════════════
  // TOGGLE GLOBAL
  // ═══════════════════════════════════════════════════════════════════

  function toggleHackerPanel() {
    let panel = document.getElementById('hacker-panel');
    if (!panel) {
      panel = createHackerPanel();
    }

    panelState.visible = !panelState.visible;
    panel.classList.toggle('hidden', !panelState.visible);

    if (panelState.visible) {
      refreshPanel();
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // UTILITAIRE
  // ═══════════════════════════════════════════════════════════════════

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ═══════════════════════════════════════════════════════════════════
  // RACCOURCI CLAVIER & INITIALISATION
  // ═══════════════════════════════════════════════════════════════════

  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && e.key === 'H') {
      e.preventDefault();
      toggleHackerPanel();
    }
  });

  // Exposer globalement
  window.toggleHackerPanel = toggleHackerPanel;
  window.hackerPanelState = panelState;

})();
