/**
 * ========================================================================
 * ShadowNet Browser — Command Palette (Palette de Commandes Hacker)
 * ========================================================================
 *
 * Accessible via Ctrl+Shift+P, cette palette permet d'exécuter
 * rapidement des commandes sans toucher la souris.
 *
 * Inspirée de VS Code / Sublime Text, adaptée pour le pentest :
 * - Lancer des scans de reconnaissance
 * - Basculer les modes proxy/tor/spoofing
 * - Encoder/décoder rapidement
 * - Lancer des payloads prédéfinis
 * - Contrôler le navigateur
 */

(function() {
  // ═══════════════════════════════════════════════════════════════════
  // REGISTRE DE COMMANDES
  // ═══════════════════════════════════════════════════════════════════

  const commands = [
    // ─── Navigation ─────────────────────────────────────────────────
    {
      id: 'new-tab',
      label: 'Nouvel onglet',
      category: 'Navigation',
      icon: '+',
      shortcut: 'Ctrl+T',
      action: () => window.createNewTab('about:blank')
    },
    {
      id: 'reload-no-cache',
      label: 'Recharger sans cache',
      category: 'Navigation',
      icon: '⟳',
      action: () => {
        const wv = document.querySelector(`#webview-${window.state.activeTabId}`);
        if (wv) wv.reloadIgnoringCache();
      }
    },

    // ─── Proxy & Interception ───────────────────────────────────────
    {
      id: 'toggle-proxy',
      label: 'Toggle Proxy d\'Interception',
      category: 'Proxy',
      icon: '⬡',
      shortcut: 'Ctrl+Shift+I',
      action: () => document.getElementById('btn-toggle-proxy').click()
    },
    {
      id: 'clear-proxy-history',
      label: 'Vider l\'historique du proxy',
      category: 'Proxy',
      icon: '⊘',
      action: async () => {
        await window.shadownet.proxy.clearHistory();
        window.showToast('info', 'Historique vidé', 'L\'historique du proxy a été effacé');
      }
    },
    {
      id: 'open-proxy-panel',
      label: 'Ouvrir le panneau Proxy',
      category: 'Proxy',
      icon: '⬡',
      action: () => window.toggleRightPanel('proxy')
    },

    // ─── Reconnaissance ─────────────────────────────────────────────
    {
      id: 'whois-lookup',
      label: 'WHOIS / DNS Lookup',
      category: 'Recon',
      icon: '⌕',
      action: () => {
        window.toggleRightPanel('recon');
        document.getElementById('btn-whois').click();
      }
    },
    {
      id: 'subdomain-enum',
      label: 'Énumérer les sous-domaines',
      category: 'Recon',
      icon: '⌕',
      action: () => {
        window.toggleRightPanel('recon');
        document.getElementById('btn-subdomains').click();
      }
    },
    {
      id: 'dir-scan',
      label: 'Scanner de répertoires (DirBuster)',
      category: 'Recon',
      icon: '⌕',
      action: () => {
        window.toggleRightPanel('recon');
        document.getElementById('btn-dirscan').click();
      }
    },
    {
      id: 'open-shodan',
      label: 'Ouvrir Shodan pour l\'IP courante',
      category: 'Recon',
      icon: '◎',
      action: () => {
        const ip = document.getElementById('url-ip').textContent;
        if (ip && ip !== '—') {
          window.createNewTab(`https://www.shodan.io/host/${ip}`);
        } else {
          window.showToast('warning', 'Aucune IP', 'Naviguez vers un site d\'abord');
        }
      }
    },
    {
      id: 'open-censys',
      label: 'Ouvrir Censys pour le domaine courant',
      category: 'Recon',
      icon: '◎',
      action: () => {
        if (window.state.currentDomain) {
          window.createNewTab(`https://search.censys.io/search?resource=hosts&q=${window.state.currentDomain}`);
        }
      }
    },
    {
      id: 'open-virustotal',
      label: 'Ouvrir VirusTotal pour le domaine',
      category: 'Recon',
      icon: '◎',
      action: () => {
        if (window.state.currentDomain) {
          window.createNewTab(`https://www.virustotal.com/gui/domain/${window.state.currentDomain}`);
        }
      }
    },

    // ─── Vulnérabilités ─────────────────────────────────────────────
    {
      id: 'scan-headers',
      label: 'Scanner les headers de sécurité',
      category: 'Vuln',
      icon: '⚠',
      action: () => {
        window.toggleRightPanel('vuln');
        document.getElementById('btn-scan-headers').click();
      }
    },
    {
      id: 'check-exposed',
      label: 'Vérifier les fichiers exposés',
      category: 'Vuln',
      icon: '⚠',
      action: () => {
        window.toggleRightPanel('vuln');
        document.getElementById('btn-check-files').click();
      }
    },
    {
      id: 'dom-sinks',
      label: 'Mapper les DOM Sinks (XSS)',
      category: 'Vuln',
      icon: '⚠',
      action: () => {
        window.toggleRightPanel('vuln');
        document.getElementById('btn-dom-sinks').click();
      }
    },

    // ─── Crypto ─────────────────────────────────────────────────────
    {
      id: 'open-crypto',
      label: 'Ouvrir le Crypto Toolkit',
      category: 'Crypto',
      icon: '⚿',
      action: () => window.toggleRightPanel('crypto')
    },
    {
      id: 'encode-b64',
      label: 'Encoder la sélection en Base64',
      category: 'Crypto',
      icon: '⚿',
      action: async () => {
        const text = await getSelectionFromWebview();
        if (text) {
          const result = await window.shadownet.crypto.encode(text, 'base64');
          navigator.clipboard.writeText(result.result);
          window.showToast('success', 'Encodé en Base64', 'Résultat copié dans le presse-papiers');
        }
      }
    },
    {
      id: 'decode-b64',
      label: 'Décoder la sélection depuis Base64',
      category: 'Crypto',
      icon: '⚿',
      action: async () => {
        const text = await getSelectionFromWebview();
        if (text) {
          const result = await window.shadownet.crypto.decode(text, 'base64');
          navigator.clipboard.writeText(result.result || result.error);
          window.showToast('success', 'Décodé depuis Base64', 'Résultat copié');
        }
      }
    },

    // ─── Session & Sécurité ─────────────────────────────────────────
    {
      id: 'randomize-fp',
      label: 'Randomiser le fingerprint',
      category: 'Session',
      icon: '◬',
      action: async () => {
        await window.shadownet.session.randomize();
        window.showToast('success', 'Fingerprint Randomisé', 'Nouvelle identité appliquée');
      }
    },
    {
      id: 'toggle-tor',
      label: 'Toggle routage Tor',
      category: 'Session',
      icon: '◎',
      action: () => document.getElementById('btn-toggle-tor').click()
    },
    {
      id: 'toggle-webrtc',
      label: 'Toggle blocage WebRTC',
      category: 'Session',
      icon: '⊘',
      action: async () => {
        window.state.webrtcBlocked = !window.state.webrtcBlocked;
        await window.shadownet.session.toggleWebRTC(window.state.webrtcBlocked);
        const indicator = document.getElementById('webrtc-indicator');
        indicator.className = `indicator ${window.state.webrtcBlocked ? 'on' : 'off'}`;
        window.showToast('info', 'WebRTC', window.state.webrtcBlocked ? 'Bloqué' : 'Autorisé');
      }
    },
    {
      id: 'burn-session',
      label: '🔥 BURN SESSION — Effacer toutes les données',
      category: 'Session',
      icon: '🔥',
      shortcut: 'Ctrl+Shift+B',
      action: () => document.getElementById('btn-burn').click()
    },

    // ─── Outils ─────────────────────────────────────────────────────
    {
      id: 'toggle-split',
      label: 'Toggle Split Screen',
      category: 'Outils',
      icon: '⊞',
      shortcut: 'F12',
      action: () => window.toggleSplitScreen()
    },
    {
      id: 'open-payloads',
      label: 'Ouvrir les Payloads',
      category: 'Outils',
      icon: '☠',
      action: () => window.toggleRightPanel('payloads')
    },
    {
      id: 'open-ai',
      label: 'Ouvrir l\'Assistant IA',
      category: 'Outils',
      icon: '◈',
      action: () => window.toggleRightPanel('ai')
    },
    {
      id: 'open-hex',
      label: 'Ouvrir le Hex Viewer',
      category: 'Outils',
      icon: '⬢',
      action: () => window.toggleRightPanel('hex')
    },
    {
      id: 'view-source',
      label: 'Voir le code source de la page',
      category: 'Outils',
      icon: '</>',
      action: () => {
        if (window.state.currentUrl) {
          window.createNewTab(`view-source:${window.state.currentUrl}`);
        }
      }
    }
  ];

  // ═══════════════════════════════════════════════════════════════════
  // INITIALISATION DE LA PALETTE
  // ═══════════════════════════════════════════════════════════════════

  const paletteInput = document.getElementById('palette-input');
  const paletteResults = document.getElementById('palette-results');
  const paletteBackdrop = document.querySelector('.palette-backdrop');
  let selectedIndex = 0;
  let filteredCommands = [...commands];

  // Fermer en cliquant sur le backdrop
  paletteBackdrop.addEventListener('click', () => {
    document.getElementById('command-palette').classList.add('hidden');
  });

  // Filtrage en temps réel
  paletteInput.addEventListener('input', () => {
    const query = paletteInput.value.toLowerCase().trim();
    selectedIndex = 0;

    if (!query) {
      filteredCommands = [...commands];
    } else {
      filteredCommands = commands.filter(cmd =>
        cmd.label.toLowerCase().includes(query) ||
        cmd.category.toLowerCase().includes(query) ||
        cmd.id.includes(query)
      );
    }

    renderPaletteResults();
  });

  // Navigation clavier
  paletteInput.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectedIndex = Math.min(selectedIndex + 1, filteredCommands.length - 1);
      renderPaletteResults();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectedIndex = Math.max(selectedIndex - 1, 0);
      renderPaletteResults();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredCommands[selectedIndex]) {
        executeCommand(filteredCommands[selectedIndex]);
      }
    }
  });

  // ═══════════════════════════════════════════════════════════════════
  // RENDU DES RÉSULTATS
  // ═══════════════════════════════════════════════════════════════════

  function renderPaletteResults() {
    paletteResults.innerHTML = filteredCommands.map((cmd, i) => `
      <div class="palette-item ${i === selectedIndex ? 'selected' : ''}" data-index="${i}">
        <span class="cmd-icon">${cmd.icon}</span>
        <span class="cmd-label">${escapeHtml(cmd.label)}</span>
        <span class="cmd-shortcut">${cmd.shortcut || cmd.category}</span>
      </div>
    `).join('');

    // Événements de clic
    paletteResults.querySelectorAll('.palette-item').forEach(el => {
      el.addEventListener('click', () => {
        const index = parseInt(el.dataset.index);
        if (filteredCommands[index]) {
          executeCommand(filteredCommands[index]);
        }
      });
      el.addEventListener('mouseenter', () => {
        selectedIndex = parseInt(el.dataset.index);
        renderPaletteResults();
      });
    });

    // Scroll vers l'élément sélectionné
    const selected = paletteResults.querySelector('.selected');
    if (selected) selected.scrollIntoView({ block: 'nearest' });
  }

  // ═══════════════════════════════════════════════════════════════════
  // EXÉCUTION DES COMMANDES
  // ═══════════════════════════════════════════════════════════════════

  function executeCommand(cmd) {
    // Fermer la palette
    document.getElementById('command-palette').classList.add('hidden');

    // Exécuter la commande
    try {
      cmd.action();
    } catch (err) {
      window.showToast('danger', 'Erreur de commande', err.message);
    }
  }

  /**
   * Récupérer le texte sélectionné dans la webview active
   */
  async function getSelectionFromWebview() {
    const webview = document.querySelector(`#webview-${window.state.activeTabId}`);
    if (!webview) return null;
    try {
      return await webview.executeJavaScript('window.getSelection().toString()');
    } catch {
      return null;
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Rendu initial
  renderPaletteResults();

})();
