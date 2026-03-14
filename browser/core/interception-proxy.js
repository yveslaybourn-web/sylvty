/**
 * ========================================================================
 * ShadowNet Browser — Module de Proxy d'Interception
 * ========================================================================
 *
 * Implémente un proxy HTTP/HTTPS intégré utilisant l'API webRequest
 * d'Electron pour intercepter, analyser et modifier le trafic réseau
 * en temps réel.
 *
 * Fonctionnalités :
 * - Interception et pause des requêtes HTTP/HTTPS
 * - Modification (tampering) des headers, body et URL à la volée
 * - Rejeu de requêtes modifiées (replay attack)
 * - Historique complet des requêtes/réponses
 * - Drop de requêtes suspectes
 *
 * Contexte sécurité : Ce module est l'équivalent du proxy de Burp Suite.
 * Il permet d'analyser le trafic entre le navigateur et le serveur cible
 * pour identifier des vulnérabilités (tokens exposés, IDOR, etc.)
 */

const { net } = require('electron');

class InterceptionProxy {
  /**
   * @param {Electron.Session} session - La session Electron à intercepter
   */
  constructor(session) {
    this._session = session;
    this._enabled = false;
    this._interceptMode = false; // Mode actif : pause les requêtes
    this._requestHistory = [];
    this._pausedRequests = new Map(); // Requêtes en attente de décision
    this._requestCounter = 0;
    this._maxHistorySize = 5000; // Limite pour éviter les fuites mémoire
    this._filters = { urls: ['<all_urls>'] };

    // Initialiser les listeners (toujours actifs pour le logging)
    this._setupListeners();
  }

  // ═══════════════════════════════════════════════════════════════════
  // CONTRÔLE DU PROXY
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Active le proxy d'interception
   * En mode actif, les requêtes sont pausées et nécessitent une action manuelle
   */
  enable() {
    this._enabled = true;
    this._interceptMode = true;
  }

  /**
   * Désactive le proxy d'interception
   * Les requêtes passent sans interruption mais sont toujours loguées
   */
  disable() {
    this._enabled = false;
    this._interceptMode = false;
    // Libérer toutes les requêtes en attente
    for (const [id, req] of this._pausedRequests) {
      if (req.callback) {
        req.callback({ cancel: false });
      }
    }
    this._pausedRequests.clear();
  }

  isEnabled() { return this._enabled; }
  getInterceptedCount() { return this._requestHistory.length; }

  // ═══════════════════════════════════════════════════════════════════
  // LISTENERS WEBREQUEST — INTERCEPTION DU TRAFIC
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Configure les listeners sur l'API webRequest d'Electron
   *
   * Flux d'interception :
   * 1. onBeforeRequest → Capture l'URL, méthode, body
   * 2. onBeforeSendHeaders → Capture et modifie les headers
   * 3. onHeadersReceived → Analyse les headers de réponse
   * 4. onCompleted / onErrorOccurred → Finalise le log
   */
  _setupListeners() {
    const webRequest = this._session.webRequest;

    // ─── PHASE 1 : Avant l'envoi de la requête ──────────────────────

    webRequest.onBeforeRequest(this._filters, (details, callback) => {
      const requestId = `req_${++this._requestCounter}`;

      // Construire l'objet de requête pour l'historique
      const requestEntry = {
        id: requestId,
        timestamp: Date.now(),
        url: details.url,
        method: details.method || 'GET',
        resourceType: details.resourceType,
        uploadData: details.uploadData ? this._parseUploadData(details.uploadData) : null,
        requestHeaders: {},
        responseHeaders: {},
        statusCode: null,
        statusLine: null,
        completed: false,
        // Métadonnées de sécurité
        security: {
          protocol: new URL(details.url).protocol,
          hostname: new URL(details.url).hostname,
          isThirdParty: false,
          flags: [] // WAF détecté, API key exposée, etc.
        }
      };

      // Stocker dans l'historique
      this._addToHistory(requestEntry);

      // Si le mode interception est actif, pauser la requête
      if (this._interceptMode && this._shouldIntercept(details)) {
        this._pausedRequests.set(requestId, {
          details,
          entry: requestEntry,
          callback
        });
        return; // Ne pas appeler le callback → requête en pause
      }

      // Sinon, laisser passer
      callback({ cancel: false });
    });

    // ─── PHASE 2 : Avant l'envoi des headers ────────────────────────

    webRequest.onBeforeSendHeaders(this._filters, (details, callback) => {
      // Enregistrer les headers de requête
      const entry = this._findInHistory(details.url, details.method);
      if (entry) {
        entry.requestHeaders = { ...details.requestHeaders };
      }

      callback({ requestHeaders: details.requestHeaders });
    });

    // ─── PHASE 3 : Réception des headers de réponse ─────────────────

    webRequest.onHeadersReceived(this._filters, (details, callback) => {
      const entry = this._findInHistory(details.url, details.method);
      if (entry) {
        entry.responseHeaders = { ...details.responseHeaders };
        entry.statusCode = details.statusCode;
        entry.statusLine = details.statusLine;

        // Analyse de sécurité automatique des headers
        this._analyzeResponseSecurity(entry);
      }

      callback({ responseHeaders: details.responseHeaders });
    });

    // ─── PHASE 4 : Requête terminée ─────────────────────────────────

    webRequest.onCompleted(this._filters, (details) => {
      const entry = this._findInHistory(details.url, details.method);
      if (entry) {
        entry.completed = true;
        entry.fromCache = details.fromCache;
      }
    });

    webRequest.onErrorOccurred(this._filters, (details) => {
      const entry = this._findInHistory(details.url, details.method);
      if (entry) {
        entry.completed = true;
        entry.error = details.error;
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════
  // ACTIONS SUR LES REQUÊTES INTERCEPTÉES
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Modifier une requête en pause avant de la transmettre
   * Équivalent de l'onglet "Intercept" de Burp Suite
   *
   * @param {string} requestId - ID de la requête pausée
   * @param {Object} modifications - { url, headers, body }
   */
  tamperRequest(requestId, modifications) {
    const paused = this._pausedRequests.get(requestId);
    if (!paused) return { error: 'Requête non trouvée ou déjà traitée' };

    // Appliquer les modifications
    if (modifications.url) {
      paused.entry.url = modifications.url;
      paused.entry.tampered = true;
    }
    if (modifications.headers) {
      paused.entry.requestHeaders = { ...paused.entry.requestHeaders, ...modifications.headers };
    }

    // Transmettre la requête modifiée
    paused.callback({
      cancel: false,
      redirectURL: modifications.url || undefined
    });

    paused.entry.security.flags.push('TAMPERED');
    this._pausedRequests.delete(requestId);

    return { success: true, requestId };
  }

  /**
   * Transmettre une requête pausée sans modification
   */
  forwardRequest(requestId) {
    const paused = this._pausedRequests.get(requestId);
    if (!paused) return { error: 'Requête non trouvée' };

    paused.callback({ cancel: false });
    this._pausedRequests.delete(requestId);

    return { success: true };
  }

  /**
   * Bloquer/supprimer une requête en pause
   * Utile pour empêcher des requêtes de tracking ou des callbacks malveillants
   */
  dropRequest(requestId) {
    const paused = this._pausedRequests.get(requestId);
    if (!paused) return { error: 'Requête non trouvée' };

    paused.callback({ cancel: true });
    paused.entry.security.flags.push('DROPPED');
    this._pausedRequests.delete(requestId);

    return { success: true };
  }

  /**
   * Rejouer une requête (Replay Attack)
   * Renvoie une requête précédemment capturée, potentiellement modifiée
   *
   * Contexte sécurité : Le rejeu de requêtes permet de tester :
   * - La protection CSRF (le token est-il vérifié ?)
   * - Les conditions de course (race conditions)
   * - La validation côté serveur (peut-on modifier les paramètres ?)
   */
  async replayRequest(requestData) {
    try {
      const { url, method, headers, body } = requestData;

      return new Promise((resolve) => {
        const request = net.request({
          url,
          method: method || 'GET',
          headers: headers || {}
        });

        let responseData = '';

        request.on('response', (response) => {
          response.on('data', (chunk) => {
            responseData += chunk.toString();
          });
          response.on('end', () => {
            resolve({
              statusCode: response.statusCode,
              headers: response.headers,
              body: responseData,
              timestamp: Date.now()
            });
          });
        });

        request.on('error', (err) => {
          resolve({ error: err.message });
        });

        if (body) {
          request.write(body);
        }
        request.end();
      });
    } catch (err) {
      return { error: err.message };
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // HISTORIQUE ET REQUÊTES
  // ═══════════════════════════════════════════════════════════════════

  getRequestHistory() {
    return this._requestHistory.slice(-200); // Retourner les 200 dernières
  }

  getPausedRequests() {
    return Array.from(this._pausedRequests.entries()).map(([id, req]) => ({
      id,
      url: req.details.url,
      method: req.details.method,
      timestamp: req.entry.timestamp
    }));
  }

  clearHistory() {
    this._requestHistory = [];
  }

  // ═══════════════════════════════════════════════════════════════════
  // ANALYSE DE SÉCURITÉ AUTOMATIQUE
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Analyse automatique des réponses HTTP pour détecter :
   * - WAF (Web Application Firewalls)
   * - Clés API exposées dans les headers
   * - En-têtes de sécurité manquants
   * - Informations de version de serveur
   */
  _analyzeResponseSecurity(entry) {
    const headers = entry.responseHeaders || {};

    // Détection de WAF
    const wafSignatures = {
      'cloudflare': ['cf-ray', 'cf-cache-status'],
      'akamai': ['x-akamai-transformed'],
      'aws-waf': ['x-amzn-requestid'],
      'sucuri': ['x-sucuri-id'],
      'imperva': ['x-iinfo'],
      'f5-big-ip': ['x-cnection'],
      'barracuda': ['barra_counter_session']
    };

    for (const [waf, sigs] of Object.entries(wafSignatures)) {
      for (const sig of sigs) {
        if (Object.keys(headers).some(h => h.toLowerCase() === sig)) {
          entry.security.flags.push(`WAF:${waf.toUpperCase()}`);
        }
      }
    }

    // Détection de clés API dans les headers de réponse
    const apiKeyPatterns = [
      /api[_-]?key/i,
      /authorization/i,
      /x-api-token/i,
      /access[_-]?token/i
    ];

    for (const [header, values] of Object.entries(headers)) {
      for (const pattern of apiKeyPatterns) {
        if (pattern.test(header)) {
          entry.security.flags.push('API_KEY_IN_HEADERS');
        }
      }
    }

    // En-têtes de sécurité manquants
    const requiredHeaders = [
      'strict-transport-security',
      'content-security-policy',
      'x-content-type-options',
      'x-frame-options'
    ];

    const headerKeys = Object.keys(headers).map(h => h.toLowerCase());
    for (const rh of requiredHeaders) {
      if (!headerKeys.includes(rh)) {
        entry.security.flags.push(`MISSING:${rh.toUpperCase()}`);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // UTILITAIRES INTERNES
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Détermine si une requête doit être interceptée
   * Filtre les ressources internes (file://, chrome://, devtools://)
   */
  _shouldIntercept(details) {
    const url = details.url;
    // Ne pas intercepter les URLs internes du navigateur
    if (url.startsWith('file://') || url.startsWith('chrome://') ||
        url.startsWith('devtools://') || url.startsWith('data:')) {
      return false;
    }
    // Intercepter uniquement les requêtes de type document, xhr, fetch
    const interceptTypes = ['mainFrame', 'subFrame', 'xmlhttprequest', 'other'];
    return interceptTypes.includes(details.resourceType);
  }

  /**
   * Parse les données d'upload d'une requête POST
   * Convertit les buffers en chaînes lisibles pour l'inspection
   */
  _parseUploadData(uploadData) {
    if (!uploadData || !Array.isArray(uploadData)) return null;
    return uploadData.map(item => {
      if (item.bytes) {
        return item.bytes.toString('utf-8');
      }
      if (item.file) {
        return `[Fichier: ${item.file}]`;
      }
      return '[Données binaires]';
    }).join('');
  }

  /**
   * Recherche une entrée dans l'historique par URL et méthode
   * Retourne la plus récente correspondance
   */
  _findInHistory(url, method) {
    for (let i = this._requestHistory.length - 1; i >= 0; i--) {
      const entry = this._requestHistory[i];
      if (entry.url === url && (!method || entry.method === method)) {
        return entry;
      }
    }
    return null;
  }

  /**
   * Ajouter une entrée à l'historique avec gestion de la taille
   */
  _addToHistory(entry) {
    this._requestHistory.push(entry);
    // Éviter les fuites mémoire en limitant la taille
    if (this._requestHistory.length > this._maxHistorySize) {
      this._requestHistory = this._requestHistory.slice(-Math.floor(this._maxHistorySize * 0.8));
    }
  }
}

module.exports = { InterceptionProxy };
