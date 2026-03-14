/**
 * ========================================================================
 * ShadowNet Browser — Script Injector Engine
 * ========================================================================
 *
 * Bibliothèque persistante de snippets JS personnalisés qui peuvent
 * être injectés automatiquement sur des domaines spécifiques.
 *
 * Fonctionnalités :
 * - Stockage de scripts personnalisés avec ciblage par domaine
 * - Injection automatique au chargement de page
 * - Présets de scripts utiles pour le pentest
 * - Conversion de requêtes interceptées en scripts Python/Node.js/cURL
 *
 * Contexte sécurité : Permet de persister des payloads de test
 * entre les sessions et de les réexécuter automatiquement.
 */

class ScriptInjectorEngine {
  constructor() {
    // Bibliothèque de scripts personnalisés
    // Format: { id, name, domain, code, enabled, runAt }
    this._scripts = new Map();
    this._counter = 0;

    // Charger les scripts prédéfinis
    this._loadPresets();
  }

  // ═══════════════════════════════════════════════════════════════════
  // GESTION DES SCRIPTS
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Ajouter un script à la bibliothèque
   * @param {Object} script - { name, domain, code, runAt }
   *   domain: '*' pour tous les domaines, ou un pattern glob
   *   runAt: 'document_start' | 'document_end' | 'document_idle'
   */
  addScript({ name, domain = '*', code, runAt = 'document_end', enabled = true }) {
    const id = `script_${++this._counter}`;
    this._scripts.set(id, {
      id, name, domain, code, runAt, enabled,
      createdAt: Date.now(),
      executionCount: 0
    });
    return id;
  }

  /**
   * Retirer un script
   */
  removeScript(id) {
    return this._scripts.delete(id);
  }

  /**
   * Toggle un script
   */
  toggleScript(id) {
    const script = this._scripts.get(id);
    if (script) {
      script.enabled = !script.enabled;
      return script.enabled;
    }
    return false;
  }

  /**
   * Obtenir tous les scripts
   */
  getAllScripts() {
    return Array.from(this._scripts.values());
  }

  /**
   * Obtenir les scripts applicables pour un domaine donné
   */
  getScriptsForDomain(domain) {
    return Array.from(this._scripts.values()).filter(s => {
      if (!s.enabled) return false;
      if (s.domain === '*') return true;
      // Matching de domaine simple
      if (s.domain.startsWith('*.')) {
        return domain.endsWith(s.domain.slice(1)) || domain === s.domain.slice(2);
      }
      return domain === s.domain || domain.endsWith('.' + s.domain);
    });
  }

  /**
   * Incrémenter le compteur d'exécution
   */
  recordExecution(id) {
    const script = this._scripts.get(id);
    if (script) script.executionCount++;
  }

  // ═══════════════════════════════════════════════════════════════════
  // CONVERSION DE REQUÊTES EN CODE
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Convertir une requête HTTP interceptée en code Python (requests)
   */
  toPython(request) {
    const { url, method, requestHeaders, uploadData } = request;
    const headers = requestHeaders || {};

    let code = `import requests\n\n`;
    code += `url = "${url}"\n`;

    // Headers
    const headerEntries = Object.entries(headers);
    if (headerEntries.length > 0) {
      code += `headers = {\n`;
      for (const [key, value] of headerEntries) {
        const val = Array.isArray(value) ? value[0] : value;
        code += `    "${key}": "${String(val).replace(/"/g, '\\"')}",\n`;
      }
      code += `}\n`;
    }

    // Body
    if (uploadData) {
      code += `data = """${uploadData}"""\n`;
    }

    // Requête
    const methodLower = (method || 'GET').toLowerCase();
    code += `\nresponse = requests.${methodLower}(\n`;
    code += `    url,\n`;
    if (headerEntries.length > 0) code += `    headers=headers,\n`;
    if (uploadData) code += `    data=data,\n`;
    code += `    verify=False  # Désactiver la vérification SSL pour le pentest\n`;
    code += `)\n\n`;
    code += `print(f"Status: {response.status_code}")\n`;
    code += `print(f"Headers: {dict(response.headers)}")\n`;
    code += `print(f"Body: {response.text[:2000]}")\n`;

    return code;
  }

  /**
   * Convertir une requête HTTP en code Node.js (fetch)
   */
  toNodeJS(request) {
    const { url, method, requestHeaders, uploadData } = request;
    const headers = requestHeaders || {};

    let code = `// Node.js (fetch)\n`;
    code += `const response = await fetch("${url}", {\n`;
    code += `  method: "${method || 'GET'}",\n`;

    const headerEntries = Object.entries(headers);
    if (headerEntries.length > 0) {
      code += `  headers: {\n`;
      for (const [key, value] of headerEntries) {
        const val = Array.isArray(value) ? value[0] : value;
        code += `    "${key}": "${String(val).replace(/"/g, '\\"')}",\n`;
      }
      code += `  },\n`;
    }

    if (uploadData) {
      code += `  body: ${JSON.stringify(uploadData)},\n`;
    }

    code += `});\n\n`;
    code += `console.log("Status:", response.status);\n`;
    code += `const data = await response.text();\n`;
    code += `console.log("Body:", data.substring(0, 2000));\n`;

    return code;
  }

  /**
   * Convertir une requête HTTP en commande cURL
   */
  toCurl(request) {
    const { url, method, requestHeaders, uploadData } = request;
    const headers = requestHeaders || {};

    let cmd = `curl -X ${method || 'GET'}`;
    cmd += ` \\\n  "${url}"`;

    for (const [key, value] of Object.entries(headers)) {
      const val = Array.isArray(value) ? value[0] : value;
      cmd += ` \\\n  -H "${key}: ${String(val).replace(/"/g, '\\"')}"`;
    }

    if (uploadData) {
      cmd += ` \\\n  -d '${uploadData.replace(/'/g, "\\'")}'`;
    }

    cmd += ` \\\n  -k --verbose`; // -k = insecure, skip SSL verification

    return cmd;
  }

  // ═══════════════════════════════════════════════════════════════════
  // SCRIPTS PRÉDÉFINIS
  // ═══════════════════════════════════════════════════════════════════

  _loadPresets() {
    // ─── Extraction de formulaires ────────────────────────────
    this.addScript({
      name: '📋 Extraire tous les formulaires',
      domain: '*',
      enabled: false,
      code: `
        (function() {
          const forms = document.querySelectorAll('form');
          const data = [];
          forms.forEach((f, i) => {
            const inputs = [...f.querySelectorAll('input, textarea, select')].map(inp => ({
              name: inp.name, type: inp.type, value: inp.value, id: inp.id
            }));
            data.push({
              index: i, action: f.action, method: f.method,
              id: f.id, inputs
            });
          });
          console.table(data);
          console.log('[ShadowNet] ' + forms.length + ' formulaire(s) extraits');
          return data;
        })()
      `
    });

    // ─── Extraction de liens ──────────────────────────────────
    this.addScript({
      name: '🔗 Extraire tous les liens',
      domain: '*',
      enabled: false,
      code: `
        (function() {
          const links = [...document.querySelectorAll('a[href]')].map(a => ({
            text: a.textContent.trim().substring(0, 50),
            href: a.href,
            target: a.target,
            rel: a.rel
          }));
          console.table(links);
          console.log('[ShadowNet] ' + links.length + ' lien(s) extraits');
          return links;
        })()
      `
    });

    // ─── Cookies Dumper ───────────────────────────────────────
    this.addScript({
      name: '🍪 Dump des cookies',
      domain: '*',
      enabled: false,
      code: `
        (function() {
          const cookies = document.cookie.split(';').map(c => {
            const [name, ...value] = c.trim().split('=');
            return { name: name.trim(), value: value.join('=') };
          });
          console.table(cookies);
          console.log('[ShadowNet] ' + cookies.length + ' cookie(s) trouvé(s)');
          return cookies;
        })()
      `
    });

    // ─── LocalStorage/SessionStorage Dumper ────────────────────
    this.addScript({
      name: '💾 Dump Storage (Local + Session)',
      domain: '*',
      enabled: false,
      code: `
        (function() {
          const local = {};
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            local[key] = localStorage.getItem(key);
          }
          const session = {};
          for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            session[key] = sessionStorage.getItem(key);
          }
          console.log('[ShadowNet] localStorage:', local);
          console.log('[ShadowNet] sessionStorage:', session);
          return { localStorage: local, sessionStorage: session };
        })()
      `
    });

    // ─── XSS Probe automatique ────────────────────────────────
    this.addScript({
      name: '⚡ XSS Probe (inputs reflétés)',
      domain: '*',
      enabled: false,
      code: `
        (function() {
          const probe = 'sn' + Math.random().toString(36).substring(7);
          const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea');
          let probed = 0;

          inputs.forEach(input => {
            const originalValue = input.value;
            input.value = probe;
            // Vérifier si le probe apparaît dans le DOM après soumission
            input.dispatchEvent(new Event('input', { bubbles: true }));
            probed++;
          });

          // Vérifier après un court délai si le probe est reflété
          setTimeout(() => {
            const html = document.documentElement.innerHTML;
            if (html.includes(probe)) {
              console.warn('[ShadowNet] ⚠ INPUT REFLÉTÉ DÉTECTÉ! Probe: ' + probe);
              console.warn('[ShadowNet] XSS potentiel — Tester avec des payloads');
            } else {
              console.log('[ShadowNet] Aucune réflexion détectée pour ' + probed + ' input(s)');
            }
          }, 1000);

          return { probe, inputsProbed: probed };
        })()
      `
    });

    // ─── Intercepter les requêtes XHR/Fetch ───────────────────
    this.addScript({
      name: '🌐 Intercepter XHR/Fetch',
      domain: '*',
      enabled: false,
      code: `
        (function() {
          if (window.__sn_xhr_hooked) return 'already_hooked';
          window.__sn_xhr_hooked = true;
          window.__sn_requests = [];

          // Hook XMLHttpRequest
          const origOpen = XMLHttpRequest.prototype.open;
          const origSend = XMLHttpRequest.prototype.send;

          XMLHttpRequest.prototype.open = function(method, url) {
            this.__sn_method = method;
            this.__sn_url = url;
            return origOpen.apply(this, arguments);
          };

          XMLHttpRequest.prototype.send = function(body) {
            window.__sn_requests.push({
              type: 'XHR', method: this.__sn_method,
              url: this.__sn_url, body: body,
              timestamp: Date.now()
            });
            console.log('[ShadowNet] XHR:', this.__sn_method, this.__sn_url);
            return origSend.apply(this, arguments);
          };

          // Hook Fetch
          const origFetch = window.fetch;
          window.fetch = function(url, opts) {
            window.__sn_requests.push({
              type: 'Fetch', method: opts?.method || 'GET',
              url: typeof url === 'string' ? url : url.url,
              body: opts?.body, timestamp: Date.now()
            });
            console.log('[ShadowNet] Fetch:', opts?.method || 'GET', url);
            return origFetch.apply(this, arguments);
          };

          console.log('[ShadowNet] XHR/Fetch interceptor installé');
          return 'hooks_installed';
        })()
      `
    });
  }
}

// Exporter
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ScriptInjectorEngine };
}
if (typeof window !== 'undefined') {
  window.ScriptInjectorEngine = ScriptInjectorEngine;
}
