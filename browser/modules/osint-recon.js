/**
 * ========================================================================
 * ShadowNet Browser — Module OSINT & Reconnaissance
 * ========================================================================
 *
 * Module de reconnaissance passive et active pour la collecte
 * d'informations sur les cibles.
 *
 * Fonctionnalités :
 * - Détection de technologies (Wappalyzer-style)
 * - WHOIS / DNS lookup
 * - Énumération de sous-domaines via Certificate Transparency
 * - Scanner de répertoires cachés (DirBuster lite)
 * - Extraction d'informations depuis les headers HTTP
 *
 * Contexte sécurité : La reconnaissance est la première phase de tout
 * test de pénétration. Plus on collecte d'informations sur la cible,
 * plus les attaques seront ciblées et efficaces.
 */

class OSINTRecon {
  constructor() {
    // Signatures étendues pour la détection de technologies
    this.techSignatures = this._buildTechSignatures();

    // Wordlist par défaut pour le scan de répertoires
    this.defaultWordlist = [
      // Fichiers de configuration exposés
      '.git/HEAD', '.git/config', '.gitignore',
      '.env', '.env.local', '.env.production', '.env.backup',
      '.htaccess', '.htpasswd',
      'web.config', 'wp-config.php', 'wp-config.php.bak',
      'config.php', 'config.php.bak', 'config.yml', 'config.json',

      // Fichiers d'information
      'robots.txt', 'sitemap.xml', 'sitemap_index.xml',
      'crossdomain.xml', 'clientaccesspolicy.xml',
      '.well-known/security.txt', '.well-known/openid-configuration',
      'humans.txt', 'manifest.json', 'browserconfig.xml',

      // Panneaux d'administration
      'admin/', 'admin/login', 'administrator/',
      'wp-admin/', 'wp-login.php',
      'phpmyadmin/', 'pma/', 'adminer.php',
      'cpanel', 'webmail/',

      // APIs et documentation
      'api/', 'api/v1/', 'api/v2/', 'api/v3/',
      'graphql', 'graphiql',
      'swagger.json', 'swagger.yaml', 'swagger-ui/',
      'openapi.json', 'api-docs/',

      // Fichiers de build/package
      'package.json', 'package-lock.json',
      'composer.json', 'composer.lock',
      'Gemfile', 'Gemfile.lock',
      'requirements.txt', 'Pipfile',
      'yarn.lock', 'pnpm-lock.yaml',

      // Fichiers de debug/info
      'phpinfo.php', 'info.php', 'test.php',
      'debug/', 'debug.log', 'error.log',
      'server-status', 'server-info',
      'trace.axd', 'elmah.axd',

      // Fichiers sensibles divers
      '.DS_Store', 'Thumbs.db',
      '.svn/', '.svn/entries',
      '.hg/', '.hg/hgrc',
      'backup/', 'backups/', 'bak/',
      'db/', 'database/', 'dump/', 'sql/',
      'old/', 'temp/', 'tmp/', 'test/',
      'upload/', 'uploads/', 'files/',
      'cgi-bin/', 'includes/',
      '.bash_history', '.ssh/',
      'id_rsa', 'id_dsa'
    ];
  }

  /**
   * Détecter les technologies d'un site à partir du HTML et des headers
   *
   * @param {Object} params - { headers, html, scripts, cookies, meta }
   * @returns {Array} Technologies détectées avec catégorie et confiance
   */
  detectTechnologies({ headers = {}, html = '', scripts = [], cookies = [], meta = {} }) {
    const detected = [];
    const context = {
      headers: JSON.stringify(headers).toLowerCase(),
      html: html.toLowerCase(),
      scripts: scripts.join(' ').toLowerCase(),
      cookies: cookies.join(' ').toLowerCase(),
      meta: JSON.stringify(meta).toLowerCase()
    };

    for (const sig of this.techSignatures) {
      let matches = 0;
      let totalChecks = sig.checks.length;

      for (const check of sig.checks) {
        if (check.test(context)) {
          matches++;
        }
      }

      if (matches > 0) {
        const confidence = Math.round((matches / totalChecks) * 100);
        detected.push({
          name: sig.name,
          category: sig.category,
          confidence,
          version: sig.extractVersion ? sig.extractVersion(context) : null,
          website: sig.website || null,
          cpe: sig.cpe || null // Common Platform Enumeration pour CVE lookup
        });
      }
    }

    // Trier par confiance décroissante
    detected.sort((a, b) => b.confidence - a.confidence);

    return detected;
  }

  /**
   * Analyser les headers HTTP pour extraire des informations de sécurité
   */
  analyzeSecurityPosture(headers) {
    const report = {
      score: 100,  // Score de sécurité sur 100
      grade: 'A',
      findings: [],
      recommendations: []
    };

    const headerKeys = Object.keys(headers).map(h => h.toLowerCase());

    // Vérifications critiques
    const checks = [
      {
        header: 'strict-transport-security',
        severity: 'critical',
        points: 15,
        desc: 'HSTS non configuré — vulnérable au downgrade HTTPS',
        fix: 'Ajouter: Strict-Transport-Security: max-age=31536000; includeSubDomains'
      },
      {
        header: 'content-security-policy',
        severity: 'critical',
        points: 20,
        desc: 'CSP absent — vulnérable aux XSS et injections',
        fix: 'Configurer une Content-Security-Policy restrictive'
      },
      {
        header: 'x-content-type-options',
        severity: 'high',
        points: 10,
        desc: 'X-Content-Type-Options absent — vulnérable au MIME sniffing',
        fix: 'Ajouter: X-Content-Type-Options: nosniff'
      },
      {
        header: 'x-frame-options',
        severity: 'high',
        points: 10,
        desc: 'X-Frame-Options absent — vulnérable au clickjacking',
        fix: 'Ajouter: X-Frame-Options: DENY ou SAMEORIGIN'
      },
      {
        header: 'referrer-policy',
        severity: 'medium',
        points: 5,
        desc: 'Referrer-Policy absent — fuite potentielle de données',
        fix: 'Ajouter: Referrer-Policy: strict-origin-when-cross-origin'
      },
      {
        header: 'permissions-policy',
        severity: 'medium',
        points: 5,
        desc: 'Permissions-Policy absent — APIs navigateur non restreintes',
        fix: 'Configurer Permissions-Policy pour restreindre les APIs'
      }
    ];

    for (const check of checks) {
      if (!headerKeys.includes(check.header)) {
        report.score -= check.points;
        report.findings.push({
          severity: check.severity,
          header: check.header,
          description: check.desc
        });
        report.recommendations.push(check.fix);
      }
    }

    // Vérifier les headers dangereux (information disclosure)
    const dangerousHeaders = {
      'server': 'Le header Server expose la version du serveur',
      'x-powered-by': 'X-Powered-By expose la technologie backend',
      'x-aspnet-version': 'Version ASP.NET exposée',
      'x-aspnetmvc-version': 'Version ASP.NET MVC exposée'
    };

    for (const [header, desc] of Object.entries(dangerousHeaders)) {
      if (headerKeys.includes(header)) {
        report.score -= 3;
        report.findings.push({
          severity: 'low',
          header,
          description: desc,
          value: headers[header]
        });
      }
    }

    // Calculer le grade
    report.score = Math.max(0, report.score);
    if (report.score >= 90) report.grade = 'A';
    else if (report.score >= 75) report.grade = 'B';
    else if (report.score >= 60) report.grade = 'C';
    else if (report.score >= 40) report.grade = 'D';
    else report.grade = 'F';

    return report;
  }

  /**
   * Construire la base de signatures de technologies
   */
  _buildTechSignatures() {
    return [
      // ─── Serveurs Web ──────────────────────────────────────────
      {
        name: 'Apache', category: 'Serveur Web', website: 'https://httpd.apache.org',
        cpe: 'cpe:/a:apache:http_server',
        checks: [
          ctx => ctx.headers.includes('apache'),
          ctx => ctx.headers.includes('mod_'),
        ],
        extractVersion: ctx => {
          const match = ctx.headers.match(/apache\/([\d.]+)/);
          return match ? match[1] : null;
        }
      },
      {
        name: 'Nginx', category: 'Serveur Web', website: 'https://nginx.org',
        cpe: 'cpe:/a:nginx:nginx',
        checks: [
          ctx => ctx.headers.includes('nginx'),
        ],
        extractVersion: ctx => {
          const match = ctx.headers.match(/nginx\/([\d.]+)/);
          return match ? match[1] : null;
        }
      },
      {
        name: 'Microsoft IIS', category: 'Serveur Web',
        cpe: 'cpe:/a:microsoft:iis',
        checks: [
          ctx => ctx.headers.includes('microsoft-iis'),
          ctx => ctx.headers.includes('x-aspnet'),
        ]
      },

      // ─── CDN / WAF ────────────────────────────────────────────
      {
        name: 'Cloudflare', category: 'CDN/WAF',
        checks: [
          ctx => ctx.headers.includes('cloudflare'),
          ctx => ctx.headers.includes('cf-ray'),
          ctx => ctx.headers.includes('cf-cache-status'),
        ]
      },
      {
        name: 'AWS CloudFront', category: 'CDN',
        checks: [
          ctx => ctx.headers.includes('cloudfront'),
          ctx => ctx.headers.includes('x-amz-cf'),
        ]
      },

      // ─── Frameworks Frontend ──────────────────────────────────
      {
        name: 'React', category: 'Framework JS',
        checks: [
          ctx => ctx.html.includes('data-reactroot') || ctx.html.includes('data-reactid'),
          ctx => ctx.html.includes('__react'),
          ctx => ctx.scripts.includes('react.'),
        ]
      },
      {
        name: 'Vue.js', category: 'Framework JS',
        checks: [
          ctx => ctx.html.includes('data-v-'),
          ctx => ctx.scripts.includes('vue.'),
          ctx => ctx.html.includes('id="app"') && ctx.scripts.includes('vue'),
        ]
      },
      {
        name: 'Angular', category: 'Framework JS',
        checks: [
          ctx => ctx.html.includes('ng-version'),
          ctx => ctx.html.includes('ng-app'),
          ctx => ctx.scripts.includes('angular'),
        ]
      },
      {
        name: 'jQuery', category: 'Librairie JS',
        checks: [
          ctx => ctx.scripts.includes('jquery'),
          ctx => ctx.html.includes('jquery'),
        ]
      },

      // ─── CMS ──────────────────────────────────────────────────
      {
        name: 'WordPress', category: 'CMS', cpe: 'cpe:/a:wordpress:wordpress',
        checks: [
          ctx => ctx.html.includes('wp-content'),
          ctx => ctx.html.includes('wp-includes'),
          ctx => ctx.html.includes('wp-json'),
          ctx => ctx.cookies.includes('wordpress'),
        ]
      },
      {
        name: 'Drupal', category: 'CMS', cpe: 'cpe:/a:drupal:drupal',
        checks: [
          ctx => ctx.headers.includes('x-drupal'),
          ctx => ctx.html.includes('drupal.js'),
          ctx => ctx.html.includes('drupal.settings'),
        ]
      },

      // ─── Backend ──────────────────────────────────────────────
      {
        name: 'PHP', category: 'Langage',
        checks: [
          ctx => ctx.headers.includes('x-powered-by') && ctx.headers.includes('php'),
          ctx => ctx.cookies.includes('phpsessid'),
        ]
      },
      {
        name: 'Express.js', category: 'Framework Backend',
        checks: [
          ctx => ctx.headers.includes('x-powered-by') && ctx.headers.includes('express'),
        ]
      },
      {
        name: 'Django', category: 'Framework Backend',
        checks: [
          ctx => ctx.cookies.includes('csrftoken'),
          ctx => ctx.html.includes('csrfmiddlewaretoken'),
        ]
      },
      {
        name: 'Laravel', category: 'Framework Backend',
        checks: [
          ctx => ctx.cookies.includes('laravel_session'),
          ctx => ctx.cookies.includes('xsrf-token'),
        ]
      },
      {
        name: 'ASP.NET', category: 'Framework Backend',
        checks: [
          ctx => ctx.headers.includes('x-aspnet-version'),
          ctx => ctx.cookies.includes('asp.net'),
          ctx => ctx.html.includes('__viewstate'),
        ]
      },
    ];
  }
}

// Exporter
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { OSINTRecon };
}
if (typeof window !== 'undefined') {
  window.OSINTRecon = OSINTRecon;
}
