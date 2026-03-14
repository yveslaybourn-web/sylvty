/**
 * ════════════════════════════════════════════════════════════════════════
 * ShadowNet Browser — Export Engine
 * ════════════════════════════════════════════════════════════════════════
 *
 * Module de génération de rapports de pentest en plusieurs formats.
 *
 * Fonctionnalités :
 * - Export JSON (données brutes, pretty-printed)
 * - Export Markdown (rapport structuré lisible)
 * - Export HTML (rapport autonome avec thème cyberpunk)
 *
 * Contexte sécurité : La documentation des résultats est une phase
 * critique du pentest. Ce module génère des rapports professionnels
 * incluant les vulnérabilités, preuves de concept et recommandations.
 */

class ExportEngine {
  /**
   * Exporte les données en JSON formaté (pretty-printed)
   * @param {Object} data - Données du rapport de pentest
   * @returns {string} JSON indenté
   */
  toJSON(data) {
    return JSON.stringify(data, null, 2);
  }

  /**
   * Génère un rapport Markdown structuré pour le pentest
   * @param {Object} data - Données du rapport de pentest
   * @returns {string} Rapport au format Markdown
   */
  toMarkdown(data) {
    const lines = [];

    // ═══ En-tête du rapport ═══
    lines.push('# ShadowNet — Rapport de Pentest');
    lines.push('');

    // ═══ Informations générales ═══
    lines.push('## Informations Générales');
    lines.push('');
    lines.push(`- **Date** : ${data.date || 'Non spécifiée'}`);
    lines.push(`- **Cible** : ${data.target || 'Non spécifiée'}`);
    lines.push(`- **Scope** : ${data.scope ? data.scope.join(', ') : 'Non défini'}`);
    lines.push('');

    // ═══ Résultats de reconnaissance ═══
    lines.push('## Résultats de Reconnaissance');
    lines.push('');

    // Tech stack détecté
    if (data.techStack && data.techStack.length > 0) {
      lines.push('### Stack Technologique');
      lines.push('');
      for (const tech of data.techStack) {
        lines.push(`- **${tech.name}** (${tech.category})`);
      }
      lines.push('');
    }

    // Enregistrements DNS
    if (data.dns) {
      lines.push('### DNS');
      lines.push('');
      if (data.dns.addresses && data.dns.addresses.length > 0) {
        lines.push(`- **Adresses** : ${data.dns.addresses.join(', ')}`);
      }
      if (data.dns.mx && data.dns.mx.length > 0) {
        lines.push(`- **MX** : ${data.dns.mx.join(', ')}`);
      }
      if (data.dns.ns && data.dns.ns.length > 0) {
        lines.push(`- **NS** : ${data.dns.ns.join(', ')}`);
      }
      if (data.dns.txt && data.dns.txt.length > 0) {
        lines.push(`- **TXT** : ${data.dns.txt.join(', ')}`);
      }
      lines.push('');
    }

    // Sous-domaines découverts
    if (data.subdomains && data.subdomains.length > 0) {
      lines.push('### Sous-domaines');
      lines.push('');
      for (const sub of data.subdomains) {
        lines.push(`- ${sub}`);
      }
      lines.push('');
    }

    // ═══ Vulnérabilités détectées ═══
    lines.push('## Vulnérabilités Détectées');
    lines.push('');

    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      lines.push('| Sévérité | Titre | Description |');
      lines.push('|----------|-------|-------------|');
      for (const vuln of data.vulnerabilities) {
        const severity = vuln.severity ? vuln.severity.toUpperCase() : 'N/A';
        const title = vuln.title || 'Sans titre';
        const description = vuln.description || '';
        lines.push(`| ${severity} | ${title} | ${description} |`);
      }
      lines.push('');
    } else {
      lines.push('Aucune vulnérabilité détectée.');
      lines.push('');
    }

    // ═══ Requêtes interceptées ═══
    lines.push('## Requêtes Interceptées');
    lines.push('');

    if (data.requests && data.requests.length > 0) {
      lines.push(`**Total** : ${data.requests.length} requête(s)`);
      lines.push('');
      lines.push('### Requêtes Notables');
      lines.push('');
      // Afficher les requêtes avec des codes de statut intéressants (erreurs, redirections)
      const notable = data.requests.filter(
        (r) => r.statusCode >= 300 || r.statusCode === 0
      );
      const toShow = notable.length > 0 ? notable : data.requests.slice(0, 10);
      for (const req of toShow) {
        lines.push(`- \`${req.method} ${req.url}\` → **${req.statusCode}**`);
      }
      lines.push('');
    } else {
      lines.push('Aucune requête interceptée.');
      lines.push('');
    }

    // ═══ Secrets exposés ═══
    lines.push('## Secrets Exposés');
    lines.push('');

    if (data.secrets && data.secrets.length > 0) {
      for (const secret of data.secrets) {
        lines.push(`- **${secret.type}** : \`${secret.value}\` _(source: ${secret.source})_`);
      }
      lines.push('');
    } else {
      lines.push('Aucun secret exposé détecté.');
      lines.push('');
    }

    // ═══ Notes de l'utilisateur ═══
    lines.push('## Notes');
    lines.push('');
    lines.push(data.notes || 'Aucune note.');
    lines.push('');

    // ═══ Findings détaillés ═══
    lines.push('## Findings');
    lines.push('');

    if (data.findings && data.findings.length > 0) {
      for (const finding of data.findings) {
        lines.push(`### ${finding.title || 'Finding sans titre'}`);
        lines.push('');
        lines.push(`**Sévérité** : ${finding.severity ? finding.severity.toUpperCase() : 'N/A'}`);
        lines.push('');
        lines.push(finding.description || 'Pas de description.');
        lines.push('');

        if (finding.poc) {
          lines.push('**Preuve de Concept (PoC)** :');
          lines.push('');
          lines.push('```');
          lines.push(finding.poc);
          lines.push('```');
          lines.push('');
        }

        if (finding.recommendation) {
          lines.push(`**Recommandation** : ${finding.recommendation}`);
          lines.push('');
        }
      }
    } else {
      lines.push('Aucun finding détaillé.');
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Génère un rapport HTML autonome avec thème cyberpunk
   * @param {Object} data - Données du rapport de pentest
   * @returns {string} Document HTML complet
   */
  toHTML(data) {
    // ═══ Couleurs par niveau de sévérité ═══
    const severityColors = {
      critical: '#ff0040',
      high: '#ff8c00',
      medium: '#ffd700',
      low: '#00e5ff',
      info: '#888888',
    };

    /**
     * Génère un badge HTML coloré selon la sévérité
     */
    const severityBadge = (severity) => {
      const sev = (severity || 'info').toLowerCase();
      const color = severityColors[sev] || severityColors.info;
      return `<span class="badge" style="background:${color};color:#000;padding:2px 8px;border-radius:3px;font-weight:bold;font-size:0.85em;">${sev.toUpperCase()}</span>`;
    };

    /**
     * Échappe les caractères HTML dangereux
     */
    const esc = (str) => {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    };

    // ═══ Construction des sections HTML ═══

    // Section : Informations générales
    const infoSection = `
      <section>
        <h2>Informations Générales</h2>
        <table class="info-table">
          <tr><td class="label">Date</td><td>${esc(data.date) || 'Non spécifiée'}</td></tr>
          <tr><td class="label">Cible</td><td>${esc(data.target) || 'Non spécifiée'}</td></tr>
          <tr><td class="label">Scope</td><td>${data.scope ? data.scope.map(esc).join(', ') : 'Non défini'}</td></tr>
        </table>
      </section>`;

    // Section : Reconnaissance
    let reconHTML = '<section><h2>Résultats de Reconnaissance</h2>';

    if (data.techStack && data.techStack.length > 0) {
      reconHTML += '<h3>Stack Technologique</h3><ul>';
      for (const tech of data.techStack) {
        reconHTML += `<li><strong>${esc(tech.name)}</strong> (${esc(tech.category)})</li>`;
      }
      reconHTML += '</ul>';
    }

    if (data.dns) {
      reconHTML += '<h3>DNS</h3><ul>';
      if (data.dns.addresses && data.dns.addresses.length > 0) {
        reconHTML += `<li><strong>Adresses</strong> : ${data.dns.addresses.map(esc).join(', ')}</li>`;
      }
      if (data.dns.mx && data.dns.mx.length > 0) {
        reconHTML += `<li><strong>MX</strong> : ${data.dns.mx.map(esc).join(', ')}</li>`;
      }
      if (data.dns.ns && data.dns.ns.length > 0) {
        reconHTML += `<li><strong>NS</strong> : ${data.dns.ns.map(esc).join(', ')}</li>`;
      }
      if (data.dns.txt && data.dns.txt.length > 0) {
        reconHTML += `<li><strong>TXT</strong> : ${data.dns.txt.map(esc).join(', ')}</li>`;
      }
      reconHTML += '</ul>';
    }

    if (data.subdomains && data.subdomains.length > 0) {
      reconHTML += '<h3>Sous-domaines</h3><ul>';
      for (const sub of data.subdomains) {
        reconHTML += `<li>${esc(sub)}</li>`;
      }
      reconHTML += '</ul>';
    }

    reconHTML += '</section>';

    // Section : Vulnérabilités
    let vulnHTML = '<section><h2>Vulnérabilités Détectées</h2>';
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
      vulnHTML += `
        <table class="vuln-table">
          <thead><tr><th>Sévérité</th><th>Titre</th><th>Description</th></tr></thead>
          <tbody>`;
      for (const vuln of data.vulnerabilities) {
        vulnHTML += `<tr>
          <td>${severityBadge(vuln.severity)}</td>
          <td>${esc(vuln.title)}</td>
          <td>${esc(vuln.description)}</td>
        </tr>`;
      }
      vulnHTML += '</tbody></table>';
    } else {
      vulnHTML += '<p class="empty">Aucune vulnérabilité détectée.</p>';
    }
    vulnHTML += '</section>';

    // Section : Requêtes interceptées
    let reqHTML = '<section><h2>Requêtes Interceptées</h2>';
    if (data.requests && data.requests.length > 0) {
      reqHTML += `<p><strong>Total</strong> : ${data.requests.length} requête(s)</p>`;
      const notable = data.requests.filter(
        (r) => r.statusCode >= 300 || r.statusCode === 0
      );
      const toShow = notable.length > 0 ? notable : data.requests.slice(0, 10);
      reqHTML += '<h3>Requêtes Notables</h3><ul>';
      for (const req of toShow) {
        reqHTML += `<li><code>${esc(req.method)} ${esc(req.url)}</code> → <strong>${req.statusCode}</strong></li>`;
      }
      reqHTML += '</ul>';
    } else {
      reqHTML += '<p class="empty">Aucune requête interceptée.</p>';
    }
    reqHTML += '</section>';

    // Section : Secrets exposés
    let secretsHTML = '<section><h2>Secrets Exposés</h2>';
    if (data.secrets && data.secrets.length > 0) {
      secretsHTML += '<ul>';
      for (const secret of data.secrets) {
        secretsHTML += `<li><strong>${esc(secret.type)}</strong> : <code>${esc(secret.value)}</code> <em>(source: ${esc(secret.source)})</em></li>`;
      }
      secretsHTML += '</ul>';
    } else {
      secretsHTML += '<p class="empty">Aucun secret exposé détecté.</p>';
    }
    secretsHTML += '</section>';

    // Section : Notes
    const notesHTML = `
      <section>
        <h2>Notes</h2>
        <div class="notes">${esc(data.notes) || 'Aucune note.'}</div>
      </section>`;

    // Section : Findings détaillés
    let findingsHTML = '<section><h2>Findings</h2>';
    if (data.findings && data.findings.length > 0) {
      for (const finding of data.findings) {
        findingsHTML += `
          <div class="finding">
            <h3>${esc(finding.title) || 'Finding sans titre'} ${severityBadge(finding.severity)}</h3>
            <p>${esc(finding.description) || 'Pas de description.'}</p>`;

        if (finding.poc) {
          findingsHTML += `
            <h4>Preuve de Concept (PoC)</h4>
            <pre><code>${esc(finding.poc)}</code></pre>`;
        }

        if (finding.recommendation) {
          findingsHTML += `<p><strong>Recommandation</strong> : ${esc(finding.recommendation)}</p>`;
        }

        findingsHTML += '</div>';
      }
    } else {
      findingsHTML += '<p class="empty">Aucun finding détaillé.</p>';
    }
    findingsHTML += '</section>';

    // ═══ Assemblage du document HTML complet ═══
    return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ShadowNet — Rapport de Pentest</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #0a0a0a;
      color: #c0c0c0;
      font-family: 'Courier New', 'Fira Code', monospace;
      padding: 40px;
      line-height: 1.6;
    }
    .header {
      text-align: center;
      border-bottom: 2px solid #00ff41;
      padding-bottom: 20px;
      margin-bottom: 40px;
    }
    .header h1 {
      color: #00ff41;
      font-size: 2.2em;
      text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff4180;
      letter-spacing: 4px;
    }
    .header .subtitle {
      color: #00e5ff;
      font-size: 1.1em;
      margin-top: 8px;
      text-shadow: 0 0 8px #00e5ff80;
    }
    h2 {
      color: #00ff41;
      border-bottom: 1px solid #00ff4140;
      padding-bottom: 6px;
      margin: 30px 0 15px 0;
      font-size: 1.4em;
      text-shadow: 0 0 6px #00ff4160;
    }
    h3 {
      color: #00e5ff;
      margin: 20px 0 10px 0;
      font-size: 1.1em;
    }
    h4 {
      color: #00e5ff;
      margin: 12px 0 6px 0;
      font-size: 1em;
    }
    section {
      margin-bottom: 30px;
      padding: 15px;
      border: 1px solid #1a1a2e;
      border-radius: 4px;
      background: #0d0d1a;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 10px 0;
    }
    th, td {
      padding: 8px 12px;
      text-align: left;
      border: 1px solid #1a1a2e;
    }
    th {
      background: #111128;
      color: #00e5ff;
      font-weight: bold;
    }
    tr:nth-child(even) { background: #0f0f20; }
    .info-table td { border: none; padding: 4px 12px; }
    .info-table .label { color: #00e5ff; font-weight: bold; width: 120px; }
    ul { padding-left: 20px; margin: 8px 0; }
    li { margin: 4px 0; }
    code {
      background: #1a1a2e;
      padding: 2px 6px;
      border-radius: 3px;
      color: #00ff41;
      font-size: 0.9em;
    }
    pre {
      background: #111128;
      padding: 12px;
      border-radius: 4px;
      overflow-x: auto;
      margin: 8px 0;
      border: 1px solid #1a1a2e;
    }
    pre code { background: none; padding: 0; }
    .badge {
      display: inline-block;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .finding {
      border: 1px solid #1a1a2e;
      padding: 15px;
      margin: 15px 0;
      border-radius: 4px;
      background: #0f0f1a;
    }
    .notes {
      white-space: pre-wrap;
      padding: 10px;
      background: #111128;
      border-radius: 4px;
      border-left: 3px solid #00e5ff;
    }
    .empty { color: #555; font-style: italic; }
    strong { color: #e0e0e0; }
    em { color: #888; }
    .footer {
      text-align: center;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #1a1a2e;
      color: #444;
      font-size: 0.85em;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>⟁ ShadowNet</h1>
    <div class="subtitle">Rapport de Pentest</div>
  </div>
  ${infoSection}
  ${reconHTML}
  ${vulnHTML}
  ${reqHTML}
  ${secretsHTML}
  ${notesHTML}
  ${findingsHTML}
  <div class="footer">
    Généré par ShadowNet Browser — Export Engine
  </div>
</body>
</html>`;
  }
}

// Exporter
module.exports = { ExportEngine };
