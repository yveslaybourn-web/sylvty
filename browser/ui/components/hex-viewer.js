/**
 * ========================================================================
 * ShadowNet Browser — Hex Viewer
 * ========================================================================
 *
 * Visualiseur hexadécimal pour analyser les réponses HTTP brutes,
 * les payloads binaires, et les données encodées.
 *
 * Contexte sécurité : L'analyse hex est essentielle pour :
 * - Identifier les null bytes dans les uploads de fichiers
 * - Détecter les caractères cachés dans les réponses
 * - Analyser les payloads binaires (shellcode, etc.)
 * - Vérifier l'encodage réel des données
 */

(function() {

  const hexContent = document.getElementById('hex-content');

  /**
   * Convertir une chaîne en vue hexadécimale
   * Format classique : offset | hex bytes | ASCII
   *
   * @param {string|ArrayBuffer} data - Données à afficher
   * @param {number} bytesPerRow - Octets par ligne (défaut: 16)
   */
  function renderHexView(data, bytesPerRow = 16) {
    let bytes;

    if (typeof data === 'string') {
      // Convertir la chaîne en tableau d'octets
      bytes = new Uint8Array(data.split('').map(c => c.charCodeAt(0)));
    } else if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (data instanceof Uint8Array) {
      bytes = data;
    } else {
      hexContent.innerHTML = '<span style="color:var(--text-muted)">Aucune donnée à afficher.\nCollez du texte ou sélectionnez une réponse HTTP.</span>';
      return;
    }

    if (bytes.length === 0) {
      hexContent.innerHTML = '<span style="color:var(--text-muted)">Données vides</span>';
      return;
    }

    let html = '';
    const totalRows = Math.ceil(bytes.length / bytesPerRow);

    for (let row = 0; row < totalRows; row++) {
      const offset = row * bytesPerRow;
      const rowBytes = bytes.slice(offset, offset + bytesPerRow);

      // Offset (adresse)
      const offsetStr = offset.toString(16).padStart(8, '0').toUpperCase();

      // Octets en hexadécimal
      let hexStr = '';
      let asciiStr = '';

      for (let i = 0; i < bytesPerRow; i++) {
        if (i < rowBytes.length) {
          const byte = rowBytes[i];
          hexStr += byte.toString(16).padStart(2, '0').toUpperCase() + ' ';

          // Caractère ASCII imprimable (32-126), sinon point
          if (byte >= 32 && byte <= 126) {
            asciiStr += String.fromCharCode(byte);
          } else {
            asciiStr += '.';
          }
        } else {
          hexStr += '   '; // Padding pour la dernière ligne
          asciiStr += ' ';
        }

        // Séparateur au milieu (après 8 octets)
        if (i === 7) hexStr += ' ';
      }

      html += `<div class="hex-row">` +
        `<span class="hex-offset">${offsetStr}</span>` +
        `<span class="hex-bytes">${escapeHtml(hexStr)}</span>` +
        `<span class="hex-ascii">${escapeHtml(asciiStr)}</span>` +
        `</div>`;
    }

    // Ajouter les statistiques en bas
    html += `\n<div style="margin-top:12px;color:var(--text-muted);font-size:10px">` +
      `Taille: ${bytes.length} octets (${formatSize(bytes.length)}) | ` +
      `Lignes: ${totalRows} | ` +
      `Octets/ligne: ${bytesPerRow}</div>`;

    hexContent.innerHTML = html;
  }

  /**
   * Formater la taille en unité lisible
   */
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ═══════════════════════════════════════════════════════════════════
  // INTERFACE — Input pour coller des données
  // ═══════════════════════════════════════════════════════════════════

  // Ajouter un input au panneau hex
  const inputArea = document.createElement('div');
  inputArea.innerHTML = `
    <textarea id="hex-input" class="cyber-textarea" placeholder="Collez des données ici pour les visualiser en hexadécimal..." rows="3" style="margin-bottom:8px"></textarea>
    <div style="display:flex;gap:4px;margin-bottom:8px">
      <button class="action-btn" id="btn-hex-render">Afficher en Hex</button>
      <button class="action-btn" id="btn-hex-response">Hex de la réponse courante</button>
    </div>
  `;

  if (hexContent && hexContent.parentNode) {
    hexContent.parentNode.insertBefore(inputArea, hexContent);
  }

  // Bouton pour rendre en hex
  document.getElementById('btn-hex-render')?.addEventListener('click', () => {
    const input = document.getElementById('hex-input').value;
    if (input) {
      renderHexView(input);
    }
  });

  // Bouton pour récupérer la réponse HTTP courante
  document.getElementById('btn-hex-response')?.addEventListener('click', async () => {
    const webview = document.querySelector(`#webview-${window.state?.activeTabId}`);
    if (!webview) {
      window.showToast?.('warning', 'Aucune page', 'Naviguez vers un site d\'abord');
      return;
    }

    try {
      const html = await webview.executeJavaScript('document.documentElement.outerHTML');
      renderHexView(html.substring(0, 4096)); // Limiter à 4KB
    } catch (err) {
      window.showToast?.('danger', 'Erreur', err.message);
    }
  });

  // Rendu initial
  renderHexView('');

  // Exposer globalement
  window.renderHexView = renderHexView;

})();
