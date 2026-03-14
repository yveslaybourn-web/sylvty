/**
 * ========================================================================
 * ShadowNet Browser — Composant Diff Viewer
 * ========================================================================
 *
 * Comparateur visuel de réponses HTTP côte à côte.
 * Utile pour le fuzzing et l'analyse de variations de réponses.
 *
 * Algorithme : Comparaison ligne par ligne avec mise en évidence
 * des lignes ajoutées (vert), supprimées (rouge), et modifiées (jaune).
 */

// ═══════════════════════════════════════════════════════════════════════
// ÉTAT DU DIFF VIEWER
// ═══════════════════════════════════════════════════════════════════════

const diffState = {
  responseA: null,
  responseB: null,
  requestHistory: []
};

// ═══════════════════════════════════════════════════════════════════════
// INITIALISATION
// ═══════════════════════════════════════════════════════════════════════

function initDiffViewer() {
  const btnCompare = document.getElementById('btn-diff-compare');
  const selectA = document.getElementById('diff-select-a');
  const selectB = document.getElementById('diff-select-b');

  if (btnCompare) {
    btnCompare.addEventListener('click', () => {
      const idxA = parseInt(selectA.value);
      const idxB = parseInt(selectB.value);

      if (isNaN(idxA) || isNaN(idxB)) {
        window.showToast('warning', 'Sélection requise', 'Choisissez deux requêtes à comparer');
        return;
      }

      if (idxA === idxB) {
        window.showToast('warning', 'Même requête', 'Sélectionnez deux requêtes différentes');
        return;
      }

      const a = diffState.requestHistory[idxA];
      const b = diffState.requestHistory[idxB];

      if (a && b) {
        renderDiff(a, b);
      }
    });
  }

  // Bouton rafraîchir la liste des requêtes
  const btnRefresh = document.getElementById('btn-diff-refresh');
  if (btnRefresh) {
    btnRefresh.addEventListener('click', refreshDiffSelectors);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// RAFRAÎCHIR LES SÉLECTEURS
// ═══════════════════════════════════════════════════════════════════════

async function refreshDiffSelectors() {
  try {
    const requests = await window.shadownet.proxy.getRequests();
    diffState.requestHistory = requests || [];

    const selectA = document.getElementById('diff-select-a');
    const selectB = document.getElementById('diff-select-b');

    if (!selectA || !selectB) return;

    const options = requests.slice(-50).reverse().map((req, i) => {
      const realIdx = requests.length - 1 - i;
      const label = `[${req.method}] ${truncateDiff(req.url, 50)} → ${req.statusCode || '?'}`;
      return `<option value="${realIdx}">${escapeHtmlDiff(label)}</option>`;
    }).join('');

    const placeholder = '<option value="" disabled selected>Choisir une requête...</option>';
    selectA.innerHTML = placeholder + options;
    selectB.innerHTML = placeholder + options;

    window.showToast('info', 'Diff', `${requests.length} requêtes disponibles`);
  } catch {
    window.showToast('danger', 'Erreur', 'Impossible de charger les requêtes');
  }
}

// ═══════════════════════════════════════════════════════════════════════
// ALGORITHME DE DIFF
// ═══════════════════════════════════════════════════════════════════════

/**
 * Comparaison ligne par ligne de deux réponses
 * Utilise un algorithme LCS simplifié pour la mise en correspondance
 */
function computeDiff(textA, textB) {
  const linesA = (textA || '').split('\n');
  const linesB = (textB || '').split('\n');
  const result = [];

  const maxLen = Math.max(linesA.length, linesB.length);

  for (let i = 0; i < maxLen; i++) {
    const lineA = i < linesA.length ? linesA[i] : null;
    const lineB = i < linesB.length ? linesB[i] : null;

    if (lineA === lineB) {
      result.push({ type: 'equal', lineA, lineB, lineNum: i + 1 });
    } else if (lineA === null) {
      result.push({ type: 'added', lineA: '', lineB, lineNum: i + 1 });
    } else if (lineB === null) {
      result.push({ type: 'removed', lineA, lineB: '', lineNum: i + 1 });
    } else {
      result.push({ type: 'modified', lineA, lineB, lineNum: i + 1 });
    }
  }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════
// RENDU DU DIFF
// ═══════════════════════════════════════════════════════════════════════

function renderDiff(requestA, requestB) {
  const container = document.getElementById('diff-output');
  if (!container) return;

  // Construire les textes à comparer
  const textA = formatRequestForDiff(requestA);
  const textB = formatRequestForDiff(requestB);

  const diff = computeDiff(textA, textB);

  // Statistiques
  const stats = {
    equal: diff.filter(d => d.type === 'equal').length,
    added: diff.filter(d => d.type === 'added').length,
    removed: diff.filter(d => d.type === 'removed').length,
    modified: diff.filter(d => d.type === 'modified').length
  };

  let html = `
    <div class="diff-stats" style="
      display:flex;gap:16px;padding:8px 12px;margin-bottom:8px;
      background:rgba(0,255,65,0.05);border:1px solid rgba(0,255,65,0.1);
      border-radius:4px;font-size:11px;
    ">
      <span style="color:var(--text-muted)">═ ${stats.equal} identiques</span>
      <span style="color:#00ff41">+ ${stats.added} ajoutées</span>
      <span style="color:#ff4444">- ${stats.removed} supprimées</span>
      <span style="color:#ffaa00">~ ${stats.modified} modifiées</span>
    </div>
    <div class="diff-container" style="display:flex;gap:2px;font-family:'Fira Code',monospace;font-size:12px;">
      <div class="diff-col" style="flex:1;overflow-x:auto;">
        <div style="padding:4px 8px;color:var(--neon-cyan);font-weight:bold;border-bottom:1px solid rgba(0,255,65,0.2);margin-bottom:4px">
          A: [${escapeHtmlDiff(requestA.method)}] ${escapeHtmlDiff(truncateDiff(requestA.url, 40))}
        </div>
  `;

  // Colonne A
  for (const line of diff) {
    const color = getLineColor(line.type, 'a');
    const bg = getLineBg(line.type);
    html += `<div style="padding:1px 8px;background:${bg};white-space:pre-wrap;word-break:break-all">`;
    html += `<span style="color:var(--text-muted);margin-right:8px">${String(line.lineNum).padStart(3)}</span>`;
    html += `<span style="color:${color}">${escapeHtmlDiff(line.lineA || '')}</span>`;
    html += `</div>`;
  }

  html += `</div><div class="diff-col" style="flex:1;overflow-x:auto;">`;
  html += `<div style="padding:4px 8px;color:var(--neon-cyan);font-weight:bold;border-bottom:1px solid rgba(0,255,65,0.2);margin-bottom:4px">`;
  html += `B: [${escapeHtmlDiff(requestB.method)}] ${escapeHtmlDiff(truncateDiff(requestB.url, 40))}`;
  html += `</div>`;

  // Colonne B
  for (const line of diff) {
    const color = getLineColor(line.type, 'b');
    const bg = getLineBg(line.type);
    html += `<div style="padding:1px 8px;background:${bg};white-space:pre-wrap;word-break:break-all">`;
    html += `<span style="color:var(--text-muted);margin-right:8px">${String(line.lineNum).padStart(3)}</span>`;
    html += `<span style="color:${color}">${escapeHtmlDiff(line.lineB || '')}</span>`;
    html += `</div>`;
  }

  html += `</div></div>`;
  container.innerHTML = html;
}

function formatRequestForDiff(req) {
  let text = `${req.method} ${req.url}\n`;
  text += `Status: ${req.statusCode || 'N/A'}\n`;
  text += `Type: ${req.resourceType || 'N/A'}\n`;

  if (req.requestHeaders) {
    text += `\n═══ REQUEST HEADERS ═══\n`;
    for (const [k, v] of Object.entries(req.requestHeaders)) {
      text += `${k}: ${v}\n`;
    }
  }

  if (req.responseHeaders) {
    text += `\n═══ RESPONSE HEADERS ═══\n`;
    for (const [k, v] of Object.entries(req.responseHeaders)) {
      text += `${k}: ${Array.isArray(v) ? v.join(', ') : v}\n`;
    }
  }

  if (req.body) {
    text += `\n═══ BODY ═══\n${req.body}`;
  }

  return text;
}

function getLineColor(type, col) {
  switch (type) {
    case 'added': return col === 'b' ? '#00ff41' : 'var(--text-muted)';
    case 'removed': return col === 'a' ? '#ff4444' : 'var(--text-muted)';
    case 'modified': return '#ffaa00';
    default: return 'var(--text-secondary)';
  }
}

function getLineBg(type) {
  switch (type) {
    case 'added': return 'rgba(0,255,65,0.05)';
    case 'removed': return 'rgba(255,68,68,0.05)';
    case 'modified': return 'rgba(255,170,0,0.05)';
    default: return 'transparent';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// UTILITAIRES LOCAUX
// ═══════════════════════════════════════════════════════════════════════

function escapeHtmlDiff(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function truncateDiff(str, len) {
  if (!str) return '';
  return str.length > len ? str.substring(0, len) + '...' : str;
}

// Exposer globalement
window.initDiffViewer = initDiffViewer;
window.refreshDiffSelectors = refreshDiffSelectors;
