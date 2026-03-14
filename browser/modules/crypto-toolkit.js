/**
 * ========================================================================
 * ShadowNet Browser — Crypto Toolkit
 * ========================================================================
 *
 * Suite d'outils d'encodage/décodage et d'analyse cryptographique
 * pour le test de pénétration web.
 *
 * Fonctionnalités :
 * - Encodage/décodage : Base64, URL, Hex, HTML Entities, Unicode
 * - Inspection et tampering de JWT (JSON Web Tokens)
 * - Calcul de hash (MD5, SHA-1, SHA-256, SHA-512)
 * - Analyse de tokens et de secrets
 *
 * Contexte sécurité : Les outils crypto sont essentiels pour :
 * - Manipuler les paramètres encodés dans les requêtes
 * - Inspecter et modifier les tokens d'authentification
 * - Décoder les payloads obfusqués
 * - Identifier les algorithmes de hash utilisés
 */

class CryptoToolkit {
  constructor() {
    // Patterns pour identifier les types de hash
    this.hashPatterns = [
      { name: 'MD5', regex: /^[a-f0-9]{32}$/i, length: 32 },
      { name: 'SHA-1', regex: /^[a-f0-9]{40}$/i, length: 40 },
      { name: 'SHA-256', regex: /^[a-f0-9]{64}$/i, length: 64 },
      { name: 'SHA-512', regex: /^[a-f0-9]{128}$/i, length: 128 },
      { name: 'bcrypt', regex: /^\$2[ayb]\$\d{2}\$/, length: null },
      { name: 'NTLM', regex: /^[a-f0-9]{32}$/i, length: 32 },
    ];
  }

  // ═══════════════════════════════════════════════════════════════════
  // ENCODAGE / DÉCODAGE
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Encoder du texte dans le format spécifié
   */
  encode(text, format) {
    switch (format) {
      case 'base64':
        return btoa(unescape(encodeURIComponent(text)));
      case 'url':
        return encodeURIComponent(text);
      case 'url-full':
        // Encodage URL complet (tous les caractères)
        return text.split('').map(c =>
          '%' + c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()
        ).join('');
      case 'hex':
        return text.split('').map(c =>
          c.charCodeAt(0).toString(16).padStart(2, '0')
        ).join('');
      case 'html':
        return text.replace(/[&<>"'\/]/g, c => ({
          '&': '&amp;', '<': '&lt;', '>': '&gt;',
          '"': '&quot;', "'": '&#x27;', '/': '&#x2F;'
        }[c]));
      case 'html-dec':
        // HTML entities décimales
        return text.split('').map(c => `&#${c.charCodeAt(0)};`).join('');
      case 'html-hex':
        // HTML entities hexadécimales
        return text.split('').map(c =>
          `&#x${c.charCodeAt(0).toString(16)};`
        ).join('');
      case 'unicode':
        return text.split('').map(c =>
          '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')
        ).join('');
      case 'binary':
        return text.split('').map(c =>
          c.charCodeAt(0).toString(2).padStart(8, '0')
        ).join(' ');
      default:
        throw new Error(`Format d'encodage inconnu: ${format}`);
    }
  }

  /**
   * Décoder du texte depuis le format spécifié
   */
  decode(text, format) {
    switch (format) {
      case 'base64':
        return decodeURIComponent(escape(atob(text)));
      case 'url':
        return decodeURIComponent(text);
      case 'hex':
        return text.match(/.{1,2}/g)?.map(byte =>
          String.fromCharCode(parseInt(byte, 16))
        ).join('') || '';
      case 'html':
        const textarea = document.createElement('textarea');
        textarea.innerHTML = text;
        return textarea.value;
      case 'unicode':
        return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
      case 'binary':
        return text.split(' ').map(b =>
          String.fromCharCode(parseInt(b, 2))
        ).join('');
      default:
        throw new Error(`Format de décodage inconnu: ${format}`);
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // ANALYSE JWT (JSON Web Token)
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Décoder et analyser un JWT
   *
   * Contexte sécurité : Les JWT sont omniprésents dans l'auth web.
   * Un JWT mal configuré peut permettre :
   * - Escalade de privilèges (modifier le rôle dans le payload)
   * - Contournement d'auth (alg: "none" attack)
   * - Exposition de données sensibles (données PII dans le payload)
   */
  inspectJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { error: 'Format JWT invalide — un JWT doit avoir 3 parties séparées par des points' };
    }

    try {
      const header = JSON.parse(this._base64UrlDecode(parts[0]));
      const payload = JSON.parse(this._base64UrlDecode(parts[1]));

      // Analyse de sécurité
      const vulnerabilities = [];
      const info = [];

      // Vérifier l'algorithme
      if (header.alg === 'none' || header.alg === 'None') {
        vulnerabilities.push({
          severity: 'CRITICAL',
          issue: 'Algorithme "none" — Signature non vérifiée!',
          impact: 'N\'importe qui peut forger un token valide'
        });
      }

      if (header.alg === 'HS256' || header.alg === 'HS384' || header.alg === 'HS512') {
        info.push({
          note: `Algorithme symétrique (${header.alg})`,
          detail: 'La même clé est utilisée pour signer et vérifier. Tester: clé faible, confusion alg RS→HS'
        });
      }

      // Vérifier l'expiration
      if (payload.exp) {
        const expDate = new Date(payload.exp * 1000);
        if (expDate < new Date()) {
          info.push({
            note: 'Token expiré',
            detail: `Expiré le ${expDate.toISOString()}`
          });
        } else {
          const remaining = Math.round((expDate - new Date()) / 1000 / 60);
          info.push({
            note: `Token valide encore ${remaining} minutes`,
            detail: `Expire le ${expDate.toISOString()}`
          });
        }
      } else {
        vulnerabilities.push({
          severity: 'HIGH',
          issue: 'Pas de champ "exp" — Le token n\'expire jamais!',
          impact: 'Un token volé peut être utilisé indéfiniment'
        });
      }

      // Détecter les rôles et privilèges
      const privilegeFields = ['role', 'roles', 'admin', 'is_admin', 'isAdmin',
                                'permissions', 'scope', 'scopes', 'groups'];
      for (const field of privilegeFields) {
        if (payload[field] !== undefined) {
          info.push({
            note: `Champ de privilège détecté: ${field}`,
            detail: `Valeur: ${JSON.stringify(payload[field])} — Tester la modification`
          });
        }
      }

      // Détecter les données sensibles
      const sensitiveFields = ['email', 'phone', 'ssn', 'address', 'password',
                                'credit_card', 'secret'];
      for (const field of sensitiveFields) {
        if (payload[field] !== undefined) {
          vulnerabilities.push({
            severity: 'MEDIUM',
            issue: `Donnée sensible dans le JWT: ${field}`,
            impact: 'Les JWT sont décodables par n\'importe qui — pas de confidentialité'
          });
        }
      }

      return {
        header,
        payload,
        signature: parts[2],
        vulnerabilities,
        info,
        raw: { header: parts[0], payload: parts[1], signature: parts[2] }
      };
    } catch (err) {
      return { error: `Erreur de décodage JWT: ${err.message}` };
    }
  }

  /**
   * Modifier le payload d'un JWT (sans re-signer)
   * Utile pour tester si le serveur vérifie la signature
   *
   * @param {string} token - JWT original
   * @param {Object} payloadOverrides - Champs à modifier
   * @returns {string} JWT modifié (signature invalide)
   */
  tamperJWT(token, payloadOverrides) {
    const parts = token.split('.');
    if (parts.length !== 3) return { error: 'JWT invalide' };

    try {
      const payload = JSON.parse(this._base64UrlDecode(parts[1]));
      Object.assign(payload, payloadOverrides);

      const newPayload = this._base64UrlEncode(JSON.stringify(payload));
      return {
        token: `${parts[0]}.${newPayload}.${parts[2]}`,
        note: 'Signature originale conservée — Le token est invalide si le serveur vérifie la signature'
      };
    } catch (err) {
      return { error: err.message };
    }
  }

  /**
   * Créer un JWT avec l'attaque "alg: none"
   * Teste si le serveur accepte les tokens non signés
   */
  createNoneAlgJWT(payload) {
    const header = { alg: 'none', typ: 'JWT' };
    const headerB64 = this._base64UrlEncode(JSON.stringify(header));
    const payloadB64 = this._base64UrlEncode(JSON.stringify(payload));
    return `${headerB64}.${payloadB64}.`;
  }

  // ═══════════════════════════════════════════════════════════════════
  // IDENTIFICATION DE HASH
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Identifier le type probable d'un hash
   */
  identifyHash(hash) {
    const trimmed = hash.trim();
    const matches = [];

    for (const pattern of this.hashPatterns) {
      if (pattern.regex.test(trimmed)) {
        matches.push(pattern.name);
      }
    }

    return matches.length > 0 ? matches : ['Type de hash inconnu'];
  }

  // ═══════════════════════════════════════════════════════════════════
  // UTILITAIRES INTERNES
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Décodage Base64URL (RFC 4648 §5)
   * Variante de Base64 utilisée dans les JWT
   */
  _base64UrlDecode(str) {
    // Remplacer les caractères URL-safe par les caractères Base64 standard
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    // Ajouter le padding si nécessaire
    while (base64.length % 4) {
      base64 += '=';
    }
    return atob(base64);
  }

  /**
   * Encodage Base64URL
   */
  _base64UrlEncode(str) {
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }
}

// Exporter
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CryptoToolkit };
}
if (typeof window !== 'undefined') {
  window.CryptoToolkit = CryptoToolkit;
}
