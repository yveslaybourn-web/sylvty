/**
 * ========================================================================
 * ShadowNet Browser — Scope Manager
 * ========================================================================
 *
 * Gestionnaire du périmètre de test autorisé.
 *
 * Fonctionnalités :
 * - Gestion dynamique des domaines autorisés (ajout/suppression)
 * - Support des wildcards (*.example.com)
 * - Deux modes de contrôle : strict (blocage) et warn (avertissement)
 * - Persistance via ConfigManager
 *
 * Contexte sécurité : Lors d'un pentest, il est impératif de rester
 * dans le périmètre défini contractuellement. Ce module garantit que
 * toutes les requêtes sont vérifiées contre le scope autorisé avant
 * exécution, évitant ainsi tout dépassement accidentel du périmètre.
 */

class ScopeManager {
  constructor(configManager) {
    this._configManager = configManager;

    // Charger le scope depuis la configuration persistée
    const savedScope = this._configManager.get('scope_domains') || [];
    this._scope = new Set(savedScope);

    // Mode de contrôle : 'strict' bloque, 'warn' avertit seulement
    this._mode = this._configManager.get('scope_mode') || 'strict';
  }

  // ═══════════════════════════════════════════════════════════════════
  // GESTION DES DOMAINES
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Ajouter un domaine au périmètre autorisé.
   * Supporte les wildcards : *.example.com autorise tous les sous-domaines.
   */
  addDomain(domain) {
    this._scope.add(domain);
    this._saveScope();
  }

  /**
   * Retirer un domaine du périmètre autorisé.
   */
  removeDomain(domain) {
    this._scope.delete(domain);
    this._saveScope();
  }

  /**
   * Retourner la liste des domaines dans le périmètre.
   */
  getScope() {
    return Array.from(this._scope);
  }

  /**
   * Vider complètement le périmètre.
   */
  clear() {
    this._scope.clear();
    this._saveScope();
  }

  // ═══════════════════════════════════════════════════════════════════
  // MODE DE CONTRÔLE
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Définir le mode de contrôle du périmètre.
   * - 'strict' : les requêtes hors scope sont bloquées
   * - 'warn'   : les requêtes hors scope génèrent un avertissement
   */
  setMode(mode) {
    if (mode !== 'strict' && mode !== 'warn') {
      throw new Error(`Mode invalide : "${mode}". Utilisez 'strict' ou 'warn'.`);
    }
    this._mode = mode;
    this._configManager.set('scope_mode', mode);
  }

  /**
   * Retourner le mode de contrôle actuel.
   */
  getMode() {
    return this._mode;
  }

  // ═══════════════════════════════════════════════════════════════════
  // VÉRIFICATION DU PÉRIMÈTRE
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Vérifier si une URL ou un domaine est dans le périmètre autorisé.
   * Si le scope est vide, tout est autorisé (pas de restriction).
   * Supporte le wildcard matching (*.example.com → sub.example.com).
   */
  isInScope(urlOrDomain) {
    // Si le scope est vide, tout est autorisé
    if (this._scope.size === 0) {
      return true;
    }

    const hostname = this._extractHostname(urlOrDomain);

    for (const scopeDomain of this._scope) {
      if (this._matchDomain(hostname, scopeDomain)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Vérification complète avec contexte de décision.
   * Retourne un objet { allowed, domain, message } adapté au mode actuel.
   */
  checkScope(urlOrDomain) {
    const hostname = this._extractHostname(urlOrDomain);
    const inScope = this.isInScope(urlOrDomain);

    if (inScope) {
      return {
        allowed: true,
        domain: hostname,
        message: `Domaine "${hostname}" dans le périmètre autorisé.`
      };
    }

    // Hors périmètre — comportement selon le mode
    if (this._mode === 'warn') {
      return {
        allowed: true,
        domain: hostname,
        message: `AVERTISSEMENT : Le domaine "${hostname}" est hors du périmètre autorisé.`
      };
    }

    // Mode strict — blocage
    return {
      allowed: false,
      domain: hostname,
      message: `BLOQUÉ : Le domaine "${hostname}" est hors du périmètre autorisé.`
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  // MÉTHODES INTERNES
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Extraire le hostname d'une URL ou retourner le domaine tel quel.
   */
  _extractHostname(urlOrDomain) {
    try {
      const url = new URL(urlOrDomain);
      return url.hostname;
    } catch (_) {
      // Ce n'est pas une URL valide, traiter comme un domaine brut
      return urlOrDomain;
    }
  }

  /**
   * Vérifier si un hostname correspond à un pattern de domaine du scope.
   * Gère les wildcards : *.example.com matche sub.example.com
   */
  _matchDomain(hostname, scopeDomain) {
    // Correspondance exacte
    if (hostname === scopeDomain) {
      return true;
    }

    // Wildcard matching : *.example.com
    if (scopeDomain.startsWith('*.')) {
      const baseDomain = scopeDomain.slice(2); // Retirer le '*.'
      // Le hostname doit se terminer par .baseDomain
      // (ex: sub.example.com termine par .example.com)
      if (hostname.endsWith('.' + baseDomain)) {
        return true;
      }
      // Le hostname peut aussi être exactement le baseDomain
      if (hostname === baseDomain) {
        return true;
      }
    }

    return false;
  }

  /**
   * Persister le scope dans la configuration.
   */
  _saveScope() {
    this._configManager.set('scope_domains', Array.from(this._scope));
  }
}

module.exports = { ScopeManager };
