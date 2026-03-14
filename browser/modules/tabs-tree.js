/**
 * ========================================================================
 * ShadowNet Browser — Module de Gestion d'Onglets Arborescents
 * ========================================================================
 *
 * Gère les onglets en structure arborescente, groupés par domaine cible.
 * Cette organisation est cruciale pour les sessions de reconnaissance
 * où un pentester travaille sur plusieurs aspects d'une même cible.
 *
 * Architecture :
 * - Onglets groupés par domaine racine
 * - Drag & drop pour réorganiser
 * - Indicateurs visuels de statut (chargement, erreur, etc.)
 * - Compteur de requêtes par domaine
 */

class TabsTree {
  constructor() {
    this.tabs = new Map();      // ID → TabData
    this.groups = new Map();    // domain → Set<tabId>
    this.activeTabId = null;
    this.counter = 0;
  }

  /**
   * Ajouter un nouvel onglet
   * @returns {Object} Les données de l'onglet créé
   */
  addTab(url = 'about:blank') {
    const id = `tab_${++this.counter}_${Date.now()}`;
    const domain = this._extractRootDomain(url);

    const tab = {
      id,
      url,
      title: 'Nouvel onglet',
      domain,
      favicon: null,
      loading: false,
      error: null,
      requestCount: 0,
      createdAt: Date.now(),
      lastAccessed: Date.now()
    };

    this.tabs.set(id, tab);

    // Ajouter au groupe de domaine
    if (!this.groups.has(domain)) {
      this.groups.set(domain, new Set());
    }
    this.groups.get(domain).add(id);

    return tab;
  }

  /**
   * Retirer un onglet
   */
  removeTab(id) {
    const tab = this.tabs.get(id);
    if (!tab) return false;

    // Retirer du groupe
    const group = this.groups.get(tab.domain);
    if (group) {
      group.delete(id);
      if (group.size === 0) {
        this.groups.delete(tab.domain);
      }
    }

    this.tabs.delete(id);

    // Si c'était l'onglet actif, basculer
    if (this.activeTabId === id) {
      this.activeTabId = this.tabs.size > 0 ? [...this.tabs.keys()].pop() : null;
    }

    return true;
  }

  /**
   * Activer un onglet
   */
  setActive(id) {
    const tab = this.tabs.get(id);
    if (tab) {
      this.activeTabId = id;
      tab.lastAccessed = Date.now();
    }
  }

  /**
   * Mettre à jour les propriétés d'un onglet
   */
  updateTab(id, updates) {
    const tab = this.tabs.get(id);
    if (!tab) return;

    Object.assign(tab, updates);

    // Si l'URL a changé, vérifier si le domaine a changé
    if (updates.url) {
      const newDomain = this._extractRootDomain(updates.url);
      if (newDomain !== tab.domain) {
        // Retirer de l'ancien groupe
        const oldGroup = this.groups.get(tab.domain);
        if (oldGroup) {
          oldGroup.delete(id);
          if (oldGroup.size === 0) this.groups.delete(tab.domain);
        }

        // Ajouter au nouveau groupe
        tab.domain = newDomain;
        if (!this.groups.has(newDomain)) {
          this.groups.set(newDomain, new Set());
        }
        this.groups.get(newDomain).add(id);
      }
    }
  }

  /**
   * Obtenir tous les onglets groupés par domaine
   * @returns {Map<string, Array<TabData>>} Groupes triés
   */
  getGroupedTabs() {
    const result = new Map();

    for (const [domain, tabIds] of this.groups) {
      const tabs = [];
      for (const id of tabIds) {
        const tab = this.tabs.get(id);
        if (tab) tabs.push(tab);
      }
      // Trier par date d'accès (plus récent en premier)
      tabs.sort((a, b) => b.lastAccessed - a.lastAccessed);
      result.set(domain, tabs);
    }

    return result;
  }

  /**
   * Obtenir l'onglet actif
   */
  getActiveTab() {
    return this.activeTabId ? this.tabs.get(this.activeTabId) : null;
  }

  /**
   * Fermer tous les onglets d'un domaine
   */
  closeGroup(domain) {
    const group = this.groups.get(domain);
    if (!group) return;

    for (const id of [...group]) {
      this.removeTab(id);
    }
  }

  /**
   * Fermer tous les onglets sauf l'actif
   */
  closeOthers() {
    for (const id of [...this.tabs.keys()]) {
      if (id !== this.activeTabId) {
        this.removeTab(id);
      }
    }
  }

  /**
   * Extraire le domaine racine d'une URL
   * Ex: "sub.example.com" → "example.com"
   */
  _extractRootDomain(url) {
    try {
      const hostname = new URL(url).hostname;
      const parts = hostname.split('.');
      if (parts.length > 2) {
        return parts.slice(-2).join('.');
      }
      return hostname;
    } catch {
      return 'other';
    }
  }

  /**
   * Statistiques sur les onglets
   */
  getStats() {
    return {
      totalTabs: this.tabs.size,
      totalGroups: this.groups.size,
      activeTabId: this.activeTabId,
      domains: [...this.groups.keys()]
    };
  }
}

// Exporter pour utilisation dans d'autres modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TabsTree };
}

// Exposer globalement pour le renderer
if (typeof window !== 'undefined') {
  window.TabsTree = TabsTree;
}
