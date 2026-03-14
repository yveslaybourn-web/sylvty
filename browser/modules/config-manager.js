/**
 * ========================================================================
 * ShadowNet Browser — Config Manager
 * ========================================================================
 *
 * Module de gestion de la configuration persistante.
 *
 * Fonctionnalités :
 * - Persistance des préférences utilisateur en JSON
 * - Création automatique du répertoire et fichier de config
 * - Fusion intelligente avec les valeurs par défaut
 * - Sauvegarde automatique à chaque modification
 *
 * Contexte sécurité : La configuration est stockée localement dans
 * ~/.shadownet/config.json. Ce fichier contient les préférences
 * opérationnelles du navigateur (proxy, évasion, scope, etc.).
 * Aucune donnée sensible (credentials, tokens) ne doit y être stockée.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// Chemin de stockage de la configuration
const CONFIG_DIR = path.join(os.homedir(), '.shadownet');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

// ═══════════════════════════════════════════════════════════════════
// VALEURS PAR DÉFAUT
// ═══════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG = {
  proxyEnabled: false,
  spoofEnabled: true,
  torEnabled: false,
  webrtcBlocked: true,
  zeroDiskEnabled: false,
  secretsHunterEnabled: false,
  scope: [],              // Domaines autorisés pour le pentest
  bookmarks: [],          // { id, name, url, addedAt }
  history: [],            // { url, title, visitedAt } — max 500 entrées
  notes: '',              // Notes de pentest en texte libre
  findings: [],           // { id, title, severity, description, poc, recommendation }
  customScripts: [],      // Bibliothèque persistante du script injector
  proxyRotationInterval: 30000,
  rateLimitDelay: 100
};

// Limite maximale d'entrées dans l'historique
const MAX_HISTORY_ENTRIES = 500;

class ConfigManager {

  // ═══════════════════════════════════════════════════════════════════
  // INITIALISATION
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Initialise le gestionnaire de configuration.
   * Charge la config existante ou crée les valeurs par défaut.
   */
  constructor() {
    this._config = { ...DEFAULT_CONFIG };
    this._configPath = CONFIG_FILE;
    this._configDir = CONFIG_DIR;
    this.load();
  }

  // ═══════════════════════════════════════════════════════════════════
  // CHARGEMENT & PERSISTANCE
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Charger la configuration depuis le disque (synchrone).
   * Exécuté au démarrage — fusionne avec les valeurs par défaut
   * pour garantir la présence de toutes les clés.
   */
  load() {
    try {
      // Créer le répertoire s'il n'existe pas
      if (!fs.existsSync(this._configDir)) {
        fs.mkdirSync(this._configDir, { recursive: true });
      }

      // Lire le fichier de configuration existant
      if (fs.existsSync(this._configPath)) {
        const raw = fs.readFileSync(this._configPath, 'utf-8');
        const saved = JSON.parse(raw);

        // Fusion : les valeurs sauvegardées écrasent les défauts
        this._config = { ...DEFAULT_CONFIG, ...saved };

        // Tronquer l'historique si nécessaire
        if (this._config.history.length > MAX_HISTORY_ENTRIES) {
          this._config.history = this._config.history.slice(-MAX_HISTORY_ENTRIES);
        }
      } else {
        // Premier lancement — créer le fichier avec les défauts
        this._config = { ...DEFAULT_CONFIG };
        fs.writeFileSync(this._configPath, JSON.stringify(this._config, null, 2), 'utf-8');
      }
    } catch (err) {
      // En cas d'erreur (fichier corrompu, permissions, etc.)
      // on repart sur les valeurs par défaut sans crash
      console.error('[ConfigManager] Erreur au chargement de la config :', err.message);
      this._config = { ...DEFAULT_CONFIG };
    }
  }

  /**
   * Sauvegarder la configuration sur disque (asynchrone).
   * Utilisé après chaque modification via set().
   */
  async save() {
    try {
      // S'assurer que le répertoire existe toujours
      await fs.promises.mkdir(this._configDir, { recursive: true });

      const data = JSON.stringify(this._config, null, 2);
      await fs.promises.writeFile(this._configPath, data, 'utf-8');
    } catch (err) {
      console.error('[ConfigManager] Erreur lors de la sauvegarde :', err.message);
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // ACCESSEURS
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Récupérer une valeur de configuration.
   * Retourne defaultValue si la clé n'existe pas.
   */
  get(key, defaultValue) {
    if (key in this._config) {
      return this._config[key];
    }
    return defaultValue;
  }

  /**
   * Définir une valeur de configuration et sauvegarder automatiquement.
   * Déclenche une écriture asynchrone sur disque.
   */
  set(key, value) {
    this._config[key] = value;

    // Tronquer l'historique si on dépasse la limite
    if (key === 'history' && Array.isArray(value) && value.length > MAX_HISTORY_ENTRIES) {
      this._config.history = value.slice(-MAX_HISTORY_ENTRIES);
    }

    // Sauvegarde automatique (fire-and-forget)
    this.save();
  }

  /**
   * Retourner l'intégralité de la configuration.
   * Renvoie une copie pour éviter les mutations directes.
   */
  getAll() {
    return { ...this._config };
  }

  // ═══════════════════════════════════════════════════════════════════
  // RÉINITIALISATION
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Réinitialiser la configuration aux valeurs par défaut.
   * Écrase tout et sauvegarde immédiatement.
   */
  reset() {
    this._config = { ...DEFAULT_CONFIG };
    this.save();
  }
}

module.exports = { ConfigManager };
