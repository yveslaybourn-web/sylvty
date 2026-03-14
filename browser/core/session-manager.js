/**
 * ========================================================================
 * ShadowNet Browser — Gestionnaire de Session Anti-Fingerprinting
 * ========================================================================
 *
 * Module de protection de la vie privée et d'anti-forensique.
 * Gère le spoofing d'empreinte numérique pour empêcher le tracking
 * et l'identification du navigateur par les sites cibles.
 *
 * Fonctionnalités :
 * - Spoofing de User-Agent (rotation automatique ou manuelle)
 * - Blocage des fuites WebRTC (exposition d'IP réelle)
 * - Spoofing Canvas / WebGL / AudioContext fingerprint
 * - Configuration proxy SOCKS5 pour routage Tor
 * - Burn Session : destruction totale des données
 *
 * Contexte sécurité : Pendant un pentest, l'anonymat de l'auditeur est
 * crucial. Ce module empêche le site cible d'identifier la machine
 * source via les techniques de fingerprinting du navigateur.
 */

class SessionManager {
  /**
   * @param {Electron.Session} session - La session Electron à gérer
   */
  constructor(session) {
    this._session = session;
    this._webRTCBlocked = true; // Bloqué par défaut pour la sécurité
    this._currentUA = null;
    this._proxyConfig = null;

    // Empreinte numérique courante
    this._fingerprint = {
      userAgent: null,
      platform: null,
      language: 'en-US',
      screenResolution: { width: 1920, height: 1080 },
      colorDepth: 24,
      timezone: 'UTC',
      doNotTrack: '1',
      webRTCBlocked: true,
      canvasNoise: true,
      webGLVendor: null,
      webGLRenderer: null,
      audioContextNoise: true
    };

    // Profils de User-Agent réalistes pour le spoofing
    // Ces UAs sont choisis pour être courants et ne pas attirer l'attention
    this._userAgentProfiles = [
      {
        name: 'Chrome Windows 10',
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'Win32'
      },
      {
        name: 'Chrome macOS',
        ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'MacIntel'
      },
      {
        name: 'Firefox Windows',
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        platform: 'Win32'
      },
      {
        name: 'Firefox Linux',
        ua: 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        platform: 'Linux x86_64'
      },
      {
        name: 'Safari macOS',
        ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        platform: 'MacIntel'
      },
      {
        name: 'Edge Windows',
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        platform: 'Win32'
      },
      {
        name: 'Chrome Android',
        ua: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        platform: 'Linux armv81'
      },
      {
        name: 'Safari iOS',
        ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
        platform: 'iPhone'
      }
    ];

    // WebGL vendor/renderer spoofing profiles
    this._webGLProfiles = [
      { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3070, OpenGL 4.5)' },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 6800 XT, OpenGL 4.5)' },
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel UHD Graphics 630, OpenGL 4.5)' },
      { vendor: 'Apple', renderer: 'Apple M1 Pro' },
      { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Ti, OpenGL 4.5)' }
    ];

    // Appliquer un fingerprint aléatoire au démarrage
    this.randomizeFingerprint();
  }

  // ═══════════════════════════════════════════════════════════════════
  // GESTION DU USER-AGENT
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Définir un User-Agent spécifique
   * Le UA est appliqué au niveau de la session Electron,
   * affectant toutes les requêtes sortantes
   */
  setUserAgent(userAgent) {
    this._currentUA = userAgent;
    this._session.setUserAgent(userAgent);

    // Mettre à jour le fingerprint
    const profile = this._userAgentProfiles.find(p => p.ua === userAgent);
    this._fingerprint.userAgent = userAgent;
    this._fingerprint.platform = profile ? profile.platform : 'Win32';
  }

  /**
   * Obtenir la liste des profils UA disponibles
   */
  getUserAgentProfiles() {
    return this._userAgentProfiles;
  }

  // ═══════════════════════════════════════════════════════════════════
  // ANTI-FINGERPRINTING
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Randomiser complètement l'empreinte numérique
   *
   * Contexte sécurité : Le fingerprinting est utilisé par les sites web
   * pour identifier de manière unique un visiteur sans cookies.
   * En randomisant l'empreinte, on rend le tracking impossible.
   *
   * Techniques couvertes :
   * - Canvas fingerprinting → Bruit aléatoire ajouté
   * - WebGL fingerprinting → Vendor/renderer spoofé
   * - AudioContext fingerprinting → Bruit ajouté
   * - Résolution d'écran → Valeur courante aléatoire
   * - Timezone → UTC pour anonymisation
   */
  randomizeFingerprint() {
    // Choisir un profil UA aléatoire
    const uaProfile = this._randomItem(this._userAgentProfiles);
    this.setUserAgent(uaProfile.ua);

    // Choisir un profil WebGL aléatoire
    const webGLProfile = this._randomItem(this._webGLProfiles);

    // Résolutions d'écran courantes (pour ne pas être suspect)
    const resolutions = [
      { width: 1920, height: 1080 },
      { width: 2560, height: 1440 },
      { width: 1366, height: 768 },
      { width: 1536, height: 864 },
      { width: 1440, height: 900 },
      { width: 3840, height: 2160 }
    ];

    this._fingerprint = {
      userAgent: uaProfile.ua,
      platform: uaProfile.platform,
      language: this._randomItem(['en-US', 'en-GB', 'fr-FR', 'de-DE', 'es-ES']),
      screenResolution: this._randomItem(resolutions),
      colorDepth: this._randomItem([24, 32]),
      timezone: 'UTC',
      doNotTrack: '1',
      webRTCBlocked: this._webRTCBlocked,
      canvasNoise: true,
      webGLVendor: webGLProfile.vendor,
      webGLRenderer: webGLProfile.renderer,
      audioContextNoise: true,
      profileName: uaProfile.name
    };

    return this._fingerprint;
  }

  /**
   * Obtenir l'empreinte numérique courante
   */
  getCurrentFingerprint() {
    return { ...this._fingerprint };
  }

  // ═══════════════════════════════════════════════════════════════════
  // PROTECTION WEBRTC
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Activer/désactiver le blocage WebRTC
   *
   * Contexte sécurité : WebRTC peut exposer l'adresse IP réelle
   * de l'utilisateur, même derrière un VPN ou un proxy Tor.
   * C'est une fuite critique pour l'anonymat du pentester.
   *
   * Quand activé, les requêtes STUN/TURN sont bloquées au niveau réseau.
   */
  setWebRTCBlocked(blocked) {
    this._webRTCBlocked = blocked;
    this._fingerprint.webRTCBlocked = blocked;

    if (blocked) {
      // Bloquer les requêtes vers les serveurs STUN/TURN
      // Ces serveurs sont utilisés par WebRTC pour découvrir l'IP publique
      this._session.webRequest.onBeforeRequest(
        { urls: ['*://stun.*', '*://turn.*', '*://*.stun.*'] },
        (details, callback) => {
          callback({ cancel: true });
        }
      );
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // CONFIGURATION PROXY
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Configurer un proxy SOCKS5 (typiquement pour Tor)
   *
   * Contexte sécurité : Le routage via Tor masque l'IP source
   * de l'auditeur. Le proxy SOCKS5 est le protocole standard
   * pour se connecter au réseau Tor.
   *
   * @param {string} proxyRules - Ex: "socks5://127.0.0.1:9050" pour Tor
   */
  async setProxy(proxyRules) {
    this._proxyConfig = proxyRules;
    if (proxyRules) {
      await this._session.setProxy({ proxyRules });
    } else {
      await this._session.setProxy({ proxyRules: '' });
    }
    return { proxyRules };
  }

  // ═══════════════════════════════════════════════════════════════════
  // SCRIPTS D'INJECTION ANTI-FINGERPRINTING
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Génère le script JavaScript à injecter dans les webviews
   * pour spoofer les API de fingerprinting côté client
   *
   * Ce script override les fonctions JavaScript utilisées
   * pour le fingerprinting sans casser le fonctionnement des sites
   */
  getAntiFingerPrintScript() {
    const fp = this._fingerprint;
    return `
      // ═══ ShadowNet Anti-Fingerprinting Injection ═══

      // Spoofing de navigator.platform
      Object.defineProperty(navigator, 'platform', {
        get: () => '${fp.platform}'
      });

      // Spoofing de navigator.userAgent (backup du header)
      Object.defineProperty(navigator, 'userAgent', {
        get: () => '${fp.userAgent}'
      });

      // Spoofing de la résolution d'écran
      Object.defineProperty(screen, 'width', { get: () => ${fp.screenResolution.width} });
      Object.defineProperty(screen, 'height', { get: () => ${fp.screenResolution.height} });
      Object.defineProperty(screen, 'availWidth', { get: () => ${fp.screenResolution.width} });
      Object.defineProperty(screen, 'availHeight', { get: () => ${fp.screenResolution.height - 40} });
      Object.defineProperty(screen, 'colorDepth', { get: () => ${fp.colorDepth} });

      // Spoofing de la langue
      Object.defineProperty(navigator, 'language', { get: () => '${fp.language}' });
      Object.defineProperty(navigator, 'languages', { get: () => ['${fp.language}'] });

      // Do Not Track
      Object.defineProperty(navigator, 'doNotTrack', { get: () => '${fp.doNotTrack}' });

      // Canvas fingerprint noise — Ajoute un bruit imperceptible
      // aux rendus Canvas pour casser le hash de fingerprint
      ${fp.canvasNoise ? `
      const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function(type) {
        const ctx = this.getContext('2d');
        if (ctx) {
          const imageData = ctx.getImageData(0, 0, this.width, this.height);
          for (let i = 0; i < imageData.data.length; i += 4) {
            // Ajouter un bruit minimal (±1) sur les canaux RGB
            imageData.data[i] = imageData.data[i] ^ (Math.random() > 0.5 ? 1 : 0);
          }
          ctx.putImageData(imageData, 0, 0);
        }
        return origToDataURL.apply(this, arguments);
      };
      ` : ''}

      // WebGL vendor/renderer spoofing
      ${fp.webGLVendor ? `
      const getParameterProxy = new Proxy(WebGLRenderingContext.prototype.getParameter, {
        apply: function(target, thisArg, args) {
          const param = args[0];
          const ext = thisArg.getExtension('WEBGL_debug_renderer_info');
          if (ext) {
            if (param === ext.UNMASKED_VENDOR_WEBGL) return '${fp.webGLVendor}';
            if (param === ext.UNMASKED_RENDERER_WEBGL) return '${fp.webGLRenderer}';
          }
          return Reflect.apply(target, thisArg, args);
        }
      });
      WebGLRenderingContext.prototype.getParameter = getParameterProxy;
      ` : ''}

      // AudioContext fingerprint noise
      ${fp.audioContextNoise ? `
      const origCreateOscillator = AudioContext.prototype.createOscillator;
      AudioContext.prototype.createOscillator = function() {
        const osc = origCreateOscillator.apply(this, arguments);
        const origConnect = osc.connect.bind(osc);
        osc.connect = function(dest) {
          // Ajouter un léger bruit pour altérer le fingerprint audio
          const gainNode = osc.context.createGain();
          gainNode.gain.value = 1 + (Math.random() * 0.0001);
          origConnect(gainNode);
          gainNode.connect(dest);
          return dest;
        };
        return osc;
      };
      ` : ''}

      // Blocage WebRTC
      ${fp.webRTCBlocked ? `
      // Désactiver RTCPeerConnection pour empêcher les fuites d'IP
      window.RTCPeerConnection = undefined;
      window.webkitRTCPeerConnection = undefined;
      window.mozRTCPeerConnection = undefined;
      navigator.mediaDevices = undefined;
      ` : ''}

      console.log('[ShadowNet] Anti-fingerprinting activé — Profil: ${fp.profileName || 'Custom'}');
    `;
  }

  // ═══════════════════════════════════════════════════════════════════
  // UTILITAIRES
  // ═══════════════════════════════════════════════════════════════════

  _randomItem(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }
}

module.exports = { SessionManager };
