# ◈ ShadowNet — Navigateur de Cybersécurité Avancé

<div align="center">

```
   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███╗   ██╗███████╗████████╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║████╗  ██║██╔════╝╚══██╔══╝
   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██╔██╗ ██║█████╗     ██║
   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║╚██╗██║██╔══╝     ██║
   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚████║███████╗   ██║
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
```

**Navigateur desktop pour White Hat / Grey Hat hackers, pentesters et chercheurs en sécurité**

*Burp Suite Lite + Wappalyzer + Navigateur Sécurisé — Tout-en-un*

</div>

---

## Fonctionnalités

### Proxy d'Interception (Burp Suite Lite)
- Interception HTTP/HTTPS en temps réel via l'API `webRequest` d'Electron
- Pause, modification (tampering), transfert ou blocage de requêtes à la volée
- Module de rejeu (Replay Attack) — Renvoyer des requêtes modifiées
- Historique complet des requêtes avec flags de sécurité automatiques

### Reconnaissance OSINT
- Détection de technologies Wappalyzer-style (CMS, frameworks, serveur, WAF)
- Résolution DNS / WHOIS intégrée dans la barre d'URL
- Énumération passive de sous-domaines via Certificate Transparency (crt.sh)
- Scanner de répertoires cachés (DirBuster lite) avec wordlist pré-chargée
- Liens rapides Shodan / Censys / VirusTotal via Command Palette

### Analyse de Vulnérabilités
- Scanner automatique de headers de sécurité (HSTS, CSP, X-Frame-Options, etc.)
- Détection de fichiers sensibles exposés (.git, .env, backups, phpinfo, etc.)
- Mapping des DOM sinks pour identifier les points d'injection XSS
- Alertes temps réel : WAF détecté, clés API dans les réponses, headers manquants

### Crypto & Payload Toolkit
- Encodeur/Décodeur : Base64, URL, Hex, HTML Entities, Unicode, Binaire
- Inspecteur JWT — Décodage, analyse de sécurité, tampering, attaque "alg:none"
- Identification automatique de type de hash
- Bibliothèque de payloads prêts à l'emploi : XSS, SQLi, SSRF, LFI, SSTI, XXE, Command Injection, Open Redirect

### Vie Privée & Anti-Forensique
- Spoofing granulaire : User-Agent, Canvas, WebGL, AudioContext, résolution d'écran
- Blocage WebRTC strict (prévention des fuites d'IP)
- Intégration proxy SOCKS5 pour routage Tor
- Bouton "Burn Session" — Destruction complète de toutes les données en un clic

### Assistant IA (Analyse Locale)
- Déobfuscation et beautification de JavaScript
- Détection de patterns de vulnérabilité dans le code source
- Analyse de réponses HTTP et suggestion de vecteurs d'attaque
- Génération de PoC (Proof of Concept)

### Interface Cyberpunk
- Esthétique "Command Center" — True Black + Neon (Cyan, Green, Magenta)
- Typographie monospace (Fira Code)
- Panneaux glassmorphiques avec fond matrix-style
- Effets de glitch au survol
- Command Palette (Ctrl+Shift+P) pour tout contrôler au clavier
- Onglets verticaux arborescents groupés par domaine cible
- Split-screen : page web + trafic réseau simultanément

---

## Installation & Lancement

### Prérequis
- [Node.js](https://nodejs.org/) >= 18.x
- npm >= 9.x

### Installation

```bash
cd browser
npm install
```

### Lancement

```bash
npm start
```

### Mode développement (avec DevTools)

```bash
npm run dev
```

---

## Raccourcis Clavier

| Raccourci | Action |
|---|---|
| `Ctrl+Shift+P` | Command Palette (toutes les commandes) |
| `Ctrl+Shift+I` | Toggle Proxy d'Interception |
| `Ctrl+Shift+B` | Burn Session (effacer toutes les données) |
| `F12` | Toggle Split Screen (page + réseau) |
| `Ctrl+T` | Nouvel onglet |
| `Ctrl+W` | Fermer l'onglet actif |
| `Ctrl+L` | Focus sur la barre d'URL |
| `Escape` | Fermer les overlays |

---

## Architecture du Projet

```
browser/
├── main.js                          # Point d'entrée Electron, IPC sécurisés
├── preload.js                       # Pont sécurisé main ↔ renderer
├── package.json                     # Dépendances et scripts
│
├── core/                            # Modules cœur (processus principal)
│   ├── interception-proxy.js        # Proxy HTTP/HTTPS (webRequest API)
│   └── session-manager.js           # Anti-fingerprinting, spoofing
│
├── ui/                              # Interface utilisateur (renderer)
│   ├── index.html                   # Layout HTML principal
│   ├── style.css                    # Styles cyberpunk (CSS custom properties)
│   ├── renderer.js                  # Logique UI principale
│   └── components/                  # Composants réutilisables
│       ├── command-palette.js       # Palette de commandes (Ctrl+Shift+P)
│       └── hex-viewer.js            # Visualiseur hexadécimal
│
└── modules/                         # Modules fonctionnels
    ├── tabs-tree.js                 # Gestion d'onglets arborescents
    ├── osint-recon.js               # Reconnaissance & OSINT
    ├── crypto-toolkit.js            # Outils d'encodage/crypto/JWT
    ├── payload-injector.js          # Bibliothèque de payloads
    └── ai-exploit-analyzer.js       # Analyse IA de vulnérabilités
```

### Sécurité de l'Architecture

- **Context Isolation** (`contextIsolation: true`) — Le renderer ne peut pas accéder à Node.js
- **Preload sécurisé** — Seules les API définies dans `preload.js` sont accessibles
- **Canaux IPC whitelist** — Validation stricte des canaux de communication
- **CSP** appliquée sur l'interface du navigateur
- **WebView isolées** — Chaque onglet est sandboxé

---

## Configuration Tor (Optionnel)

Pour utiliser le routage Tor, installez le service Tor :

```bash
# Ubuntu/Debian
sudo apt install tor
sudo systemctl start tor

# macOS
brew install tor
brew services start tor
```

Le proxy SOCKS5 par défaut est `127.0.0.1:9050`. Activez-le via le bouton Tor dans la barre de navigation ou la Command Palette.

---

## Avertissement Légal

Ce navigateur est conçu **exclusivement** pour :
- Tests de pénétration autorisés (avec contrat/accord écrit)
- Programmes de Bug Bounty
- Tests de sécurité sur vos propres applications
- Recherche en cybersécurité et éducation

**L'utilisation non autorisée de ces outils contre des systèmes tiers est illégale et contraire à l'éthique.**

Les auteurs déclinent toute responsabilité en cas d'utilisation malveillante.

---

## Stack Technique

| Composant | Technologie |
|---|---|
| Runtime | Electron 28+ |
| Backend | Node.js |
| Moteur de rendu | Chromium |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Interception réseau | Electron webRequest API |
| DNS | Module `dns` Node.js natif |
| Sous-domaines | API crt.sh (Certificate Transparency) |
| Proxy SOCKS5 | Configuration Electron Session |

---

## Licence

MIT License — Utilisation libre pour la recherche en sécurité et l'éducation.
