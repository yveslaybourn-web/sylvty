#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# ShadowNet Browser — Lanceur automatique
# ═══════════════════════════════════════════════════════════════════════
# Double-cliquez sur ce fichier pour lancer ShadowNet.
# Il installe automatiquement les dépendances si nécessaire.

cd "$(dirname "$0")"

# Couleurs
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ◈ ═══════════════════════════════════════════════ ◈"
echo "  ║         SHADOWNET — Cybersecurity Browser        ║"
echo "  ◈ ═══════════════════════════════════════════════ ◈"
echo -e "${NC}"

# Vérifier Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}[!] Node.js non trouvé.${NC}"
    echo "    Installez Node.js v18+ : https://nodejs.org"
    echo ""
    read -p "Appuyez sur Entrée pour quitter..."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
echo -e "${GREEN}[+]${NC} Node.js détecté : $(node -v)"

if [ "$NODE_VERSION" -lt 18 ]; then
    echo -e "${RED}[!] Node.js v18+ requis (vous avez v${NODE_VERSION})${NC}"
    read -p "Appuyez sur Entrée pour quitter..."
    exit 1
fi

# Vérifier npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}[!] npm non trouvé.${NC}"
    read -p "Appuyez sur Entrée pour quitter..."
    exit 1
fi

# Installer les dépendances si nécessaire
if [ ! -d "node_modules" ]; then
    echo -e "${CYAN}[*] Installation des dépendances...${NC}"
    echo ""
    npm install
    if [ $? -ne 0 ]; then
        echo ""
        echo -e "${RED}[!] Erreur lors de l'installation.${NC}"
        echo "    Essayez : sudo apt install build-essential python3"
        echo "    Puis relancez ce script."
        read -p "Appuyez sur Entrée pour quitter..."
        exit 1
    fi
    echo ""
    echo -e "${GREEN}[+] Dépendances installées avec succès.${NC}"
else
    echo -e "${GREEN}[+]${NC} Dépendances déjà installées."
fi

# Lancer ShadowNet
echo ""
echo -e "${GREEN}[+] Lancement de ShadowNet...${NC}"
echo ""
npx electron . 2>/dev/null || npm start
