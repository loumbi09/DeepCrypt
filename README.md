# DeepCrypt - Solution de Chiffrement Sécurisée

![License](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Open Source](https://img.shields.io/badge/Open%20Source-✔-brightgreen)

Application de chiffrement de fichiers/dossiers conforme aux standards bancaires et militaires.

## 🚀 Fonctionnalités

- **🔒 Algorithmes Modernes**  
  AES-256-GCM & ChaCha20-Poly1305
- **🛡️ Protections Avancées**  
  Anti-bruteforce • Anti-replay • Vérification d'intégrité
- **📁 Gestion Hiérarchique**  
  Chiffrement récursif de dossiers
- **⚡ Hautes Performances**  
  Jusqu'à 10 Go chiffrés en <2 minutes

## 🔍 Analyse de Sécurité

### Normes Conformes
- FIPS 140-2 (Modules Cryptographiques)
- NSA Suite B (Algorithmes Approuvés)
- RGPD (Protection des Données)

### Mécanismes Clés
- **PBKDF2-HMAC-SHA512**  
  100 000 à 1 000 000 d'itérations
- **Génération Aléatoire**  
  Sels (16 octets) • Nonces (12 octets)
- **Suppression Sécurisée**  
  Écrasement des fichiers originaux

## 📈 Benchmarks

| Taille Fichier | AES-256-GCM | ChaCha20-Poly1305 |
|----------------|-------------|-------------------|
| 100 MB         | 1.2s        | 0.9s              |
| 1 GB           | 11.8s       | 8.7s              |
| 10 GB          | 118s        | 89s               |

*Configuration : Intel i7-1185G7 • 16GB DDR4 • SSD NVMe*

## 🧩 Workflow d'Utilisation

1. `Sélection` Fichier/Dossier
2. `Choix` Algorithme (AES/ChaCha20)
3. `Paramétrage` Nombre d'itérations PBKDF2
4. `Saisie` Mot de passe fort
5. `Option` Suppression sécurisée
6. `Exécution` Chiffrement/Déchiffrement

```bash
# Commande d'installation
git clone https://github.com/loumbi09/DeepCrypt.git
cd deepcrypt && pip install -r requirements.txt
python DeepCrypt.py
