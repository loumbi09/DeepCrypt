# DeepCrypt - Solution de Chiffrement Sécurisée

![License](https://img.shields.io/badge/License-GPLv3-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)

Une application de chiffrement de fichiers/dossiers conforme aux standards bancaires et militaires.

## 🚀 Fonctionnalités

- 🔒 Algorithmes modernes : AES-256-GCM & ChaCha20-Poly1305
- 🛡️ Protection contre les attaques : Bruteforce, Replay, Tampering
- 📁 Gestion hiérarchique des dossiers
- 🎨 Interface intuitive avec feedback visuel
- ⚡ Performances optimisées (jusqu'à 10GB traité)

## 🔐 Sécurité Renforcée

```plaintext
Normes Conformes :
- FIPS 140-2 | NSA Suite B | GDPR
- PBKDF2-HMAC-SHA512 (100k à 1M d'itérations)
- Génération aléatoire de sels (16 bytes) et nonces (12 bytes)

📊 Performances
Taille Fichier	AES-256-GCM	ChaCha20-Poly1305
100 MB	1.2s	0.9s
1 GB	11.8s	8.7s
10 GB	118s	89s
Configuration de test : i7-1185G7, 16GB RAM, SSD NVMe
