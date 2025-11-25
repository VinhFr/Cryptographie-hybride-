# Projet de Chiffrement & Déchiffrement Sécurisé entre Deux Appareils
Basé sur Diffie–Hellman (DH), DSA et AES — utilisant les sockets réseau, le multithreading et les outils GNU/Linux.

## 📝 Description
Ce projet implémente une communication sécurisée entre deux appareils (Client ↔ Serveur) en combinant :

- Diffie–Hellman (DH) pour l’échange de clé
- Digital Signature Algorithm (DSA) pour signer et vérifier les messages
- AES-256 pour le chiffrement symétrique
- Sockets TCP pour la communication réseau
- Threads POSIX pour gérer l’envoi et la réception simultanés
- Outils GNU/Linux et Makefile pour compiler, tester et automatiser

---

## 🔐 Architecture Cryptographique

### Diffie–Hellman (DH)
- Génération de paires de clés DH
- Échange de clés publiques via socket
- Dérivation d’une clé secrète commune → utilisée comme clé AES

### Digital Signature Algorithm (DSA)
- Chaque appareil possède une paire DSA (privée/publique)
- Chaque message est signé avant envoi
- La signature est vérifiée à la réception

### AES-256 (CBC ou GCM)
- Clé = dérivée du protocole DH
- IV généré aléatoirement pour chaque message
- Chiffrement des données avant envoi

Format du message :

---

## 🧩 Architecture Fonctionnelle


---

## ⚙️ Fonctionnalités

### Cryptographie
- DH : génération, échange, dérivation
- DSA : signature, vérification
- AES-256 : chiffrement/déchiffrement
- IV aléatoire sécurisé via OpenSSL

### Réseau
- Connexion TCP (client/serveur)
- Envoi structuré (IV + bloc AES + signature)
- Gestion d’erreurs réseau

### Multithreading
- Un thread pour l’envoi
- Un thread pour la réception
- Communication temps réel

### GNU/Linux
- Compilation via GCC
- Utilisation d’OpenSSL
- Gestion via Makefile

---

## 📁 Structure du Projet


---

## 🔧 Installation

### Dépendances
Installer GCC et OpenSSL :

```bash
sudo apt update
sudo apt install build-essential libssl-dev

