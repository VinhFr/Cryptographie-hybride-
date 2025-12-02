# E2EE : Chiffrement & Déchiffrement Sécurisé entre Deux Appareils

Basé sur Diffie–Hellman (DH), DSA et AES — utilisant les sockets réseau, le multithreading et les outils GNU/Linux.

---

## 📝 Description

Ce projet implémente une communication sécurisée entre deux appareils (Client ↔ Serveur) en combinant :

* Diffie–Hellman (DH) pour l’échange de clé
* Digital Signature Algorithm (DSA) pour la signature et la vérification
* AES-256 pour le chiffrement symétrique
* Sockets TCP pour la communication réseau
* Threads POSIX pour l’émission et la réception simultanées
* Outils GNU/Linux et Makefile pour la compilation et la génération automatique de clés

---

## 🔐 Architecture Cryptographique

### Diffie–Hellman (DH)

* Génération des clés DH
* Échange des clés publiques via socket
* Calcul d’une clé secrète commune utilisée pour AES

### Digital Signature Algorithm (DSA)

* Génération des paires DSA (privée/publique)
* Signature numérique des messages
* Vérification de la signature à la réception

### AES-256 (CBC ou GCM)

* Chiffrement symétrique basé sur la clé issue de DH
* IV généré aléatoirement pour chaque message
* Format d’un paquet transmis :

```
| IV | Données chiffrées AES | Signature DSA |
```

### Clé de session (AES-256)

* Créée automatiquement à chaque nouvelle session
* N’existe que pour la durée de la session (tempt fixe)
* Éphémère : elle disparaît à la fin de la session
* Garantit le Perfect Forward Secrecy (PFS) grâce au renouvellement systématique

---

## 🧩 Architecture Fonctionnelle

```
Appareil A                                  Appareil B
--------------------------------------------------------------
1. Échange des clés DH --------------------> Clé secrète partagée
2. Échange des clés DSA -------------------> Authentification
3. Envoi message chiffré + signé ---------->
4. Déchiffrement + vérification <-----------
```

---

## ⚙️ Fonctionnalités

### Cryptographie

* Diffie–Hellman : génération, échange et dérivation
* DSA : signature / vérification
* AES-256 : chiffrement / déchiffrement
* IV sécurisé généré via OpenSSL

### Réseau

* Communication TCP client/serveur
* Sérialisation complète des données (IV + AES + DSA)
* Résistance aux erreurs réseau

### Multithreading

* Thread d’envoi
* Thread de réception
* Communication simultanée full-duplex

### GNU/Linux

* Compilation via **GCC**
* Utilisation de la bibliothèque **OpenSSL**
* Automatisation via **Makefile**
* Génération automatique de clés DSA et paramètres DH

---

## 📁 Structure du Projet

```
projet-crypto/
│
├── src/
│   ├── main.c
│   ├── crypto.c
│   ├── network.c
│
├── include/
│   ├── crypto.h
│   ├── network.h
│
├── keys/
│   ├── server_dsa_priv.pem
│   ├── server_dsa_pub.pem
│   ├── client_dsa_priv.pem
│   ├── client_dsa_pub.pem
│   └── dhparams.pem
│
├── Makefile
└── README.md
```

---

## 🔧 Installation et Setup

### Dépendances

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

### Compilation et Génération des clés

Le Makefile compile le projet et gère automatiquement la génération des clés et paramètres DH(p,g) cryptographiques si nécessaire :

Si dhparams.pem n'existe pas, les paramètres Diffie-Hellman (p,g) 2048 bits sont créés.
```bash
make
```

Si les clés DSA n'existent pas, elles sont générées automatiquement :

server_dsa_priv.pem / server_dsa_pub.pem

client_dsa_priv.pem / client_dsa_pub.pem
```bash
make keys
```
## 🔄 Fonctionnement des Threads

### Thread de réception

* Lecture des paquets
* Déchiffrement AES-256
* Vérification DSA
* Affichage du message

### Thread d’envoi

* Lecture de l’entrée utilisateur
* Génération IV
* Chiffrement AES
* Signature DSA
* Envoi au réseau

---

## 🛡️ Sécurité

* Clé AES jamais transmise (issue de DH)
* Signatures DSA empêchant les attaques MITM
* IV unique par paquet
* Vérification stricte du padding et de la signature

---

## 👤 Auteur

Projet réalisé par **TRAN Bui Xuan Vinh**  
Période : **5/11/2025 → 5/12/2025**

