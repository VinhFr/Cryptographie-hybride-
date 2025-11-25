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
* Outils GNU/Linux et Makefile pour la compilation

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

---

## 📁 Structure du Projet

```
projet-crypto/
│
├── src/
│   ├── main.c
│   ├── network.c
│   ├── crypto_dh.c
│   ├── crypto_dsa.c
│   ├── crypto_aes.c
│   ├── thread_handler.c
│   └── utils.c
│
├── include/
│   ├── network.h
│   ├── crypto_dh.h
│   ├── crypto_dsa.h
│   ├── crypto_aes.h
│   ├── thread_handler.h
│   └── utils.h
│
├── keys/
│   ├── dsa_private.pem
│   ├── dsa_public.pem
│   └── dh_params.pem
│
├── Makefile
└── README.md
```

---

## 🔧 Installation

### Dépendances

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

---

## 🏗️ Compilation

```bash
make
```

Nettoyage :

```bash
make clean
```

---

## ▶️ Exécution

### Serveur :

```bash
./crypto_app server 5000
```

### Client :

```bash
./crypto_app client 127.0.0.1 5000
```

---

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

Projet réalisé par **[Votre Nom]**
Année : **2024–2025**

---

## 📄 Licence

**MIT License**
