# E2EE : Chiffrement & Déchiffrement Sécurisé entre Deux Appareils

Basé sur Diffie–Hellman (DH), DSA, HKDF et AES — utilisant les sockets réseau TCP, le multithreading et les outils GNU/Linux.

---

## 📝 Description

Ce projet implémente une communication sécurisée entre deux appareils (Client ↔ Serveur) en combinant :

* Diffie–Hellman (DH) pour l’échange de clé
* Digital Signature Algorithm (DSA) pour la signature et la vérification
* HKDF-SHA256 pour la dérivation et le renouvellement sécurisé des clés AES 
* AES-256 pour le chiffrement symétrique (GCM -Galois counter mode)
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
| IV | Données chiffrées AES |
```

### Clé de session (AES-256)

* Créée automatiquement à chaque nouvelle session
* N’existe que pour la durée de la session (tempt fixe)
* Éphémère : elle disparaît à la fin de la session
* Garantit le Perfect Forward Secrecy (PFS) grâce au renouvellement systématique

---

## 🧩 Architecture Fonctionnelle

```
	 Appareil A (client)                         	           Appareil B (server)
	 ------------------------------------------------------------------------
Etape 1:		 Échange de clé publique DH + signature 
Etape 2:    		 Vérification de la signature
Etape 3: 		 Dérivation du secret partagé (shared key)
Etape 4:		 Génération d'une clé AES de session pour chaque message    
Etape 5: Envoi de message chiffré AES-GCM      <------------------> Envoi de message chiffré AES-GCM
Etape 6: Déchiffrement et affichage du message <------------------> Déchiffrement et affichage du message
```

---

## ⚙️ Fonctionnalités

### Cryptographie

* Diffie–Hellman : génération, échange et dérivation
* DSA : signature / vérification
* AES-256 : chiffrement / déchiffrement
* HKDF : dérivation de la clé AES à partir du secret partagé DH et renouvellement pour chaque message

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

* Clé AES jamais transmise (dérivée du secret DH)
* Signatures DSA empêchant les attaques MITM
* IV unique par paquet (Authenticité)
* Vérification stricte du padding et de la signature
* Nouvelle clé AES dérivée par HKDF pour chaque message (Perfect Forward Secrecy, PFS)

---

## 👤 Auteur

Projet réalisé par **TRAN Bui Xuan Vinh**  
Période : **5/11/2025 → 5/12/2025**

