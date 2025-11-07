# Projet chiffrement et dechiffrement entre 2 appareils en utilisant Diffie-Hellman (DH), Digital Signature Algorithm (DSA), Advanced Encryption Standard (AES). 

## Table of Contents
1. [Info Générales](#general-info)  
2. [Technologies](#technologies)  
3. [Installation](#installation)  
4. [Méthodes de Chiffrement](#méthodes-de-chiffrement)  
    - [Chiffrement par XOR](#chiffrement-par-xor)  
    - [Chiffrement par Bloc : CBC](#chiffrement-par-bloc-cbc)  
5. [Échange de Clés : Diffie-Hellman](#échange-de-clés-diffie-hellman)  
6. [Cryptanalyse](#cryptanalyse)  
    - [Attaques sur le Message Chiffré](#attaques-sur-le-message-chiffré)  
    - [Attaque sur le Masque Jetable](#attaque-sur-le-masque-jetable)  
7. [Contributeurs](#contributeurs)

---

## Info Générales
Ce projet a pour objectif d'explorer les techniques fondamentales de chiffrement, d'échange sécurisé de clés et de cryptanalyse. Il se compose de trois parties principales :  
1. Mise en œuvre de méthodes de chiffrement symétrique.  
2. Simulation de l'échange de clés Diffie-Hellman.  
3. Développement d'attaques pour casser les messages chiffrés.  

### Statut : Terminé ✅  

---

## Technologies
Voici les technologies et outils utilisés dans ce projet :  
- **C** : Implémentation des algorithmes de chiffrement et cryptanalyse.  
- **Makefile** : Gestion de la compilation et des dépendances.  
- **GNU Compiler Collection (GCC)** : Compilation du code source.  

---

## Installation
Pour exécuter le projet, suivez ces étapes :  

1. **Clonez le dépôt** :  
    ```bash
    git clone https://example.com
    cd chemin/vers/le/projet
    ```

2. **Compilez les différentes parties** :  
    - Partie 1 (Chiffrement symétrique) :  
        ```bash
        make P1
        ./sym_crypt -i clair.txt -o crypt.txt -k taratata -m cbc-crypt -v iv.txt
        ./sym_crypt -o clair.txt -i crypt.txt -f key.txt -m xor -l log.txt
        ./sym_crypt -i clair.txt -o crypt.txt -f key.txt -m mask
        ```
    - Partie 2 (Échange Diffie-Hellman) :  
        ```bash
        make P2
        ./dh_gen_group -o param.txt
        ./python3 dh_genkey.py -i param.txt -o key.txt
        ```
    - Partie 3 (Cryptanalyse) :  
        ```bash
        make P3
        ./break_code -i Datas/Crypted/ringCxor.txt -m c1 -k 4 -l log.txt
        ./break_code -i Datas/Crypted/ringCxor.txt -m all -k 4 -d Dicos/english.txt
        ./crack mask chif1.txt chif2.txt test2.txt clair.txt
        ```

3. **Nettoyez les fichiers intermédiaires** :  
    - Supprimez les fichiers objets :  
        ```bash
        make clean
        ```
    - Supprimez également les exécutables :  
        ```bash
        make mrproper
        ```  

---

## Méthodes de Chiffrement
### Chiffrement par XOR
Le chiffrement par XOR est une méthode simple où chaque caractère du message est combiné à une clé via l'opérateur XOR. Ce projet implémente également le déchiffrement.

### Chiffrement par Bloc : CBC
Le mode **Cipher Block Chaining (CBC)** relie chaque bloc chiffré au précédent pour renforcer la sécurité. Cette méthode permet de chiffrer des messages plus longs en toute sécurité.

---

## Échange de Clés : Diffie-Hellman
L'échange de clés Diffie-Hellman est implémenté pour simuler une négociation sécurisée entre deux parties, en utilisant des nombres premiers et des groupes cycliques.

---

## Cryptanalyse
### Attaques sur le Message Chiffré
Le projet inclut plusieurs outils d'attaque pour casser les messages chiffrés :  
1. **Réduction des Caractères Possibles (Crack C1)** :  
   Limitation des caractères possibles dans la clé en analysant les résultats probables.  
2. **Analyse Statistique (Crack C2)** :  
   Utilisation des fréquences des lettres pour deviner le message ou la clé.  
3. **Attaque par Dictionnaire (Crack C3)** :  
   Comparaison avec une base de données de mots pour deviner le contenu chiffré.  

### Attaque sur le Masque Jetable
Démonstration des faiblesses liées à la réutilisation d’un masque jetable, qui compromet la confidentialité.

---

## Contributeurs
Un grand merci aux contributeurs de ce projet :  
- **NGUYEN Duc Hai** : Responsable Projet - Implémentation Makefile - P1 : XOR et Masque jetable - P2 : Calcul nombre premier - P3 : Attaque sur Masque jetable
- **SESCAU Mathias** : Responsable Conception/Intégration - Rédaction README - P1 : Déchiffrement CBC - P2 : Simulation d'échange et calcul de clé - P3 : Attaque par Dictionnaire (Crack C3)
- **CANTALEJO Jorian** : Responsable Conception/Intégration - P1 : Chiffrement CBC - P2 : Simulation d'échange et calcul de clé - P3 : Analyse Statistique (Crack C2)  
- **TRAN Bui Xuan Vinh** : P1 : XOR et Masque jetable - P2 : Calcul nombre premier - P3 : Réduction des Caractères Possibles (Crack C1)

