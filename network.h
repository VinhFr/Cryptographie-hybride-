#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>

/* =================================================================== */
/*   Fichier contient des fonctions "socket" pour la communication     */
/*   entre deux appareils (1 client - 1 serveur).                                             */
/*   Utilise les socket TCP (fiabilité garantie).                      */
/* =================================================================== */

/* Création d'un socket TCP serveur */
int create_server_socket(int port);

/* Création d'un socket TCP client */
int create_client_socket(const char *ip, int port);

/* Acceptation d'une connexion entrante  */
int accept_client(int server_fd);

/*
 * Ici, j'utilise send_n_data (ou recv_n_data) au lieu de la fonction send (recev) simple pour garantir que
 * tous les octets demandés sont effectivement envoyés (ou recu) sur le socket.
 * BN = Big number (Grand nombre)
 * La fonction send (ou recev) peut ne pas envoyer (ou recevoir) toutes les données en une seule fois,
 * notamment lorsque la taille des données est grande ou à cause des limites du buffer réseau.
 * Par conséquent, il est nécessaire de boucler et d’envoyer (ou recevoir) les données restantes
 * jusqu’à ce que la totalité soit transmise.
 *
 * send_n_data (ou recv_n_data) gère ce comportement en répétant les appels à send,
 * ajustant le pointeur de données et la longueur restante à chaque itération,
 * assurant ainsi un envoi (ou recu) complet et fiable.
 */
ssize_t send_n_data(int sockfd, const void *data, size_t len);
ssize_t recv_n_data(int sockfd, void *buffer, size_t len);

/* Envoi header (taille de paquet) et data */
int send_blob(int sockfd, const unsigned char *buffer, uint32_t len);

/* Recu header (taille de paquet) et data */
int recv_blob(int sockfd, unsigned char **out, uint32_t *out_len);
#endif
