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

/* Envoi de données via socket TCP */
ssize_t send_data(int sockfd, const void *data, size_t len);

/* Reception de donnees via socket TCP */
ssize_t recv_data(int sockfd, void *buffer, size_t len);

#endif
