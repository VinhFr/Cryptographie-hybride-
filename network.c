#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* ====================================================================== */
/*           Implementation des fonctions sockets TCP                     */
/* ====================================================================== */

int create_server_socket(int port){
  /* Creation socket TCP */
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1){
    perror("Socket creation error");
    return EXIT_FAILURE;
  }

  /* Init caracteristiques serveur distant (struct sockaddr_in) */
  struct  sockaddr_in serv_addr, cli_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  serv_addr.sin_addr.s_addr = INADDR_ANY;

  /* Associer une adresse locale (numero de port et adresse IP) */
  if (bind(server_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
    perror("Bind error");
    close(server_fd);
    return EXIT_FAILURE;
  }

  /* Mise d'un processus serveur a l'etat d'ecoute */
  if (listen(server_fd, 15) == -1){
    perror("listen error");
    close(server_fd);
    return EXIT_FAILURE;
  }

  printf("Serveur prêt sur le port %d\n", port);
  return server_fd;
}

int create_client_socket(const char *ip, int port){
  /* Creation socket TCP */
  int client_fd;
  client_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (client_fd == -1){
    perror("Socket creation error");
    return EXIT_FAILURE;
  }

  /* Init caracteristiques serveur distant (struct sockaddr_in) */
  struct  sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  inet_pton(AF_INET,ip, &(serv_addr.sin_addr));


  /* Etablissement connexion TCP avec process serveur distant */
  if (connect(client_fd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1){
      perror("Connectino error");
      close(client_fd);
      return EXIT_FAILURE;
  }

  printf("Client connecté depuis %s:%d\n",ip,port);
  return client_fd;
}

/* Acceptation d'une connexion entrante */
int accept_client(int server_fd){
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);

  int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
  if (client_fd < 0) {
      perror("Erreur accept");
      return -1;
  }

  printf("Client connecté depuis %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
  return client_fd;
}

ssize_t send_n_data(int sockfd, const void *buffer, size_t len){
  size_t left = len;
  const char *p = buffer;
  while (left){
    ssize_t sent_bytes = send(sockfd, p, left, 0);
    if (sent_bytes < 0) {
        perror("Erreur send");
        return -1;
    }
    left -= sent_bytes;
    p += sent_bytes;
  }
  return sent_bytes;
}

ssize_t recv_n_data(int sockfd, void *buffer, size_t len){
  size_t left = len;
  char *p = buffer;
  while (left){
    ssize_t recv_bytes = recv(sockfd, p, left, 0);
    if (recv_bytes < 0) {
        perror("Erreur recv");
        return -1;
    }
    left -= recv_bytes;
    p += recv_bytes;
  }
  return recv_bytes;
}

/* Parametres :
   be - Big-Endian
   htonl() : host -> network(32-bit)
*/
int send_blob(int sockfd, const unsigned char *buffer, uint32_t len){
  uint32_t be = htonl(len);
  if (send_n_data(sockfd, &be, 4) != 4) return -1;
  if (len > 0 && send_n_data(sockfd,buffer,len) != (ssize_t)len) return -1;
  return 0;
}

/*
  ntohl() : network -> host (32-bit)
*/
int recv_blob(int sockfd, unsigned char **out, uint32_t *out_len){
  uint32_t be;
  if (recv_n_data(sockfd,&be,4) != 4) return -1;
  uint32_t len = ntohl(be);
  unsigned char *buffer = NULL;
  if (len){
    buffer = OPENSSL_malloc(len);
    if (!buffer) return -1;
    if (recv_n_data(sockfd, buffer, len) != (ssize_t)len){
      OPENSSL_free(buffer);
      return -1;
    }
  }
  *out = buffer;
  *out_len = len;
  return 0;
}
