#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/crypto.h>

/* ====================================================================== */
/*              Implémentation des fonctions sockets TCP                  */
/* ====================================================================== */

int create_server_socket(int port){
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1){
        perror("Socket creation error");
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(port);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    /* Bind */
    if (bind(server_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1){
        perror("Bind error");
        close(server_fd);
        return -1;
    }

    /* Listen */
    if (listen(server_fd, 15) == -1){
        perror("Listen error");
        close(server_fd);
        return -1;
    }

    printf("Serveur prêt sur le port %d\n", port);
    return server_fd;
}

int create_client_socket(const char *ip, int port){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1){
        perror("Socket creation error");
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0){
        perror("Invalid IP");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1){
        perror("Connection error");
        close(sock);
        return -1;
    }

    printf("Client connecté à %s:%d\n", ip, port);
    return sock;
}

int accept_client(int server_fd){
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);

    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);
    if (client_fd < 0){
        perror("Accept error");
        return -1;
    }

    printf("Client connecté depuis %s:%d\n",
           inet_ntoa(client_addr.sin_addr),
           ntohs(client_addr.sin_port));

    return client_fd;
}

/* ---------------------------------------------------------------------- */
/*        send_n_data : envoyer exactement len octets                     */
/* ---------------------------------------------------------------------- */
ssize_t send_n_data(int sockfd, const void *buffer, size_t len){
    size_t total = 0;
    const unsigned char *p = buffer;

    while (total < len){
        ssize_t n = send(sockfd, p + total, len - total, 0);
        if (n <= 0){
            perror("Erreur send");
            return -1;
        }
        total += n;
    }
    return total;
}

/* ---------------------------------------------------------------------- */
/*        recv_n_data : recevoir exactement len octets                    */
/* ---------------------------------------------------------------------- */
ssize_t recv_n_data(int sockfd, void *buffer, size_t len){
    size_t total = 0;
    unsigned char *p = buffer;

    while (total < len){
        ssize_t n = recv(sockfd, p + total, len - total, 0);
        if (n <= 0){
            perror("Erreur recv");
            return -1;
        }
        total += n;
    }
    return total;
}

/* ---------------------------------------------------------------------- */
/*        send_blob: gửi (4 byte length + data)                           */
/* ---------------------------------------------------------------------- */
int send_blob(int sockfd, const unsigned char *buffer, uint32_t len){
    uint32_t be_len = htonl(len);

    if (send_n_data(sockfd, &be_len, 4) != 4)
        return -1;

    if (len > 0 && send_n_data(sockfd, buffer, len) != (ssize_t)len)
        return -1;

    return 0;
}

/* ---------------------------------------------------------------------- */
/*        recv_blob: nhận blob (alloc động)                               */
/* ---------------------------------------------------------------------- */
int recv_blob(int sockfd, unsigned char **out, uint32_t *out_len){
    uint32_t be_len;

    if (recv_n_data(sockfd, &be_len, 4) != 4)
        return -1;

    uint32_t len = ntohl(be_len);
    unsigned char *buffer = NULL;

    if (len > 0){
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

/* ---------------------------------------------------------------------- */
/*        start_client + start_server                                     */
/* ---------------------------------------------------------------------- */

int start_client(const char *addr, int port){
    return create_client_socket(addr, port);
}

int start_server(const char *addr, int port){
    int server_fd = create_server_socket(port);
    if (server_fd < 0) return -1;

    int client_fd = accept_client(server_fd);

    close(server_fd);
    return client_fd;
}
