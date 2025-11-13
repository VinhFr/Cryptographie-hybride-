#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

int sock;

void* recv_thread(void* arg) {
    char buffer[1024];
    while (1) {
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) break;
        buffer[bytes] = '\0';
        printf("\n[Server]: %s\n> ", buffer);
        fflush(stdout);
    }
    return NULL;
}

void* send_thread(void* arg) {
    char buffer[1024];
    while (1) {
        printf("> ");
        fflush(stdout);
        fgets(buffer, sizeof(buffer), stdin);
        send(sock, buffer, strlen(buffer), 0);
    }
    return NULL;
}

int main() {
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8888);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

    pthread_t t_send, t_recv;
    pthread_create(&t_recv, NULL, recv_thread, NULL);
    pthread_create(&t_send, NULL, send_thread, NULL);

    pthread_join(t_send, NULL);
    pthread_join(t_recv, NULL);

    close(sock);
    return 0;
}
