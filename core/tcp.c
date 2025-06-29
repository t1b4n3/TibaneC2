#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>

#define PORT 9999

struct thread_args {
    int sock;
    char *ip;
    int agent_id;
};

void *agent_handler(void *args) {
    struct thread_args *args = (struct thread_args*)args;
    
}

int tcp_listener() {
    struct sockaddr_in clientAddr;
    socklen_t client_len = sizeof(clientAddr);
    int serverSock;

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_family = AF_INET;

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) {
        perror("binding failed");
        close(serverSock);
        return -1;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        perror("Listen Failed");
        close(serverSock);
        return -1;
    }
    
    while (1) {
        int sock;
        if ((sock = accept(serverSock, (struct sockaddr*)&clientAddr, (socklen_t*)&client_len)) < 0) {
            perror("Accept failed");
            continue;
        }
        
        // port = ntohs(clientAddr.sin_port) 
        // ip = inet_ntoa(client_addr.sin_addr)

        pthread_t thread;
        struct thread_args *args = malloc(sizeof(struct thread_args));
        args->sock=sock;
        strcpy(args->ip, inet_ntoa(clientAddr.sin_addr));

        if (pthread_create(&thread, NULL, agent_handler, (void*)args) < 0) {
            perror("could not create thread");
            close(sock);
            continue;
        }
        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread);
        
        close(sock);
    }

    close(serverSock);

    return 0;

}


