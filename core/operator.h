#ifndef operator
#define operator

#include <pthread.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

#include "db.h"

#define PORT 8888

struct thread_args {
    int sock;
    char ip[256];
};

void info_view(char *table) {
    
}

void OPERATE() {

}






void *authenticate(void *args) {
    struct thread_args *arg = (struct thread_args*)args;
    int sock = arg->sock;
    
    char auth[1024];
    int bytes_received = recv(sock, auth, sizeof(auth), 0);
    if (bytes_received <= 0) {
        perror("recv failed");
        return NULL;
    }
    auth[bytes_received] = '\0'; 
    
    cJSON *creds cJSON_Parse(auth);
    cJSON *username = cJSON_GetObjectItem(creds, "username");
    cJSON *password = cJSON_GetObjectItem(creds, "password");

    cJSON *reply = cJSON_CreateObject();
    if (authenticate_operator(username->valuestring, password->valuestring) == 0) {
        cJSON_AddStringToObject(reply, "operator", "true");
        char *reply_ = cJSON_Print(reply);
        send(sock, reply_, strlen(reply_), 0);

        OPERATE();

    } else {
        cJSON_AddStringToObject(reply, "operator", "false");
        char *reply_ = cJSON_Print(reply);
        send(sock, reply_, strlen(reply_), 0);
    }
    close(sock);
    free(args);
    return NULL;
}


int Operator() {
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
        args->sock = sock;
        strcpy(args->ip, inet_ntoa(clientAddr.sin_addr));

        if (pthread_create(&thread, NULL, authenticate, (void*)args) < 0) {
            perror("could not create thread");
            free(args);
            continue;
        }
        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread);
        
    }

    close(serverSock);

    return 0;

}




#endif