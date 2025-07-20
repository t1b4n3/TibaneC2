#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <cjson/cJSON.h>
#include "./includes/db.h"
#include "./includes/operator.h"
#include "./includes/beacon_tcp.h"
#include "./includes/register.h"

void *agent_conn(void *port);
void *agent_handler(void *args);


int main() {
    // for log file
    lopen();
    // get 
    START:
    int conf = open("../config/server_conf.json", O_RDONLY);
    if (conf == -1) {
        write(1, "Failed to Configuration file\n", 20);
        // logfile
        sleep(30);
        goto START;
    }

    char buffer[0x200];
    READ:
    size_t bytesRead;
    if ((bytesRead = read(conf, buffer, sizeof(buffer))) <= 0) {
            perror("Read Error");
            sleep(30);
            goto READ;
    }

    PARSE:
    cJSON *config = cJSON_Parse(buffer);
    if (!config) {
        fprintf(stderr, "Failed to parse JSON: %s\n", buffer);
        sleep(30);
        goto PARSE;
    }

    cJSON *username = cJSON_GetObjectItem(config, "username");
    cJSON *password = cJSON_GetObjectItem(config, "password");
    cJSON *dbserver = cJSON_GetObjectItem(config, "database_server");
    cJSON *db = cJSON_GetObjectItem(config, "database");
    cJSON *agent_port = cJSON_GetObjectItem(config, "agent_port");
    cJSON *operator_port = cJSON_GetObjectItem(config, "operator_port");

    close(conf);

    // open logs
    
    if (db_conn(dbserver->valuestring, username->valuestring, password->valuestring, db->valuestring) == -1) {
        perror("Database Failed to connect");
        exit(1);
    }
    pthread_t operator_thread, agent_thread;
    if (pthread_create(&operator_thread, NULL, Operator_conn, (void*)&operator_port->valueint) != 0) {
        perror("Failed to start Operator thread");
        exit(1);
    }




    if (pthread_create(&agent_thread, NULL, agent_conn, (void*)&agent_port->valueint) != 0) {
        perror("Failed to start Operator thread");
        exit(1);
    }
    
    // Wait for threads to finish (if they ever do)
    pthread_join(operator_thread, NULL);
    pthread_join(agent_thread, NULL);


    cJSON_Delete(config);
    db_close();
    lclose();
    return 0;
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
    } else if (strcmp(type->valuestring, "session") == 0) {
        // session mode
        // session();
    }

    //cJSON_Delete(json);
    close(sock);
    free(args);
    return NULL;
}