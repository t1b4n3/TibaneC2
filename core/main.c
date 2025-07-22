#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <cjson/cJSON.h>
#include "./includes/db.h"
#include "./includes/operator.h"
#include "./includes/register.h"

// communication channels
// tcp
#include "./includes/tcp/beacon_tcp.h"
#include "includes/tcp/tcp_listener.h"
// tcp ssl
#include "includes/tcp_ssl/tcp_ssl.h"

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
        sleep(120);
    }

    do {
    pthread_t operator_thread, tcp_thread;
    if (pthread_create(&operator_thread, NULL, Operator_conn, (void*)&operator_port->valueint) != 0) {
        perror("Failed to start Operator thread");
        sleep(30);
    }

    if (pthread_create(&tcp_thread, NULL, tcp_agent_conn, (void*)&agent_port->valueint) != 0) {
        perror("Failed to start Operator thread");
        
    }

    pthread_t tcp_ssl_thread;
    if (pthread_create(&tcp_ssl_thread, NULL, tcp_ssl_listener, (void*)&tcp_ssl->valueint) != 0) {
        perror("Failed to start Operator thread");
        sleep(30);
    }

    
    // Wait for threads to finish (if they ever do)
    pthread_join(operator_thread, NULL);
    pthread_join(tcp_thread, NULL);
    pthread_join(tcp_ssl_thread, NULL);
    } while (1);


    cJSON_Delete(config);
    db_close();
    lclose();
    return 0;
}

