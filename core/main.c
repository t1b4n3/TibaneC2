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
#include "includes/tcp_ssl/beacon_tcp_ssl.h"
// http

// https

#define BUFFER_SIZE 256

struct database_configs_t {
    char database_server[BUFFER_SIZE];
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];
    char database[BUFFER_SIZE];
};


struct operator_console_t {
    int tcp_port;
    //int tcp_ssl_port;
};

struct communication_channels_t {
    bool tcp;
    bool https;
    bool tcp_ssl;
    // ports
    int tcp_port;
    int https_port;
    int tcp_ssl_port;
};



char *server_config();
struct database_configs_t *database_config(cJSON *configs);
struct communication_channels_t *channels_config(cJSON *configs);

int main() {
    // for log file
    lopen();
    // get 

    char *buffer = server_config();
    PARSE:
    cJSON *config = cJSON_Parse(buffer);
    if (!config) {
        fprintf(stderr, "Failed to parse JSON: %s\n", buffer);
        sleep(30);
        goto PARSE;
    }
    // free memory
    free(buffer);

    struct database_configs_t *database = database_config(config);

    struct communication_channels_t channels;

    cJSON *operator_port = cJSON_GetObjectItem(config, "operator_port");
    cJSON *tcp_port = cJSON_GetObjectItem(config, "tcp_port");
    

    

    // open logs
    if (db_conn(database->database_server, database->username, database->password, database->database)) {
        perror("Database Failed to connect");
        sleep(120);
    }

    do {
    pthread_t operator_thread, tcp_thread;
    if (pthread_create(&operator_thread, NULL, Operator_conn, (void*)&operator_port->valueint) != 0) {
        perror("Failed to start Operator thread");
        sleep(30);
    }

    if (pthread_create(&tcp_thread, NULL, tcp_agent_conn, (void*)&tcp_port->valueint) != 0) {
        perror("Failed to start Operator thread");
        
    }

    pthread_t tcp_ssl_thread;
    if (pthread_create(&tcp_ssl_thread, NULL, tcp_ssl_listener, (void*)&tcp_ssl_port->valueint) != 0) {
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

char *server_config() {
    char *buffer = (char*)malloc(0x200);
    size_t bytesRead;
    while (1) {
        int conf = open("../config/server_conf.json", O_RDONLY);
        if (conf == -1) {
            write(1, "Failed to Configuration file\n", 20);
            // logfile

            sleep(30);
            continue;
        }

        if ((bytesRead = read(conf, buffer, sizeof(buffer))) <= 0) {
            perror("Read Error");
            sleep(30);
            continue;
        }
        close(conf);
    }
    return buffer;
}

struct database_configs_t *database_configs(cJSON *configs) {
    struct database_configs_t database;
    cJSON *database_array = cJSON_GetObjectItem(configs, "Database");
    char items[4][0x20] = {"database_server", "username", "password", "database"};

    for (int i = 0; i < 4; i++) {
        char item[0x20] = items[i];
        cJSON *database_item = cJSON_GetArrayItem(database_array, item);
        char *value = (database_item && database_item->valuestring) ? database_item->valuestring : "NULL";
        
        if (strncmp("database", item, 8) == 0) {
            strncpy(database.database, value, BUFFER_SIZE);
        } else if (strncmp("database_server", item, 16) == 0) {
            strncpy(database.database_server, value, BUFFER_SIZE);
        } else if (strncpy("password", item, 8) ==  0) {
            strncpy(database.password, value, BUFFER_SIZE);
        } else if (strncmp("username", item, 8) == 0) {
            strncpy(database.username, value, BUFFER_SIZE);
        }

    }
    return &database;
}