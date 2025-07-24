#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <fcntl.h>
#include <cjson/cJSON.h>

// my headers
#include "./includes/db.h"
#include "./includes/operator.h"
//#include "./includes/register.h"

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
    int tcp_ssl_port;
};

struct communication_channels_t {
    bool tcp;
    bool https;
    bool tcp_ssl;
    // ports
    int tcp_port;
    int https_port;
    int tcp_ssl_port;
    // ssl certificates
    char *ssl_cert;
    char *ssl_key;
};



char *server_config();
struct database_configs_t *database_config(cJSON *configs);
struct communication_channels_t *channels_config(cJSON *configs);
struct operator_console_t *operator_console(cJSON *configs);

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
    if (database == NULL);

    struct communication_channels_t *channels = channels_config(config);
    if (channels == NULL);
    
    struct operator_console_t *operator = operator_console(config); 
    if (operator == NULL);

    cJSON_Delete(config);

    // open logs
    if (db_conn(database->database_server, database->username, database->password, database->database)) {
        perror("Database Failed to connect");
        sleep(120);
    }

    do {
        
        pthread_t operator_thread, tcp_thread, tcp_ssl_thread;;
        if (pthread_create(&operator_thread, NULL, Operator_conn, (void*)&operator->tcp_port) != 0) {
            perror("Failed to start Operator thread");
            sleep(30);
        }
        if (channels->tcp == true) {
            if (pthread_create(&tcp_thread, NULL, tcp_agent_conn, (void*)&channels->tcp_port) != 0) {
                perror("Failed to start TCP thread");
                sleep(30);
            }
        }
        
        if (channels->tcp_ssl == true) {
            if (pthread_create(&tcp_ssl_thread, NULL, tcp_ssl_listener, (void*)&channels->tcp_ssl_port) != 0) {
                perror("Failed to start TCP SSL thread");
                sleep(30);
            }
        }

        // Wait for threads to finish (if they ever do)
        pthread_join(operator_thread, NULL);
        pthread_join(tcp_thread, NULL);
        pthread_join(tcp_ssl_thread, NULL);
    } while (1);

    free(operator);
    free(channels);
    free(database);
    
    db_close();
    lclose();
    return 0;
}

char *server_config() {
    char *buffer = (char*)malloc(0x200);
    size_t bytesRead;
    START:
    int conf = open("../config/server_conf.json", O_RDONLY);
    if (conf == -1) {
        //write(1, "Failed to Configuration file\n", 20);
        perror( "Failed to Configuration file\n");
        // logfile
        sleep(30);
        goto START;
    }
    if ((bytesRead = read(conf, buffer, sizeof(buffer))) <= 0) {
        perror("Read Error");
        sleep(30);
        goto START;
    }
    close(conf);
    return buffer;
}

struct database_configs_t *database_config(cJSON *configs) {
    struct database_configs_t *database = malloc(sizeof(*database));
    if (!database) return NULL;
    cJSON *database_array = cJSON_GetObjectItem(configs, "Database");
    // handle error
    if (!database_array) {
        //
        return NULL;
    }
    char *keys[] = {"database_server", "username", "password", "database"};
    char *targets[] = {database->database_server, database->username, database->password, database->database};


    for (int i = 0; i < 4; i++) {
        cJSON *database_item = cJSON_GetObjectItem(database_array, keys[i]);
        char *value = (database_item && database_item->valuestring) ? database_item->valuestring : "NULL";
        strncpy(targets[i], value, BUFFER_SIZE - 1);
        targets[i][BUFFER_SIZE - 1] = '\0';
    }
    cJSON_Delete(database_array);
    return database;
}

struct communication_channels_t *channels_config(cJSON *configs) {
    struct communication_channels_t *channels = malloc(sizeof(*channels));
    if (!channels) return NULL;
    cJSON *comm = cJSON_GetObjectItem(configs, "Communication Channels");

    char *keys[] = {"tcp", "tcp_ssl", "https", "tcp_port", "tcp_ssl_port", "https_port", "ssl_cert", "ssl_key"};
    
    /*char *targets[] = {channels.ssl_cert, channels.ssl_key};
    int ports[] = (channels.tcp_port, channels.tcp_ssl_port, channels.https_port);
    bool flags[] = {channels.tcp, channels.https, channels.tcp_ssl};

    for (int i = 0;i < 8; i++) {
        cJSON *item = cJSON_GetArrayItem(comm, keys[i]);
        if (cJSON_IsString(item)) {
            strncpy(targets[i], item->valuestring, BUFFER_SIZE-1);
            targets[i][BUFFER_SIZE - 1] = '\0';
            continue;
        } else if (cJSON_IsBool(item)) {
            targets[i] = cJSON_IsTrue(item) ? true : false;
            continue;
        } else if (cJSON_IsNumber(item)) {
            targets[i] = item->valueint;
            continue;
        } 
    }*/

    for (int i = 0; i < 8; i++) {
        cJSON *item = cJSON_GetObjectItem(comm, keys[i]);
        if (!item) continue;

        if (i < 3 && cJSON_IsBool(item)) {
            // Boolean flags
            if (i == 0) channels->tcp = cJSON_IsTrue(item);
            if (i == 1) channels->tcp_ssl = cJSON_IsTrue(item);
            if (i == 2) channels->https = cJSON_IsTrue(item);
        } else if (i >= 3 && i <= 5 && cJSON_IsString(item)) {
            // Portss
            if (i == 3) channels->tcp_port =  item->valueint;
            if (i == 4) channels->tcp_ssl_port = item->valueint;
            if (i == 5) channels->https_port = item->valueint;
        } else if (i == 6 && cJSON_IsString(item)) {
            strncpy(channels->ssl_cert, item->valuestring, sizeof(channels->ssl_cert) - 1);
        } else if (i == 7 && cJSON_IsString(item)) {
            strncpy(channels->ssl_key, item->valuestring, sizeof(channels->ssl_key) - 1);
        }
        cJSON_Delete(item);
    }
    cJSON_Delete(comm);
    return channels;
}

struct operator_console_t *operator_console(cJSON *configs) {
    struct operator_console_t *operator = malloc(sizeof(*operator));
    if (!operator) return NULL;
    cJSON *op = cJSON_GetObjectItem(configs, "Operator Console");
    cJSON *item = cJSON_GetObjectItem(op, "tcp_port");
    operator->tcp_port = item->valueint;
    return operator;
}