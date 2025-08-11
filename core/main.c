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

// logs
#include "includes/logs.h"

struct database_configs_t {
    char database_server[BUFFER_SIZE];
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];
    char database[BUFFER_SIZE];
};


struct operator_console_t {
    int x;
    int port;
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
    char ssl_cert[0x100];
    char ssl_key[0x100];
};



char *server_config();
struct database_configs_t *database_config(cJSON *configs);
struct communication_channels_t *channels_config(cJSON *configs);
struct operator_console_t *operator_console(cJSON *configs);

int main() {
    char *buffer = server_config();
    PARSE:
    cJSON *config = cJSON_Parse(buffer);
    if (!config) {
        const char *error_ptr = cJSON_GetErrorPtr();
        
        if (error_ptr != NULL) {
            log_message(LOG_ERROR, "Failed to parse configuratation file JSON | near: %s", error_ptr);
        } else {
            log_message(LOG_ERROR, "Failed to parse configuratation file JSON ");
        }
        free(buffer);
        sleep(30);
        goto PARSE;
    } 
    free(buffer);

    struct database_configs_t *database = database_config(config);
    if (database == NULL) log_message(LOG_WARN, "Failed to parse database configurations");

    struct communication_channels_t *channels = channels_config(config);
    if (channels == NULL) log_message(LOG_WARN, "Failed to parse communications configurations");
    
    struct operator_console_t *operator = operator_console(config); 
    if  (operator == NULL) {
        log_message(LOG_ERROR, "Failed to parse Operator Console configurations");
        cJSON_Delete(config);
        exit(EXIT_FAILURE);
    }
    log_message(LOG_INFO, "Operator console port: %d", operator->port);


    
    cJSON_Delete(config);
    // open logs
    if (db_conn(database->database_server, database->username, database->password, database->database)) {
        log_message(LOG_ERROR, "Failed to connect to database");
        sleep(120);
    }
    log_message(LOG_INFO, "Database connect successfully");

    struct Args_t {
        char cert[BUFFER_SIZE];
        char key[BUFFER_SIZE];
        int port;
    };

    /*
    do {
        pthread_t operator_thread, tcp_thread, tcp_ssl_thread;
        if (operator->port <= 0) {

            struct Args_t *args = malloc(sizeof(*args));;
            strncpy(args->cert, channels->ssl_cert, BUFFER_SIZE);
            strncpy(args->key, channels->ssl_key, BUFFER_SIZE);
            args->port =operator->port;
            
            if (pthread_create(&operator_thread, NULL, Operator_conn, (void*)args) != 0) {
                log_message(LOG_WARN, "Failed to start listener for operator thread");
                sleep(30);
            }
            log_message(LOG_INFO, "Operator Console listener started successfully");
        } else {
            log_message(LOG_ERROR, "Listener Port for operator console is invalid");
        }

        if (channels->tcp == true) {
            
            if (pthread_create(&tcp_thread, NULL, tcp_agent_conn, (void*)&channels->tcp_port) != 0) {
                log_message(LOG_ERROR, "Failed to start tcp listener thread");
                sleep(30);
            }
        }
        
        if (channels->tcp_ssl == true) {

            struct Args_t *args = malloc(sizeof(*args));;
            strncpy(args->cert, channels->ssl_cert, BUFFER_SIZE);
            strncpy(args->key, channels->ssl_key, BUFFER_SIZE);
            args->port = channels->tcp_ssl_port;

            if (pthread_create(&tcp_ssl_thread, NULL, tcp_ssl_listener, (void*)args) != 0) {
                log_message(LOG_ERROR, "Failed to start encrypted tcp listener thread");
                sleep(30);
            }
        }

        // Wait for threads to finish (if they ever do)
        pthread_join(operator_thread, NULL);
        pthread_join(tcp_thread, NULL);
        pthread_join(tcp_ssl_thread, NULL);
    } while (1);
     */
    do {
        pthread_t operator_thread = 0, tcp_thread = 0, tcp_ssl_thread = 0; // Initialize to 0
        int operator_thread_created = 0, tcp_thread_created = 0, tcp_ssl_thread_created = 0;
    
        if (operator->port > 0) {
            struct Args_t *args = malloc(sizeof(*args));
            if (!args) {
                log_message(LOG_ERROR, "Failed to allocate args for operator thread");
                sleep(30);
                continue;
            }
    
            strncpy(args->cert, channels->ssl_cert, BUFFER_SIZE);
            strncpy(args->key, channels->ssl_key, BUFFER_SIZE);
            args->port = operator->port;
    
            if (pthread_create(&operator_thread, NULL, Operator_conn, (void*)args) == 0) {
                operator_thread_created = 1; // Mark as created
                log_message(LOG_INFO, "Operator Console listener started successfully");
            } else {
                //log_message(LOG_WARN, "Failed to start operator thread");
                log_message(LOG_ERROR, "Failed to create operator thread (error: %s)", strerror(errno));
                free(args); // Cleanup on failure
                sleep(30);
            }
        }
    
        if (channels->tcp) {
            if (pthread_create(&tcp_thread, NULL, tcp_agent_conn, (void*)&channels->tcp_port) == 0) {
                tcp_thread_created = 1;
            } else {
                log_message(LOG_ERROR, "Failed to start TCP listener thread");
                sleep(30);
            }
        }
    
        if (channels->tcp_ssl) {
            struct Args_t *args = malloc(sizeof(*args));
            if (!args) {
                log_message(LOG_ERROR, "Failed to allocate args for SSL thread");
                sleep(30);
                continue;
            }
    
            strncpy(args->cert, channels->ssl_cert, BUFFER_SIZE);
            strncpy(args->key, channels->ssl_key, BUFFER_SIZE);
            args->port = channels->tcp_ssl_port;
    
            if (pthread_create(&tcp_ssl_thread, NULL, tcp_ssl_listener, (void*)args) == 0) {
                tcp_ssl_thread_created = 1;
            } else {
                log_message(LOG_ERROR, "Failed to start SSL TCP listener thread");
                free(args); // Cleanup on failure
                sleep(30);
            }
        }
    
        // Only join threads that were successfully created
        if (operator_thread_created) pthread_join(operator_thread, NULL);
        if (tcp_thread_created) pthread_join(tcp_thread, NULL);
        if (tcp_ssl_thread_created) pthread_join(tcp_ssl_thread, NULL);
    
    } while (1);

    free(operator);
    free(channels);
    free(database);
    
    db_close();
    return 0;
}

char *server_config() {
    char *buffer = (char*)malloc(0x400);
    size_t bytesRead;
    START:
    int conf = open("tibane_server_conf.json", O_RDONLY);
    if (conf == -1) {
        //write(1, "Failed to Configuration file\n", 20);
        //perror( "Failed to Configuration file\n");
        log_message(LOG_ERROR, "Failed to open configuration file");
        // logfile
        sleep(30);
        goto START;
    }
    if ((bytesRead = read(conf, buffer, 0x400 - 1)) <= 0) {
        log_message(LOG_ERROR, "Failed to read data from configuration file");
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
    if (!database_array || !cJSON_IsArray(database_array)) {
        log_message(LOG_ERROR, "Missing or invalid database configuration array");
        free(database);
        return NULL;
    }

    cJSON *db_object = cJSON_GetArrayItem(database_array, 0);
    if (!db_object || !cJSON_IsObject(db_object)) {
        log_message(LOG_ERROR, "First item in for Database configuration is not a valid object");
        free(database);
        return NULL;
    }

    char *keys[] = {"database_server", "username", "password", "database"};
    char *targets[] = {
        database->database_server,
        database->username,
        database->password,
        database->database
    };

    for (int i = 0; i < 4; i++) {
        cJSON *database_item = cJSON_GetObjectItem(db_object, keys[i]);
        const char *value = (database_item && cJSON_IsString(database_item)) ? database_item->valuestring : "NULL";
        strncpy(targets[i], value, BUFFER_SIZE - 1);
        targets[i][BUFFER_SIZE - 1] = '\0';
    }

    return database;
}




struct communication_channels_t *channels_config(cJSON *configs) {
    struct communication_channels_t *channels = malloc(sizeof(*channels));
    if (!channels) return NULL;

    cJSON *comm_array = cJSON_GetObjectItem(configs, "CommunicationChannels");
    if (!comm_array || !cJSON_IsArray(comm_array)) {
        log_message(LOG_ERROR, "Missing or Invalid communications channels configurations array");
        free(channels);
        return NULL;
    }

    cJSON *comm = cJSON_GetArrayItem(comm_array, 0);
    if (!comm || !cJSON_IsObject(comm)) {
        log_message(LOG_ERROR, "First Item in `CommuniationsChannels` is note a valid object");
        free(channels);
        return NULL;
    }

    // Default values (optional)
    channels->tcp = channels->tcp_ssl = channels->https = 0;
    channels->tcp_port = channels->tcp_ssl_port = channels->https_port = 0;
    memset(channels->ssl_cert, 0, sizeof(channels->ssl_cert));
    memset(channels->ssl_key, 0, sizeof(channels->ssl_key));

    cJSON *item;

    if ((item = cJSON_GetObjectItem(comm, "tcp")) && cJSON_IsBool(item))
        channels->tcp = cJSON_IsTrue(item);

    if ((item = cJSON_GetObjectItem(comm, "tcp_ssl")) && cJSON_IsBool(item))
        channels->tcp_ssl = cJSON_IsTrue(item);

    if ((item = cJSON_GetObjectItem(comm, "https")) && cJSON_IsBool(item))
        channels->https = cJSON_IsTrue(item);

    if ((item = cJSON_GetObjectItem(comm, "tcp_port")) && cJSON_IsNumber(item))
        channels->tcp_port = item->valueint;

    if ((item = cJSON_GetObjectItem(comm, "tcp_ssl_port")) && cJSON_IsNumber(item))
        channels->tcp_ssl_port = item->valueint;

    if ((item = cJSON_GetObjectItem(comm, "https_port")) && cJSON_IsNumber(item))
        channels->https_port = item->valueint;

    if ((item = cJSON_GetObjectItem(comm, "ssl_cert")) && cJSON_IsString(item))
        strncpy(channels->ssl_cert, item->valuestring, sizeof(channels->ssl_cert) - 1);

    if ((item = cJSON_GetObjectItem(comm, "ssl_key")) && cJSON_IsString(item))
        strncpy(channels->ssl_key, item->valuestring, sizeof(channels->ssl_key) - 1);

    return channels;
}




struct operator_console_t *operator_console(cJSON *configs) {
    struct operator_console_t *operator = malloc(sizeof(*operator));
    if (!operator) return NULL;

    cJSON *op_array = cJSON_GetObjectItem(configs, "OperatorConsole");
    if (!op_array || !cJSON_IsArray(op_array)) {
        log_message(LOG_ERROR, "Missing or Invalid OperatorConsole configuration array");
        free(operator);
        return NULL;
    }

    cJSON *op = cJSON_GetArrayItem(op_array, 0);
    if (!op || !cJSON_IsObject(op)) {
        
        log_message(LOG_ERROR, "First Item in Operator Console in not valid object");
        free(operator);
        return NULL;
    }

    cJSON *item = cJSON_GetObjectItem(op, "port");
    if (!item || !cJSON_IsNumber(item)) {
        log_message(LOG_ERROR, "Operator Port is Missing");
        free(operator);
        return NULL;
    }

    operator->port = item->valueint;
    if (operator->port <= 0 || operator->port > 65535) {
        log_message(LOG_ERROR, "Invalid port number");
        free(operator);
        return NULL;
    }
    return operator;
}
