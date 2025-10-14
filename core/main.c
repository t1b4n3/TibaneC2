#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <fcntl.h>
//#include "./includes/cJSON/cJSON.h"
#include <cjson/cJSON.h>
// my headers
#include "./includes/db.h"
#include "./includes/operator.h"
//#include "./includes/register.h"

// communication channels
#include "./includes/listener.h"
// logs
#include "./includes/logs.h"

#include "common.h"


char *server_config();
struct database_configs_t *database_config(cJSON *configs);
struct communication_channels_t *channels_config(cJSON *configs);
struct operator_console_t *operator_console(cJSON *configs);

int main() {
    char *buffer = server_config();
    cJSON *config = cJSON_Parse(buffer);
    if (!config) {
        const char *error_ptr = cJSON_GetErrorPtr();
        
        if (error_ptr != NULL) {
            printf("Failed to parse configuration file\n %s \n", error_ptr);
        } else {
            printf("Failed to parse configuratation file\n");
        }
        free(buffer);
        exit(EXIT_FAILURE);
    } 
    free(buffer);
    cJSON *logPath = cJSON_GetObjectItem(config, "LogFile");
    set_logfile_path(logPath->valuestring);
    log_message(LOG_INFO, "Server Started");

    struct database_configs_t *database = database_config(config);
    if (database == NULL) log_message(LOG_WARN, "Failed To Parse Database Configurations");

    struct communication_channels_t *channels = channels_config(config);
    if (channels == NULL) log_message(LOG_WARN, "Failed To Parse Communications Configurations");
    
    struct operator_console_t *operator = operator_console(config); 
    if  (operator == NULL) {
        log_message(LOG_ERROR, "Failed To Parse Operator-Console Configurations");
        cJSON_Delete(config);
        exit(EXIT_FAILURE);
    }
    log_message(LOG_INFO, "Operator Console Port: %d", operator->port);


    
    cJSON_Delete(config);
    // open logs
    //if (db_conn(database->database_server, database->username, database->password, database->database) == -1) {
    //    log_message(LOG_ERROR, "Failed to connect to database");
    //    exit(EXIT_FAILURE);
    //}

    struct DBConf g_dbconf;

    strncpy(g_dbconf.host, database->database_server, BUFFER_SIZE-1);
    g_dbconf.host[BUFFER_SIZE-1] = '\0'; // ensure null-termination

    strncpy(g_dbconf.user, database->username, BUFFER_SIZE-1);
    g_dbconf.user[BUFFER_SIZE-1] = '\0';

    strncpy(g_dbconf.pass, database->password, BUFFER_SIZE-1);
    g_dbconf.pass[BUFFER_SIZE-1] = '\0';

    strncpy(g_dbconf.db, database->database, BUFFER_SIZE-1);
    g_dbconf.db[BUFFER_SIZE-1] = '\0';
    g_dbconf.port = 3306;


    if (init_db_pool(g_dbconf) == -1) {
        log_message(LOG_ERROR, "Failed to connect to database");
        exit(EXIT_FAILURE);
    }

    // set cert and key
    if (access(channels->ssl_cert, F_OK) != 0 || access(channels->ssl_key, F_OK) != 0) {
        log_message(LOG_INFO, "Creating New SSL Certification and Key");
        generate_key_and_cert(channels->ssl_cert, channels->ssl_key);
        
    }


    do {
        pthread_t operator_thread = 0, tcp_thread = 0, tcp_ssl_thread = 0; // Initialize to 0
        int operator_thread_created = 0, tcp_thread_created = 0, tcp_ssl_thread_created = 0;
        

        if (operator->port > 0)  {
            struct main_threads_args_t *operator_args = malloc(sizeof(*operator_args));
            if (!operator_args) {
                log_message(LOG_WARN, "Failed to allocate operator arg memory");
                continue;
            }

            strncpy(operator_args->cert, channels->ssl_cert, BUFFER_SIZE - 1);
            strncpy(operator_args->key, channels->ssl_key, BUFFER_SIZE - 1);
            operator_args->db_conf = g_dbconf;
            operator_args->port = operator->port;
            if (pthread_create(&operator_thread, NULL, operator_listener, (void*)operator_args) == 0) {
                operator_thread_created = 1; // Mark as created
                log_message(LOG_INFO, "Operator Console Listener Started Successfully");
            } else {
                //log_message(LOG_WARN, "Failed to start operator thread");
                log_message(LOG_ERROR, "Failed To Create Operator Thread (Error: %s)", strerror(errno));
                free(operator_args);
                operator_args = NULL;
            }
        }

        //if (channels->tcp) {
        //    struct main_threads_args_t *tcp_args = malloc(sizeof(*tcp_args));
        //    if (!tcp_args) {
        //        log_message(LOG_WARN, "Failed to allocate tcp arg memory");
        //        continue;
        //    }
        //    strncpy(tcp_args->cert, channels->ssl_cert, BUFFER_SIZE - 1);
        //    strncpy(tcp_args->key, channels->ssl_key, BUFFER_SIZE - 1);
        //    tcp_args->db_conf = g_dbconf;
        //    tcp_args->port = channels->tcp_port;
        //    log_message(LOG_INFO, "TCP Listener Thread Starting : %d", channels->tcp_port);
        //    if (pthread_create(&tcp_thread, NULL, tcp_listener, (void*)tcp_args) == 0) {
        //        tcp_thread_created = 1;
        //    } else {
        //        log_message(LOG_ERROR, "Failed to start TCP listener thread");
        //        sleep(30);
        //        free(tcp_args);
        //        tcp_args = NULL;
        //        continue;
        //    }
        //}
    
        if (channels->tcp) {

            struct main_threads_args_t *ssl_args = malloc(sizeof(*ssl_args));
            if (!ssl_args) {
                log_message(LOG_ERROR, "Failed to allocate args for SSL thread");
                continue;
            }   

            strncpy(ssl_args->cert, channels->ssl_cert, BUFFER_SIZE - 1);
            strncpy(ssl_args->key, channels->ssl_key, BUFFER_SIZE - 1);
            ssl_args->db_conf = g_dbconf;
            ssl_args->port = channels->tcp_port;

            log_message(LOG_INFO, "TCP (SSL) Listener Thread Starting : %d", channels->tcp_port);
           
            if (pthread_create(&tcp_ssl_thread, NULL, tcp_ssl_listener, (void*)ssl_args) == 0) {
                tcp_ssl_thread_created = 1;
            } else {
                log_message(LOG_ERROR, "Failed To Start SSL TCP Listener Thread [Implants]");
                free(ssl_args); // Cleanup on failure
                ssl_args = NULL;
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
    
    cleanup_db_pool();
    return 0;
}


char *server_config() {
    char *buffer;
    buffer = (char*)malloc(BUFFER_SIZE);
    size_t bytesRead;


    //char filename[BUFFER_SIZE] = "~/.tibane-server-conf.json";
    char filename[BUFFER_SIZE];
    snprintf(filename, BUFFER_SIZE, "%s/.tibane-server-conf.json", getenv("HOME"));; 

    if (access(filename, F_OK) != 0) {
        //log_message(LOG_ERROR, "Create configuration file and name is ~/.tibane-server-conf.json");
        printf("[-] Configuration file no found\n[*] Create configuration file and name is ~/.tibane-server-conf.json\n");
        exit(EXIT_FAILURE);
    }
    int conf = open(filename, O_RDONLY);
    if (conf == -1) {
        //write(1, "Failed to Configuration file\n", 20);
        perror("[-] Failed to open configuration file\n");
        //log_message(LOG_ERROR, "Failed to open configuration file");
        // logfile
        
        exit(EXIT_FAILURE);
    }
    if ((bytesRead = read(conf, buffer, BUFFER_SIZE - 1)) <= 0) {
        //log_message(LOG_ERROR, "Failed to read data from configuration file");
        perror("[-] Failed to read from configuration file");
        exit(EXIT_FAILURE);
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

    // Default values 
    channels->tcp = channels->https = 0;
    channels->tcp_port = channels->https_port = 0;
    memset(channels->ssl_cert, 0, sizeof(channels->ssl_cert));
    memset(channels->ssl_key, 0, sizeof(channels->ssl_key));

    cJSON *item;

    if ((item = cJSON_GetObjectItem(comm, "tcp")) && cJSON_IsBool(item))
        channels->tcp = cJSON_IsTrue(item);

    if ((item = cJSON_GetObjectItem(comm, "https")) && cJSON_IsBool(item))
        channels->https = cJSON_IsTrue(item);

    if ((item = cJSON_GetObjectItem(comm, "tcp_port")) && cJSON_IsNumber(item))
        channels->tcp_port = item->valueint;

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
