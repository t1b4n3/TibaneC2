#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <cjson/cJSON.h>

#include "./includes/db.h"
#include "./includes/operator.h"
#include "./includes/agent.h"

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

