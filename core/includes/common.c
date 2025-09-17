#include "common.h"
#include "logs.h"
#include <cjson/cJSON.h>

// Define (allocate storage for) global vars
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

char base62[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

struct DBConf g_dbconf; 

void send_json(SSL* ssl, const char* json_str) {
    //uint32_t length = htonl(strlen(json_str)); 
    //SSL_write(ssl, &length, 4);                
    //SSL_write(ssl, json_str, strlen(json_str)); 
     if (!ssl || !json_str) {
        log_message(LOG_ERROR, "Invalid parameters");
        return;
        }

    uint32_t length = htonl(strlen(json_str));
    
    // Send length
    int sent = SSL_write(ssl, &length, sizeof(length));
    //if (sent != sizeof(length)) {
    //    log_message(LOG_ERROR, "Failed to send length");
    //    return;
    //}

    // Send JSON data
    size_t total_sent = 0;
        size_t json_len = strlen(json_str);
     while (total_sent < json_len) {
        sent = SSL_write(ssl, json_str + total_sent, json_len - total_sent);
        if (sent <= 0) {
            log_message(LOG_ERROR, "Failed to send JSON data");
            break;
        }
        total_sent += sent;
    }
}

char* recv_json(SSL *ssl) {
    uint32_t length;
    int received = SSL_read(ssl, &length, 4);
    if (received != 4) {
        log_message(LOG_ERROR, "Failed to receieve size of incoming json"); 
        return NULL;
    }

    length = ntohl(length);

    char *buffer = (char*)malloc(length + 1); 
    if (!buffer) return NULL;

    int total = 0;
    while (total < (int)length) {
        int bytes = SSL_read(ssl, buffer + total, length - total);
        if (bytes <= 0) {
            free(buffer);
            return NULL;
        }
        total += bytes;
    }   
    buffer[length] = '\0';
    return buffer;
}


bool check_if_dir_exists(char *dir){
    if (access(dir, F_OK) != 0) {
        if (ENOENT == errno) {
            log_message(LOG_ERROR, "Directory : %s does not exist", dir);
            return false;
         }
         if (ENOTDIR == errno) {
            log_message(LOG_ERROR, "%s is not a directory", dir);
            return false;
         }
    }
    log_message(LOG_INFO, "Directory %s Already exits", dir);
    return true;
}

bool create_dir(char *dir) {
    mode_t permissions = S_IRWXU | S_IRWXG | S_IRWXO; // Read, write, execute for owner, group, others (0777)

    if (mkdir(dir, permissions) == 0) {
        log_message(LOG_INFO, "irectory '%s' created successfully.\n", dir);
    } else {
        //sperror("Failed to create directory");
        log_message(LOG_ERROR, "Failed to create directory : %s", dir);
        // You can check errno for specific errors, e.g., EEXIST if directory already exists
        if (errno == EEXIST) {
            log_message(LOG_WARN, "Directory '%s' already exists.", dir);
        }
        return false;
    }
    return true;
}

cJSON* list_files(const char *base_path) {

    struct dirent *dp;
    DIR *dir = opendir(base_path);

    if (!dir) {
        log_message(LOG_ERROR, "Failed to open directory : %s", base_path);
        return NULL; // could not open directory
    }

    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        log_message(LOG_ERROR, "Failed to create Array object");
        closedir(dir);
        return NULL;
    }

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;

        char path[BUFFER_SIZE * 2];
        snprintf(path, sizeof(path), "%s/%s", base_path, dp->d_name);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            // It's a directory -> recurse
            cJSON *dir_obj = cJSON_CreateObject();
            cJSON_AddItemToObject(dir_obj, dp->d_name, list_files(path));
            cJSON_AddItemToArray(arr, dir_obj);
        } else {
            // It's a file -> add name
            cJSON_AddItemToArray(arr, cJSON_CreateString(dp->d_name));
        }
    }
    log_message(LOG_INFO, "Returning List of files from %s", base_path);
    closedir(dir);
    return arr;
}


char* search_file(char *base_path, char *filename) {
    struct dirent *dp;
    DIR *dir = opendir(base_path);

    if (!dir) {
        log_message(LOG_ERROR, "Directory : %s Does not exist", base_path);
        return NULL;
    }

    while ((dp = readdir(dir)) != NULL) {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
            
            // Build full path
            char path[BUFFER_SIZE * 2];
            snprintf(path, sizeof(path), "%s/%s", base_path, dp->d_name);

            // If file matches, return path
            if (strcmp(dp->d_name, filename) == 0) {
                closedir(dir);
                return strdup(path);
            }

            // Check if it's a directory using stat()
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                char *result = search_file(path, filename);
                if (result) {
                    closedir(dir);
                    return result;
                }
            }
        }
    }
    log_message(LOG_ERROR, "File : %s Does not exist", filename);
    closedir(dir);
    return NULL;
}