#include "common.h"
#include "logs.h"


// Define (allocate storage for) global vars
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

char base62[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

struct DBConf g_dbconf; 

void send_json(SSL* ssl, const char* json_str) {
    size_t json_len = strlen(json_str);

    if (json_len > UINT32_MAX) {
        log_message(LOG_ERROR, "JSON data too long for 4-byte prefix");
        return; 
    }

    uint32_t length = (uint32_t)json_len;
    uint32_t netlen = htonl(length);

    
    size_t total = 0;
    while (total < sizeof(netlen)) {
        int n = SSL_write(ssl, ((char*)&netlen) + total, sizeof(netlen) - total);
        if (n <= 0) {
            log_message(LOG_ERROR, "Failed to send JSON length prefix");
            return;
        }
        total += n;
    }

    total  = 0;
    while (total < length) {
        int n = SSL_write(ssl, json_str + total, length - total);
        if (n <= 0) {
            log_message(LOG_ERROR, "Failed to send JSON data payload");
            break;
        }
        total += n;
    }
}

char* recv_json(SSL *ssl) {
    uint32_t netlen;
    size_t total = 0;

    while (total < sizeof(netlen)) {
        int n = SSL_read(ssl,
                         ((char*)&netlen) + total,
                         sizeof(netlen) - total);
        if (n <= 0) return NULL;
        total += n;
    }


    uint32_t length = ntohl(netlen);

    char* buffer = (char*)malloc(length + 1);
    if (!buffer) return NULL;

    total = 0;
    while (total < length) {
        int n = SSL_read(ssl,
                         buffer + total,
                         length - total);
        if (n <= 0) {
            free(buffer); 
            return NULL;
        }
        total += n;
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


char* resolve_home_path(char* original_path) {
    if (original_path[0] != '~') {
        // Path does not start with ~, no expansion needed
        return strdup(original_path); 
    }

    const char* home_dir = getenv("HOME");
    if (!home_dir) {
        // Fallback if $HOME is not set, maybe use getpwuid, but for now, fail.
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        return NULL;
    }

    // Allocate memory for the new expanded path: home_dir + rest of path (+ null terminator)
    size_t new_len = strlen(home_dir) + strlen(original_path);
    char* expanded_path = (char*)malloc(new_len); 
    if (!expanded_path) {
        perror("malloc failed");
        return NULL;
    }

    // Concatenate the home directory path with the rest of the path (starting after the '~')
    strcpy(expanded_path, home_dir);
    strcat(expanded_path, original_path + 1); // Skip the leading '~'

    return expanded_path;
}

// ... inside your client initialization code ...