#include "common.h"


#include "logs.h"

// Define (allocate storage for) global vars
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

char base62[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

struct DBConf g_dbconf; 



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