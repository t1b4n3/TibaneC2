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

    //struct stat s;
    //int err = stat(dir, &s);
    //if(-1 == err) {
    //    if(ENOENT == errno) {
    //        return false;
    //    } else {
    //        //perror("stat");
    //        log_message(LOG_ERROR, "ERROR checking dir");
    //        return false;
    //    }
    //} else {  
    //    if(S_ISDIR(s.st_mode)) {
    //        return true;
    //    } else {
    //        return false;
    //    }
    //}
