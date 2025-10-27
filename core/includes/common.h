#ifndef COMMON_H
#define COMMON_H

#include <pthread.h>
#include <openssl/ssl.h>
#include <mysql/mysql.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <dirent.h>
#include "logs.h"

//#include "./cJSON/cJSON.h"
#include <cjson/cJSON.h>

#define BUFFER_SIZE 0x1000
#define MAX_RESPONSE 0x20000
#define MAX_INFO 0x999999
#define FILE_CHUNK 0x256

// ---- Structs ----
struct db_agents {
    char implant_id[65];
    char os[50];
    char ip[50];
    char hostname[255];
    char arch[50];
};

struct db_tasks {
    char implant_id[65];
    char command[1024];
    char response[BUFFER_SIZE];
};

struct db_logs {
    char implant_id[65];
    char log_type[16];
    char message[BUFFER_SIZE];
};


struct database_configs_t {
    char database_server[BUFFER_SIZE];
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];
    char database[BUFFER_SIZE];
};

struct operator_listener_t {
    char cert[BUFFER_SIZE];
    char key[BUFFER_SIZE];
    int port;
};



struct operator_console_t {
    int x;
    int port;
};

struct communication_channels_t {
    bool tcp;
    bool https;
    // ports
    int tcp_port;
    int https_port;
    // ssl certificates
    char ssl_cert[0x100];
    char ssl_key[0x100];
};

struct DBConf {
    char host[BUFFER_SIZE];
    char user[BUFFER_SIZE];
    char pass[BUFFER_SIZE];
    char db[BUFFER_SIZE];
    int port;
};

struct operator_handler_args_t {
    SSL *ssl;
    struct DBConf db_conf;
};


struct main_threads_args_t {
    char cert[BUFFER_SIZE];
    char key[BUFFER_SIZE];
    int port;
    struct DBConf db_conf;
};

// 

struct implant_handler_t {
    bool encrypted;
    SSL_CTX *ctx;
    int client_fd;
    char ip[INET_ADDRSTRLEN];
    struct DBConf db_conf;
};


// ---- Global Mutexes ----
extern pthread_mutex_t db_mutex;
extern pthread_mutex_t log_mutex;

// ---- Global Variables ----

extern char base62[];


extern  struct DBConf g_dbconf;



void send_json(SSL *ssl, const char* json_str);

char* recv_json(SSL *ssl);

bool check_if_dir_exists(char *dir);

bool create_dir(char *dir);

char* search_file(char *base_path, char *filename);

cJSON* list_files(const char *base_path);

#endif
