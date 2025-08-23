#ifndef COMMON_H
#define COMMON_H

#include <pthread.h>
#include <openssl/ssl.h>
#include <mysql/mysql.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFFER_SIZE 4096
#define MAX_RESPONSE 0x20000
#define MAX_INFO 999999999




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


struct DBConf {
    char host[BUFFER_SIZE];
    char user[BUFFER_SIZE];
    char pass[BUFFER_SIZE];
    char db[BUFFER_SIZE];
    int port;
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
    bool tcp_ssl;
    // ports
    int tcp_port;
    int https_port;
    int tcp_ssl_port;
    // ssl certificates
    char ssl_cert[0x100];
    char ssl_key[0x100];
};

struct operator_handler_args_t {
    SSL *ssl;
};


struct main_threads_args_t {
    char cert[BUFFER_SIZE];
    char key[BUFFER_SIZE];
    int port;
};

// 

struct implant_handler_t {
    bool encrypted;
    SSL_CTX *ctx;
    int client_fd;
    char ip[INET_ADDRSTRLEN];
};

// ---- Global Mutexes ----
extern pthread_mutex_t db_mutex;
extern pthread_mutex_t log_mutex;

// ---- Global Variables ----
extern int server_running;
extern char base62[];
extern MYSQL *con;

extern DBConfig g_dbconf;


#endif
