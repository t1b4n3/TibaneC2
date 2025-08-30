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
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>

#include "common.h"


void GenerateID(const char *input, char output[9]);

char *register_implant(MYSQL* con, cJSON *json, char *ip);

char *beacon_implant(MYSQL* con, cJSON *json);

void *implant_handler(void *arg);


// only works for ssl
int implant_upload(SSL *ssl);
int implant_download(SSL *ssl);


#endif