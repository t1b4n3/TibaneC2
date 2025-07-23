#ifndef TCP_SSL_BEACON
#define TCP_SSL_BEACON

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include <openssl/sha.h>

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

#define BUFFER_SIZE 4096
#define MAX_RESPONSE 0x20000


void beacon(cJSON *json, int sock);

void upload(char *file);

void download(char *file);



#endif