#ifndef TCP_SSL_LISTENER
#define TCP_SSL_LISTENER


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

#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include "agent.h"

void init();

void* tcp_ssl_listener(void *port);

void generate_key_and_cert();

void ssl_register_agent(cJSON *json, char* ip, SSL *ssl);

#endif