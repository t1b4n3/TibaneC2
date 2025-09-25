#ifndef LISTENER
#define LISTENER

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>


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

#include "logs.h"
#include "implant_handler.h"
#include "./cJSON/cJSON.h"

#define MAX_RESPONSE 0x20000



//void tcp_register_agent(cJSON *json, char *ip, int sock); 

// TCP (unencrypted)

void* tcp_listener(void* port);

// TCP over SSL
 
void* tcp_ssl_listener(void *port);

// for Operator console

void *operator_listener(void* args);

// ssl keys and certifications  

void generate_key_and_cert();

void init();


#endif
