#ifndef OPERATOR_H
#define OPERATOR_H

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

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


//#include "./cJSON/cJSON.h"
#include <cjson/cJSON.h>
#include "db.h"
#include "common.h"

//upload file to operator | interact with download function from cli
int operator_file_upload(SSL *ssl);
// download file to download | cli-console must send (upload) 
int operator_file_download(SSL *ssl);

void *operator_handler(void *Args);

char *interact_with_implant(MYSQL *con, cJSON *rinfo);

char *verify_id(MYSQL *con, char *id);

int autheticate(MYSQL *con, SSL *ssl);
char *generate_salt();

#endif