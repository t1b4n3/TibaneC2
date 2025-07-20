#ifndef BEACON_TCP_H
#define BEACON_TCP_H

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
#include "db.h"
#include "logs.h"

#define BUFFER_SIZE 4096
#define MAX_RESPONSE 0x20000


struct thread_args {
    int sock;
    char ip[256];
};

// prototypes

void beacon(cJSON *json, int sock);

void upload(char *file);

void download(char *file);

///// 





















#endif