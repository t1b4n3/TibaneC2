#ifndef OPERATOR_H
#define OPERATOR_H

#include <pthread.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

#include "db.h"

void *operator_handler(void *new_sock);

void *Operator_conn(void* port);

#endif