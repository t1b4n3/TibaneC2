#ifndef REGISTER_H
#define REGISTER_H

#include <cjson/cJSON.h>

#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>

#include <unistd.h>
#include <netinet/in.h>

#include "db.h"
#include "logs.h"


// generate agent id (sha 256)
void get_agent_id(const char *input, char output[65]);

// register agent to database
void register_agent(cJSON *json, char *ip, int sock);

#endif