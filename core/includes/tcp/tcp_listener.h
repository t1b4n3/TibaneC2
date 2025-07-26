#ifndef TCP_LISTENER
#define TCP_LISTENER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <cjson/cJSON.h>

#include "../agent.h"
#include "beacon_tcp.h"

#define BUFFER_SIZE 4096
#define MAX_RESPONSE 0x20000



struct tcp_thread_args {
    int sock;
    char ip[256];
};

void tcp_register_agent(cJSON *json, char *ip, int sock); 

void* tcp_agent_conn(void* port);

void* tcp_agent_handler(void *args);

#endif
