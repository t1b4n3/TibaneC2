#include "logs.h"


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

void lopen() {
    logg = fopen("main.log", "a");
}

void llog(char *info) {
    char buffer[0x400];
    time_t t;
    time(&t);

    char ttime[0x20];
    strncpy(ttime, ctime(&t), sizeof(ttime) - 1);
    ttime[strcspn(ttime, "\n")] = 0;

    snprintf(buffer, sizeof(buffer), "[%s] - %s", ttime, info);
    fprintf(logg, "%s", buffer);

}

void log_beacon(char *agent_id) {
    char buffer[0x400];
    time_t t;
    time(&t);

    char ttime[0x20];
    strncpy(ttime, ctime(&t), sizeof(ttime) - 1);
    ttime[strcspn(ttime, "\n")] = 0;

    snprintf(buffer, sizeof(buffer), "[%s] - Beacon FROM : %s", ttime, agent_id);
    fprintf(logg, "%s", buffer);
}

void log_new_agent(char *agent_id, char *os, char *hostname, char *mac, char* arch) {
    char buffer[0x400];
    time_t t;
    time(&t);

    char ttime[0x20];
    strncpy(ttime, ctime(&t), sizeof(ttime) - 1);
    ttime[strcspn(ttime, "\n")] = 0;

    snprintf(buffer, sizeof(buffer), "[%s] - New Agent | Agent id: %s, OS: %s, Hostname: %s, MAC: %s, Arch: %s", ttime, agent_id, os, hostname, mac, arch);
    fprintf(logg, "%s", buffer);
}

void lclose() {
    fclose(logg);
}

void operator_connections(char *ip) {
    char buffer[0x400];
    time_t t;
    time(&t);

    char ttime[0x20];
    strncpy(ttime, ctime(&t), sizeof(ttime) -1);
    ttime[strcspn(ttime, "\n")] = 0;

    snprintf(buffer, sizeof(buffer), "[%s] - CONNECTION FROM: %s", ttime, ip);
    fprintf(logg, "%s", buffer);
}