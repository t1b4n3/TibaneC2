#ifndef LOGS_H
#define LOGS_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

extern FILE *logg;

void lopen();

void llog(char *info);


void log_beacon(char *agent_id);


void log_new_agent(char *agent_id, char *os, char *hostname, char *mac, char* arch);

/////////////////////
// operator
void operator_connections(char *ip);


void lclose();



#endif