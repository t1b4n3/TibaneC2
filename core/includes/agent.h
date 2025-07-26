#ifndef AGENT_H
#define AGENT_H



#include <stdio.h>              
#include <string.h>             
#include <openssl/sha.h>        

void get_agent_id(const char *input, char output[9]);

#endif