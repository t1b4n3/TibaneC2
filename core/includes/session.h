#ifndef session_mode
#define session_mode

#define BUFFER_SIZE 4096
#define MAX_RESPONSE 0x20000

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// is a proxy 
// forwards from agent - c2 - console
void session(int Agentsock, int Operatorsock) {
    // from operator
    char command[BUFFER_SIZE];
    // from agent
    char response[MAX_RESPONSE];
    while (1) {
        memset(command, 0, sizeof(command));
        memset(response, 0, sizeof(response));


    }
    

}


char* console(int sock) {

}

char* implant(int sock) {

}






#endif