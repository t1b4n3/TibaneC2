#ifndef Logging_Header_File
#define Logging_Header_File

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define buffer_len 256
#define max_response 20000


char log_buffer[max_response+buffer_len];

void log_commands(char* cmd) {
    FILE *logs = fopen("main.log", "a+");

    time_t t;
    time(&t);
    char ttime[buffer_len]; 
    strncpy(ttime, ctime(&t), sizeof(ttime));
    ttime[strcspn(ttime, "\n")] = 0;


    memset(log_buffer, 0, sizeof(log_buffer));
    sprintf(log_buffer, "%s - %s \n", ttime, cmd);

    fprintf(logs, "%s", log_buffer);
 
    
    fclose(logs);

}

void log_communication_w_agents(char* cmd,char* ip, char* response) {
    FILE *logs = fopen("main.log", "a+");
    time_t t;
    time(&t);
    char ttime[buffer_len]; 
    strncpy(ttime, ctime(&t), sizeof(ttime));
    ttime[strcspn(ttime, "\n")] = 0;

    memset(log_buffer, 0, sizeof(log_buffer));
    sprintf(log_buffer, "%s - [%s] - %s {%s} \n", ttime, ip, cmd, response);
    fprintf(logs, "%s", log_buffer);
    fclose(logs);
}
void log_connections(char *ip) {
    FILE *logs = fopen("main.log", "a+");
    time_t t;
    time(&t);
    char ttime[buffer_len]; 
 
    strncpy(ttime, ctime(&t), sizeof(ttime));
    ttime[strcspn(ttime, "\n")] = 0;

    memset(log_buffer, 0, sizeof(log_buffer));
    sprintf(log_buffer, "%s - Connection from %s \n", ttime, ip);
    fprintf(logs, "%s", log_buffer);
    fclose(logs);
}


#endif