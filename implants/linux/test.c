#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 4096
#define MAX_RESPONSE 20000


int main() {
    char buffer[BUFFER_SIZE];
    char result[MAX_RESPONSE];
    while (1) {
    printf("CMD: ");
    char cmd[BUFFER_SIZE];
    fgets(cmd, sizeof(cmd), stdin);

    cmd[strcspn(cmd, "\n")] = 0;
    char buffer[BUFFER_SIZE];
    FILE *exec;
    char result[MAX_RESPONSE];
    memset(buffer, 0, sizeof(buffer));
    memset(result, 0, MAX_RESPONSE);
    char command_with_redirect[BUFFER_SIZE + 10];
    snprintf(command_with_redirect, sizeof(command_with_redirect), "%s 2>&1", cmd);

    exec = popen(command_with_redirect, "r");
    if (!exec) {
        strcpy(result, "Failed to execute command.\n");

        goto OUTPUT;
    }

    while (fgets(buffer, sizeof(buffer), exec) != NULL) {
        strcat(result, buffer);
    }

    OUTPUT:
    printf("OUTPUT : %s \n", result);
    }

}