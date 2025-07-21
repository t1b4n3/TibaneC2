#include "session.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>


void session() {
    // from operator
    char command[BUFFER_SIZE];
    // from agent
    char response[MAX_SIZE];
    while (1) {
        memset(command, 0, sizeof(command));
        memset(response, 0, sizeof(response));

        printf("#shell~$ ");
        fgets(command, sizeof(command), stdin);

        if (strlen(command) == 0) {
            printf("Input cannot be empty.\n");
            continue;
        }

        command[strcspn(command, "\n")] = 0;  

        send(sock, command, strlen(command), 0);

        if((strncmp("q", command, 1) == 0) || (strncmp("quit", command, 4) == 0) || (strncmp("exit", command, 4) == 0)) {
            break;
        } else {
            int bytes_received = recv(sock, response, sizeof(response) -1, 0);
            if (bytes_received <= 0) {
                perror("recv failed ");
                return;
            }
        response[bytes_received] = '\0';
        }

        printf("%s\n", response);
        }
}