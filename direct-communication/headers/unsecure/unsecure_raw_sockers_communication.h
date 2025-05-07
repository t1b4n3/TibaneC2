#ifndef Unsecure_communication_header
#define Unsecure_communication_header

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <sys/select.h>
#include <stdint.h>

// for logging
#include "log.h"
// agent_management
#include "shellAgentManagement.h"


//#define PORT 50505

struct sockaddr_in clientAddr;
socklen_t client_len = sizeof(clientAddr);
int serverSock, clientSock; 

int network(int PORT) {
    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_family = AF_INET;

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) {
        perror("binding failed");
        close(serverSock);
        return -1;
    }

    if (listen(serverSock, 20) == -1) {
        perror("Listen Failed");
        close(serverSock);
        return -1;
    }

    return 0;
}

int accept_connections() {
    // set timer so that if there are no connections after 10 seconds stop accepting connections {

    int duration = 10; // default duration is 10 seconds

    start:
    do {
        memset((void*)&clientAddr, 0, client_len);
        memset((void*)&clientSock, 0, sizeof(clientSock));
        printf("[-] Waiting for connections\n");
        // add log "Waiting for connections"


            // wait 
        fd_set read_fds;
        struct timeval timeout;
        FD_ZERO(&read_fds);
        FD_SET(serverSock, &read_fds);

        timeout.tv_sec = duration;
        timeout.tv_usec = 0;

        // Wait for a connection or timeout
        int activity = select(serverSock + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("select error");
            sleep(1);
            goto start;
        }

        if (activity == 0) {
            // Timeout occurred, no connection
            printf("[-] No connection within %d seconds. Continuing...\n", duration);
            sleep(1);
            break;
        } else {
            // Connection is available
            if (FD_ISSET(serverSock, &read_fds)) {
                clientSock = accept(serverSock, (struct sockaddr*)&clientAddr, &client_len);
                if (clientSock == -1 ) {
                    perror("Accept Failed");
                    return -1;
                }
                
                connections_counter++;
                printf("[+] Connection from %s : %d | shell %d \n", inet_ntoa(clientAddr.sin_addr),ntohs(clientAddr.sin_port), connections_counter);
                log_connections(inet_ntoa(clientAddr.sin_addr));
                addAgent(clientSock, clientAddr);
                sleep(1);
                continue;

            }
        }
        } while (true);
        
    return 0;
}



#endif