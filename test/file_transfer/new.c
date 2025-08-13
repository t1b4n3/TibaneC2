#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PORT 9999
#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x1000

int sock;

int download(const char* path) {

    FILE *file = fopen(path, "wb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    char buffer[MAX_SIZE];
    ssize_t bytesReceived;  
    while ((bytesReceived = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        if (fwrite(buffer, 1, bytesReceived, file) < bytesReceived) {
            perror("Error writing to file");
            break;
        }
    }
    fclose(file);
    return 0;
}

int upload(const char* path) {
    if (access(path, F_OK) != 0) {
        fprintf(stderr, "File does not exist: %s\n", path);
        return -1;
    }


    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    char buffer[MAX_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(sock, buffer, bytesRead, 0) < 0) {
            perror("Error sending file data");
            break;
        }
    }
    return 0;
}

void list_files(int sockfd) {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    char buffer[BUFFER_SIZE];

    if (d) {
        while ((dir = readdir(d)) != NULL) {
            snprintf(buffer, sizeof(buffer), "%s\n", dir->d_name);
            send(sockfd, buffer, strlen(buffer), 0);
        }
        closedir(d);
    }
    send(sockfd, "__END__\n", strlen("__END__\n"), 0);
}

void *client_handler(void *arg) {
    char cmd[BUFFER_SIZE];
    char path[BUFFER_SIZE];

    while (1) {
        memset(cmd, 0, sizeof(cmd));
        memset(path, 0, sizeof(path));

        ssize_t n = recv(sock, cmd, sizeof(cmd)-1, 0);
        if (n <= 0) break;

        cmd[n] = '\0';

        int tokens = sscanf(cmd, "%s %s", cmd, path);

        if (tokens >= 1) {
            if (strcmp(cmd, "ls") == 0) {
                list_files(sock);
            } else if (strcmp(cmd, "upload") == 0 && tokens == 2) {
                download(path);
            } else if (strcmp(cmd, "download") == 0 && tokens == 2) {
                upload(path);
            } else if (strcmp(cmd, "exit") == 0) {
                close(sock);
                return NULL;
            } else {
                char err[] = "Unknown command\n";
                send(sock, err, strlen(err), 0);
            }
        }
    }
    return NULL;
}

int main() {
    struct sockaddr_in clientAddr;
    socklen_t client_len = sizeof(clientAddr);
    int serverSock;

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
        perror("Binding failed");
        close(serverSock);
        return -1;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        perror("Listen Failed");
        close(serverSock);
        return -1;
    }

    printf("[*] Listening on port %d...\n", PORT);

    while (1) {
        if ((sock = accept(serverSock, (struct sockaddr*)&clientAddr, &client_len)) < 0) {
            perror("Accept failed");
            continue;
        }

        printf("[+] Connection from %s:%d\n",
               inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

        pthread_t thread;
        if (pthread_create(&thread, NULL, client_handler, NULL) < 0) {
            perror("Could not create thread");
            close(sock);
            continue;
        }
        pthread_detach(thread);
    }

    close(serverSock);
    return 0;
}
