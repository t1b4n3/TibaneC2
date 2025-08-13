#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x1000 // maximum chunk size

using namespace std;

int sock;

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

int conn(const char *ip, int port) {
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        return 1;
    }

    if (conn(argv[1], atoi(argv[2])) != 0) {
        return 1;
    }

    char cmd[BUFFER_SIZE];
    char filepath[BUFFER_SIZE];

    while (1) {
        memset(cmd, 0, sizeof(cmd));
        memset(filepath, 0, sizeof(filepath));

        printf("\n> ");
        fgets(cmd, BUFFER_SIZE, stdin);

        // Send command to server
        send(sock, cmd, strlen(cmd), 0);

        if (strncmp(cmd, "upload", 6) == 0) {
            if (sscanf(cmd, "upload %s", filepath) == 1) {
                upload(filepath);
            } else {
                printf("Usage: upload <file>\n");
            }
        } else if (strncmp(cmd, "download", 8) == 0) {
            if (sscanf(cmd, "download %s", filepath) == 1) {
                download(filepath);
            } else {
                printf("Usage: download <file>\n");
            }
        } else if (strncmp(cmd, "exit", 4) == 0) {
            break;
        } else {
            // Receive server response
            char buffer[MAX_SIZE];
            ssize_t n = recv(sock, buffer, sizeof(buffer)-1, 0);
            if (n > 0) {
                buffer[n] = '\0';
                printf("%s", buffer);
            }
        }
    }

    close(sock);
    return 0;
}
