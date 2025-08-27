#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdint.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>

#define MAX_SIZE 0x1000
#define BUF_SIZE  0x256
#define PORT 8080

int upload(int sock) {
    char *path = "flag.txt";
    if (access(path, F_OK) != 0) {
        return -1;
    }

    char *contents = (char*)malloc(MAX_SIZE);
    int file = open(path, O_RDONLY);
    if (file == -1) {
        stderr;
        printf("Failed to open file\n");
        return  -1;
    }

    size_t bytesRead;
    while ((bytesRead = read(file, contents, MAX_SIZE)) > 0) {
        send(sock, contents, bytesRead, 0);
        printf("%s\n", contents);
    }
    free(contents);
    return 0;
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUF_SIZE];

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Connect
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server.\n");

    if (upload(sock) == -1) {
        printf("Failed to send\n");
    }
    return 0;
}