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
#define BUF_SIZE 0x256
#define PORT 8080


int download(int sock) {
    char *path = "flag.txt";
    char *contents = (char*)malloc(MAX_SIZE);
    int fd = open(path,  O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd == -1) {
        stderr;
        return -1;
    }
    size_t bytesRead;
    while ((bytesRead = recv(sock, contents, MAX_SIZE, 0)) > 0) {
        write(fd, contents, bytesRead);
        printf("%s\n", contents);
    }
    free(contents);
    return 0;
}


int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUF_SIZE];
    socklen_t addr_len = sizeof(client_addr);

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Setup server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
    server_addr.sin_port = htons(PORT);

    // Bind
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Client connected!\n");

    if (download(client_fd) == -1) {
        printf("Failed to download \n");
    }   


    return 0;
}