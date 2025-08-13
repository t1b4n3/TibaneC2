#include <cstdio>
#include <cstdlib>
#include <fcntl.h>         
#include <unistd.h>        
#include <sys/stat.h> 
#include <cstring>
#include <string>
#include <unistd.h>         
#include <arpa/inet.h>      
#include <sys/socket.h>     
#include <netinet/in.h>
#include <signal.h>

#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x1000 // maximum file size 

using namespace std;

int sock;

int upload(const char* path) {
    if (access(path, F_OK) != 0) {
        return -1;
    }

    char *contents = (char*)malloc(MAX_SIZE);
    int file = open(path, O_RDONLY);
    if (file == -1) {
        printf("Failed to open file\n");
        return  -1;
    }

    size_t bytesRead;
    while ((bytesRead = read(file, contents, MAX_SIZE)) > 0) {
        send(sock, contents, bytesRead, 0);
    }
    free(contents);
    return 0;
}

int download(const char* path) {
    char *contents = (char*)malloc(MAX_SIZE);
    int fd = open(path,  O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd == -1) {
        stderr;
        return -1;
    }
    size_t bytesRead;
    while ((bytesRead = recv(sock, contents, MAX_SIZE, 0)) > 0) {
        write(fd, contents, bytesRead);
    }

    free(contents);
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

    // Convert IPv4 addresses from text to binary
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return -1;
    }

    return 0;
}



int main(int argc, char **argv) {

    conn(argv[1], atoi(argv[2]));

    char cmd[BUFFER_SIZE];
    char filepath[BUFFER_SIZE];
    while (1) {
        memset(cmd, 0, sizeof(cmd));
        memset(filepath, 0, sizeof(filepath));
        printf("\n> ");
        fgets(cmd, BUFFER_SIZE, stdin);

        if (strncmp(cmd, "upload", 6) == 0) {
            if (sscanf(cmd, "upload %s", filepath) != 1) {
                // exit 
                printf("Include file path \n\n e.g\n> upload flag.txt");
                continue;
            }
            upload(filepath);
        } else if (strncmp(cmd, "download", 8) == 0) {
            if (sscanf(cmd, "download %s", filepath) != 1) {
                // 
                printf("Download did not work \n");
                continue;
            }// parse the path and take only part after '\'
            download(filepath);
        }
    }
    return 0;
}