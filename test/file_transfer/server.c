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
//#include <math.h>

#define PORT 9999
#define BUFFER_SIZE 0x100
#define MAX_SIZE 0x1000 // maximum file size 


int sock;

int upload(const char* path) {
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


void list() {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    int count = 0;
    char *filenames[BUFFER_SIZE];

    if (d) {
        while ((dir = readdir(d)) != NULL && count < BUFFER_SIZE) {
            filenames[count] = (char *)malloc(strlen(dir->d_name) + 1);
            if (filenames[count] == NULL) {
                perror("Failed to allocate memory for filename");
                for (int i = 0; i < count; i++) {
                    free(filenames[i]);
                }
                closedir(d);
                return;
            }

            strcpy(filenames[count], dir->d_name);
            count++;
        }

        closedir(d);

        for (int i = 0; i < count; i++) {
            send(sock, filenames[i], strlen(filenames[i]), 0);
            send(sock, "\n", 1, 0);
            free(filenames[i]);
        }

        // ✅ Add sentinel string to signal end of list
        send(sock, "__END__\n", strlen("__END__\n"), 0);

    } else {
        perror("Failed to open directory");
    }
}





void *client_handler(void) {
    // get username and password from json file
    //FILE *conf = fopen("conf.json", "r");


    char cmd[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    char path[BUFFER_SIZE];
    
    while (1) {
        memset(cmd, 0, sizeof(cmd));
        memset(buffer, 0, sizeof(buffer));
        memset(path, 0, sizeof(path));

        recv(sock, buffer, sizeof(buffer), 0);
        
        //memset(log_buffer, 0, sizeof(log_buffer));
        //snprintf(log_buffer, strlen(buffer)+1, "Recieved %s ", buffer);
        //Log(log_buffer);


        int tokens = sscanf(buffer, "%s %s", cmd, path) == 2; 


        if (tokens >= 1) {
            if (strcmp(cmd, "ls") == 0) {
                list();
            } else if (strncmp(cmd, "upload", 6) == 0 && tokens == 2) {
                download(path);
            } else if (strncmp(cmd, "download", 8) == 0 && tokens == 2) {
                upload(path);
            } else if (strcmp(cmd, "exit") == 0) {
                return NULL;
            } else {
                char err[] = "Unknown command\n";
                send(sock, err, strlen(err), 0);
            }
        }
        

    }
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
        perror("binding failed");
        close(serverSock);
        return -1;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        perror("Listen Failed");
        close(serverSock);
        return -1;
    }
    
    while (1) {
        if ((sock = accept(serverSock, (struct sockaddr*)&clientAddr, (socklen_t*)&client_len)) < 0) {
            perror("Accept failed");
            continue;
        }
        
        // port = ntohs(clientAddr.sin_port) 
        // ip = inet_ntoa(client_addr.sin_addr)

        pthread_t thread;
        
        if (pthread_create(&thread, NULL, client_handler, NULL) < 0) {
            perror("could not create thread");
            continue;
        }
        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread);
    }

    close(serverSock);

    return 0;
}


