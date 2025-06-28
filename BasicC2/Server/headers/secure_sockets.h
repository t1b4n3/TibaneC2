#ifndef secure_communication_header
#define secure_communication_header

#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h> 

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/sslerr.h>
#include <netinet/in.h>
#include <time.h>

#include "log.h"
#include "shell.h"
#include "certifications.h"


int serverSock, agentSock;
struct sockaddr_in client_addr;
socklen_t len = sizeof(client_addr);


void init() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); 
    ERR_load_crypto_strings();
}


int secure_network(int PORT) {
    // create socket
    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    addr.sin_family = AF_INET;

    // bind addr
    if (bind(serverSock, (struct sockaddr*)&addr, sizeof(addr))) {
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



int accept_connections()  {

    const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0");  // Allows all ciphers for debugging

    // generate certificates if they dont exesits
    if (access("certs/cert.pem", F_OK) != 0 && access("certs/key.pem", F_OK) != 0) {
        generate_key_and_cert();
    }
    
    

    // load certificates
    SSL_CTX_use_certificate_file(ctx, "certs/cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "certs/key.pem", SSL_FILETYPE_PEM);
    
    //
   

    if (!ctx) {
        perror("Unable to create SSL context");
        return -1;
    }

    int duration = 10; // default duration is 10 seconds

    start:
    do {
        memset((void*)&client_addr, 0, len);
        memset((void*)&agentSock, 0, sizeof(agentSock));
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
                agentSock = accept(serverSock, (struct sockaddr*)&client_addr, &len);
                if (agentSock == -1) {
                    perror("Accept Failed");
                    return -1;
                }
                
                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, agentSock);
                // perform tls handshake
                if (SSL_accept(ssl) <= 0) {
                    perror("TLS handshake Failed");
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(agentSock);
                    return -1;
                }

                char ip[buffer_len];
                strncpy(ip, inet_ntoa(client_addr.sin_addr), sizeof(ip));

                connections_counter++;
                // proxy sends address of connected device
                printf("[+] Connection from %s | shell %d \n", ip, connections_counter);
                //log_connections(inet_ntoa(client_addr.sin_addr));
                log_connections(ip);
                addAgent(agentSock, ip, ssl);
                //addAgent(agentSock, client_addr, ssl);
                sleep(1);
                continue;
            }
        }
        } while (true);
    return 0;
}


void close_connection(SSL *ssl, int sock) {
    SSL_free(ssl);
    close(sock);
}

void close_server() {
    close(serverSock);
}
#endif