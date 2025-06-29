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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>

#define PORT 9999


int tcp_listener() {
    int serverSock, agentSock;

    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);

    struct sockaddr_in addr;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    addr.sin_family = AF_INET;


    if ((serverSock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        // log
        return -1;
    }

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

    // openssl to socket
    const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        return -1;
    }
    SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0");  // Allows all ciphers for debugging

    // generate certificates if they dont exesits
    if (access("certs/cert.pem", F_OK) != 0 && access("certs/key.pem", F_OK) != 0) {
        generate_key_and_cert();
    }

    // load certificates
    SSL_CTX_use_certificate_file(ctx, "certs/cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "certs/key.pem", SSL_FILETYPE_PEM);


    while (1) {
        agentSock = accept(serverSock, (struct sockaddr*)&client_addr, &len);
        if (agentSock == -1) {
            perror("Accept Failed");
            // log
            continue;
        }

        // use threads to for multi-tcp


        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, agentSock);
        // perform tls handshake
        if (SSL_accept(ssl) <= 0) {
            perror("TLS handshake Failed");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(agentSock);
            continue;
        }


    }


    CLEANUP:
    SSL_free(ssl);
    close(serverSock);
}