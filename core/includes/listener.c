#include "listener.h"


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <cjson/cJSON.h>

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

#include "logs.h"
#include "implant_handler.h"
#include "operator.h"

void* tcp_ssl_listener(void *args) {

    struct main_threads_args_t *Args = (struct main_threads_args_t*)args;
    char cert[BUFFER_SIZE], key[BUFFER_SIZE];
    int PORT = Args->port;
    strncpy(cert, Args->cert, BUFFER_SIZE);
    strncpy(key, Args->key, BUFFER_SIZE);


    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) { log_message(LOG_ERROR, "Socket creation failed (TCP, SSL)"); return NULL; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    int opt = 1;
    if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(LOG_ERROR, "setsockopt(SO_REUSEADDR) [TCP SSL] failed");
        close(serverSock);
        return NULL;
    }

    if (bind(serverSock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_message(LOG_ERROR, "Binding Failed [TCP SSL]| Port : %d", PORT); close(serverSock); return NULL;
    }

    if (listen(serverSock, SOMAXCONN) < 0) {
       log_message(LOG_ERROR, "Listen failed [TCP SSL]| Port : %d", PORT); close(serverSock); return NULL;
    }

    // SSL context
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) { log_message(LOG_ERROR, "Failed to create SSL ctx "); return NULL; }
    SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0"); // debugging only

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        //ERR_print_errors_fp(stderr);
        log_message(LOG_ERROR, "Failed to load ssl certification and key");
        SSL_CTX_free(ctx);
        return NULL;
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int agentSock = accept(serverSock, (struct sockaddr*)&client_addr, &len);
        if (agentSock < 0) { log_message(LOG_WARN, "Accept Faild [TCP SSL]"); continue; }

        struct implant_handler_t *Iargs = malloc(sizeof(*Iargs));
        Iargs->ctx = ctx;
        Iargs->client_fd = agentSock;
        strcpy(Iargs->ip, inet_ntoa(client_addr.sin_addr));
        Iargs->encrypted = true;
        Iargs->db_conf = Args->db_conf;

        pthread_t thread;
        if (pthread_create(&thread, NULL, implant_handler, Iargs) < 0) {
            //perror("Thread creation failed");
            log_message(LOG_ERROR, "TCP (SSL) Thread creation failed");
            
            close(agentSock);
            free(Iargs);
            continue;
        }
        pthread_detach(thread);
    }

    close(serverSock);
    SSL_CTX_free(ctx);
    return NULL;
}

void* tcp_listener(void *args) {
    struct main_threads_args_t *Args = (struct main_threads_args_t*)args;
    int PORT = Args->port;
    struct sockaddr_in clientAddr;
    socklen_t client_len = sizeof(clientAddr);
    int serverSock;

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        log_message(LOG_ERROR, "TCP socket creation failed");;
        sleep(60);
        return NULL;
    }

    int opt = 1;
    if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(LOG_ERROR, "setsockopt(SO_REUSEADDR) [TCP] failed");
        close(serverSock);
        return NULL;
    }


    struct sockaddr_in serverAddr;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_family = AF_INET;

    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr))) {
        log_message(LOG_ERROR, "Binding Failed [TCP] | Port : %d", PORT); close(serverSock); 
        return NULL;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        log_message(LOG_ERROR, "Listen failed [TCP]| Port : %d", PORT); close(serverSock); 
        return NULL;
    }

    while (1) {
        int sock;
        if ((sock = accept(serverSock, (struct sockaddr*)&clientAddr, (socklen_t*)&client_len)) < 0) {
            log_message(LOG_WARN, "Accept Faild [TCP]");
            continue;
        }

        // port = ntohs(clientAddr.sin_port)
        // ip = inet_ntoa(client_addr.sin_addr)

        pthread_t thread;

        struct implant_handler_t *args = malloc(sizeof(*args));
        args->client_fd = sock;
        strcpy(args->ip, inet_ntoa(clientAddr.sin_addr));
        args->encrypted = false;        
        args->db_conf = Args->db_conf;

        if (pthread_create(&thread, NULL, implant_handler, (void*)args) < 0) {
            log_message(LOG_ERROR, "TCP Thread creation failed");
            free(args);
            continue;
        }
        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread);
    }
    close(serverSock);
    return NULL;
}


void *operator_listener(void* args) {
    init();

    struct main_threads_args_t *Args = (struct main_threads_args_t*)args;
  
    char cert[BUFFER_SIZE];
    char key[BUFFER_SIZE];
    int OPERATOR_PORT = Args->port;

    strncpy(cert, Args->cert, BUFFER_SIZE);
    strncpy(key, Args->key, BUFFER_SIZE);


    int serverSock;

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock == -1) {
        log_message(LOG_ERROR, "Socket creation failed for operator console");
        return NULL;
    }  

    struct sockaddr_in clientAddr;
    socklen_t client_len = sizeof(clientAddr);

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr)); // Clear structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(OPERATOR_PORT);


    int opt = 1;
    if (setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message(LOG_ERROR, "setsockopt(SO_REUSEADDR) [Operator Listener] failed : %s", strerror(errno));
        close(serverSock);
        return NULL;
    }

// Check if port is already in use before binding
    if (bind(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        if (errno == EADDRINUSE) {
            log_message(LOG_ERROR, "Port %d already in use for Operator console", OPERATOR_PORT);
        } else {
            log_message(LOG_ERROR, "Binding failed for Operator console: %s", strerror(errno));
        }
        close(serverSock);
        return NULL;
    }

    if (listen(serverSock, SOMAXCONN) == -1) {
        log_message(LOG_ERROR, "Listen Failed for operator console");
        close(serverSock);
        sleep(60);
        return NULL;
    }
    
    // openssl to socket
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_message(LOG_ERROR, "Unable to create SSL context");
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
            log_message(LOG_ERROR, "Operator Accept failed");
            continue;
        }
        
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        if (SSL_accept(ssl) <= 0) {
            log_message(LOG_ERROR, "TLS Handshake Failed [Operator]");
            SSL_free(ssl);
            close(sock);
            continue;
        }
        
        struct operator_handler_args_t *args = malloc(sizeof(*args));
        args->ssl = ssl;
        args->db_conf = Args->db_conf;
        
        pthread_t thread;
        if (pthread_create(&thread, NULL, operator_handler, (void*)args) < 0) {
            log_message(LOG_ERROR, "Failed to create operator thread");
            free(args);
            args = NULL;
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

void generate_key_and_cert(char *cert_path, char *key_path) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    X509 *x509 = NULL;
    FILE *key_file = NULL, *cert_file = NULL;

    // create directory for certs
    
  
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        log_message(LOG_ERROR, "Failed to generate RSA key\n");
        goto cleanup;
    }

    x509 = X509_new();
    if (!x509) {
        log_message(LOG_ERROR, "Failed to create X509 structure\n");
        goto cleanup;
    }

    X509_set_version(x509, 2);  // v3
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);  // 1 year

    X509_set_pubkey(x509, pkey);

   
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"SA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MyOrg", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        log_message(LOG_ERROR, "Failed To Sign Certificate\n");
        goto cleanup;
    }

    key_file = fopen(key_path, "wb");
    if (!key_file || !PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        log_message(LOG_ERROR, "Failed To Write Private key to key.pem\n");
    }
    if (key_file) fclose(key_file);

    cert_file = fopen(cert_path, "wb");
    if (!cert_file || !PEM_write_X509(cert_file, x509)) {
        log_message(LOG_ERROR, "Failed to write certificate to cert.pem\n");
    }
    if (cert_file) fclose(cert_file);

    log_message(LOG_INFO, "Key and certificate successfully generated (OpenSSL 3.0+ compliant)");
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
    EVP_cleanup();
    ERR_free_strings();
}

void init() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); 
    ERR_load_crypto_strings();
}
