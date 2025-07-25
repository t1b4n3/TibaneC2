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
    SSL *ssl;
    char ip[256];
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

    cJSON *mac = cJSON_GetObjectItem(json, "mac");
    cJSON *hostname =  cJSON_GetObjectItem(json, "hostname");
    cJSON *os =  cJSON_GetObjectItem(json, "os");
    cJSON *arch = cJSON_GetObjectItem(json, "arch");

    char input[255];
    snprintf(input, sizeof(input), "%s-%s-%s-%s", mac->valuestring, hostname->valuestring, os->valuestring, arch->valuestring);
    char agent_id[65];
    get_agent_id(input, agent_id);

    // check if id already exists in database
    if (check_agent_id(agent_id) == 1) goto REPLY;

    //log
    log_new_agent(agent_id, os->valuestring, hostname->valuestring, mac->valuestring, arch->valuestring);

    // register to datbase (agent_id, os, ip, mac, hostname)
    // check if agent id exists
    struct db_agents args;
    strncpy(args.agent_id, agent_id, sizeof(args.agent_id) - 1);
    args.agent_id[sizeof(args.agent_id) - 1] = '\0';
    strncpy(args.os, os->valuestring, sizeof(args.os) - 1);
    args.os[sizeof(args.os) - 1] = '\0';
    strncpy(args.ip, ip, sizeof(args.ip) - 1);
    args.ip[sizeof(args.ip) - 1] = '\0';
    strncpy(args.mac, mac->valuestring, sizeof(args.mac) - 1);
    args.mac[sizeof(args.mac) - 1] = '\0';
    strncpy(args.hostname, hostname->valuestring, sizeof(args.hostname) - 1);
    args.hostname[sizeof(args.hostname) - 1] = '\0';

    strncpy(args.arch, arch->valuestring, sizeof(args.arch) - 1);
    args.arch[sizeof(args.arch) - 1] = '\0';
    new_agent(args);

    // reply with agent id
    REPLY:
    cJSON *json_reply = cJSON_CreateObject();
    cJSON_AddStringToObject(json_reply, "mode", "ack");
    cJSON_AddStringToObject(json_reply, "agent_id", agent_id);

    char *reply = cJSON_Print(json_reply);
    //send(sock, reply, strlen(reply), 0);
    SSL_write(ssl, reply, strlen(reply));

    free(reply);
    cJSON_Delete(json_reply);
}

void *tcp_ssl_agent_handler(void *args) {
    struct tcp_ssl_thread_args *arg = (struct tcp_ssl_thread_args*)args;
    SSL *ssl  = arg->ssl;


    // recieves message from implant register or beaconing
    char buffer[BUFFER_SIZE];
    //int bytes_received = recv(sock, buffer, sizeof(buffer) -1, 0);
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received <= 0) {
        perror("recv failed");
        return NULL;
    }
    buffer[bytes_received] = '\0';

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        printf("Error parsing JSON!\n");
        return NULL;
    }

    cJSON *type = cJSON_GetObjectItem(json, "mode");
    if (strcmp(type->valuestring, "register") == 0) {
        ssl_register_agent(json, arg->ip, ssl);
    } else if (strcmp(type->valuestring, "beacon") == 0) {
        ssl_beacon(json, ssl);
    } else if (strcmp(type->valuestring, "session") == 0) {
        // session mode
        // session();
    }

    //cJSON_Delete(json);
    SSL_free(ssl);
    free(args);
    return NULL;
}




void* tcp_ssl_listener(void *args) {
    init();

    struct Args_t {
        char cert[BUFFER_SIZE];
        char key[BUFFER_SIZE];
        int port;
    };

    struct Args_t *Args = (struct Args_t*)args;

    char cert[BUFFER_SIZE];
    char key[BUFFER_SIZE];
    int PORT = Args->port;

    strncpy(cert, Args->cert, BUFFER_SIZE);
    strncpy(key, Args->key, BUFFER_SIZE);

        // generate certificates if they dont exesits
    if (access(cert, F_OK) != 0 || access(key, F_OK) != 0) {
        generate_key_and_cert(cert, key);
    }
    free(args);
    

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
        sleep(60);
        return NULL;
    }

    if (bind(serverSock, (struct sockaddr*)&addr, sizeof(addr))) {
        perror("binding failed");
        close(serverSock);
        return NULL;
    }

    if (listen(serverSock, 20) == -1) {
        perror("Listen Failed");
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
   
   


    while (1) {
        agentSock = accept(serverSock, (struct sockaddr*)&client_addr, &len);
        if (agentSock == -1) {
            perror("Accept Failed");
            // log
            continue;
        }
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

        // create thread to call tcp_enc_agent_handler and pass the following as arguments
        // sock, ssl, ip (create heap chunk)
        pthread_t thread;
        struct tcp_ssl_thread_args *args = malloc(sizeof(struct tcp_ssl_thread_args));
        args->ssl = ssl;
        strcpy(args->ip, inet_ntoa(client_addr.sin_addr));

        if (pthread_create(&thread, NULL, tcp_ssl_agent_handler, (void*)args) < 0) {
            perror("could not create thread");
            free(args);
            continue;
        }
        // Detach thread so resources are automatically freed on exit
        pthread_detach(thread);


        SSL_free(ssl);
        close(agentSock);
    }
    close(serverSock);
}




/*


void generate_key_and_cert(char *cert, char *key) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    X509 *x509 = NULL;
    FILE *key_file = NULL, *cert_file = NULL;

    // create directory for certs
    
  
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
        fprintf(stderr, "Failed to sign certificate\n");
        goto cleanup;
    }

    key_file = fopen(key, "wb");
    if (!key_file || !PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key \n");
    }
    if (key_file) fclose(key_file);

    cert_file = fopen(cert, "wb");
    if (!cert_file || !PEM_write_X509(cert_file, x509)) {
        fprintf(stderr, "Failed to write certificate \n");
    }
    if (cert_file) fclose(cert_file);

    printf("Key and certificate successfully generated (OpenSSL 3.0+ compliant)\n");

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
    EVP_cleanup();
    ERR_free_strings();
}


*/

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
