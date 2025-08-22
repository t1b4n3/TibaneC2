#ifndef certifications
#define certifications

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

void generate_key_and_cert() {
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

    key_file = fopen("./certs/key.pem", "wb");
    if (!key_file || !PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key to key.pem\n");
    }
    if (key_file) fclose(key_file);

    cert_file = fopen("certs/cert.pem", "wb");
    if (!cert_file || !PEM_write_X509(cert_file, x509)) {
        fprintf(stderr, "Failed to write certificate to cert.pem\n");
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

void init() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); 
    ERR_load_crypto_strings();
}


#endif