#include "agent.h"

#include <stdio.h>              
#include <string.h>             
#include <openssl/sha.h>        

const char base62[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


void get_agent_id(const char *input, char output[9]) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    char sha256_string[65];
    SHA256((unsigned char *)input, strlen(input), hash1);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(sha256_string + (i * 2), "%02x", hash1[i]);
    }
    sha256_string[64] = 0;

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)sha256_string, strlen(sha256_string), hash);

    // Use first 6 bytes of hash (48 bits)
    uint64_t val = 0;
    for (int i = 0; i < 6; i++) {
        val = (val << 8) | hash[i];
    }
    // Convert to base62 (8 characters)
    for (int i = 7; i >= 0; i--) {
        output[i] = base62[val % 62];
        val /= 62;
    }
    output[8] = '\0';
}
