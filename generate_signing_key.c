//
// Created by Assonance (Hexmark Records Ltd) on 31/05/2020.
//
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include "generate_signing_key.h"

uint8_t *get_signature_key(
        uint8_t *secretKey,
        uint8_t *dateStamp,
        uint8_t *regionName,
        uint8_t *serviceName) {

    // extra byte for null char
    uint8_t *buffer = (uint8_t *) calloc(strlen((char *) secretKey) + 5, sizeof(uint8_t));

    sprintf((char *) buffer, "AWS4%s", secretKey);
    uint8_t *kDate = sign(buffer, dateStamp);
    uint8_t *kRegion = sign(kDate, regionName);
    uint8_t *kService = sign(kRegion, serviceName);
    uint8_t *kSigning = sign(kService, (uint8_t *) "aws4_request");

    // Clean up
    free(buffer);
    free(kDate);
    free(kRegion);
    free(kService);

    return kSigning;
}

uint8_t *get_key_scope(
        uint8_t *dateStamp,
        uint8_t *region,
        uint8_t *service) {

    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = gmtime(&rawtime);

    int sigKeyLength = strlen((char *) region) + strlen((char *) service) + 16;
    uint8_t *buffer = (uint8_t *) malloc(sigKeyLength * sizeof(uint8_t));

    strftime((char *) buffer, 9, "%Y%m%d", timeinfo);
    sprintf(&((char *) buffer)[8], "/%s/%s/aws4_request", region, service);
    return buffer;
}

uint8_t *sign(uint8_t *key, uint8_t *val) {
    unsigned int len = 64;

    uint8_t *hash = (uint8_t *) calloc(len, sizeof(uint8_t));

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    HMAC_Init(&hmac, key, strlen((char *) key), EVP_sha256());
    HMAC_Update(&hmac, val, strlen((char *) val));
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    return hash;
}
