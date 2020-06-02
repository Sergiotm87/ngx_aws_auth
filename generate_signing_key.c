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


int main() {

    uint8_t *dateStamp = getDateUTC();

    uint8_t *keyScope = getKeyScope(dateStamp, "eu-west-2", "s3");
    uint8_t *signature = getSignatureKey("12345", dateStamp, "eu-west-2", "s3");

    puts(keyScope);
    puts(signature);

    free(dateStamp);
    free(keyScope);
    free(signature);
    return 0;
}

/**
 * Function to get the UTC date string
 * @return - pointer to the string
 */
uint8_t *getDateUTC() {
    time_t rawtime;
    struct tm *timeinfo;
    uint8_t *buffer = (uint8_t *) malloc(9 * sizeof(uint8_t));

    time(&rawtime);
    timeinfo = gmtime(&rawtime);
    strftime(buffer, 9, "%Y%m%d", timeinfo);
    return buffer;
}

/**
 * Generates the signing key for AWS4
 *
 * @param secretKey - AWS secret key
 * @param dateStamp - today's date in YYYYmmdd format
 * @param regionName - AWS e.g.
 * @param serviceName
 * @return
 */
uint8_t *getSignatureKey(
        uint8_t *secretKey,
        uint8_t *dateStamp,
        uint8_t *regionName,
        uint8_t *serviceName) {

    uint8_t *buffer = (uint8_t *) malloc(strlen(secretKey) * sizeof(uint8_t) + 5);
    sprintf(buffer, "AWS4%s", secretKey);
    uint8_t *kDate = sign(buffer, dateStamp);
    uint8_t *kRegion = sign(kDate, regionName);
    uint8_t *kService = sign(kRegion, serviceName);
    uint8_t *kSigning = sign(kService, "aws4_request");

    size_t encodeLength = strlen(kSigning) * sizeof(uint8_t) * 3;
    uint8_t *encodedSignature = (uint8_t *) malloc(encodeLength);
    encode(kSigning, strlen(kSigning), &encodedSignature, &encodeLength);


    // Clean up
    free(kDate);
    free(kRegion);
    free(kService);
    free(kSigning);

    return encodedSignature;
}

/**
 * AWS Keyscope requires for AWS4 request signing
 *
 * @param dateStamp
 * @param region
 * @param service
 * @return
 */
uint8_t *getKeyScope(
        uint8_t *dateStamp,
        uint8_t *region,
        uint8_t *service) {

    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = gmtime(&rawtime);

    int sigKeyLength = strlen(region) + strlen(service) + 16;
    uint8_t *buffer = (uint8_t *) malloc(sigKeyLength * sizeof(uint8_t));

    strftime(buffer, 9, "%Y%m%d", timeinfo);
    sprintf(&buffer[8], "/%s/%s/aws4_request", region, service);
    return buffer;
}

/**
 * HMAC signing for AWS hash
 *
 * @param key
 * @param val
 * @return
 */

uint8_t *sign(uint8_t *key, uint8_t *val) {
    uint8_t *hash = (uint8_t *) malloc(32 * sizeof(uint8_t));

    int keyLength = strlen(key);
    int msgLength = strlen(val);

    HMAC_CTX hmac;
    HMAC_CTX_init(&hmac);
    HMAC_Init_ex(&hmac, &key[0], keyLength, EVP_sha256(), NULL);
    HMAC_Update(&hmac, (uint8_t * ) & val[0], msgLength);
    unsigned int len = 32;
    HMAC_Final(&hmac, hash, &len);
    HMAC_CTX_cleanup(&hmac);

    return hash;
}

/**
 * Base64 encode
 *
 * @param in
 * @param in_len
 * @param out
 * @param out_len
 */
void encode(const uint8_t *in, size_t in_len,
            uint8_t **out, size_t *out_len) {
    BIO *buff, *b64f;
    BUF_MEM *ptr;

    b64f = BIO_new(BIO_f_base64());
    buff = BIO_new(BIO_s_mem());
    buff = BIO_push(b64f, buff);

    BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(buff, BIO_CLOSE);
    BIO_write(buff, in, in_len);
    BIO_flush(buff);

    BIO_get_mem_ptr(buff, &ptr);
    (*out_len) = ptr->length;
    (*out) = (uint8_t *) malloc(((*out_len) + 1) * sizeof(uint8_t));
    memcpy(*out, ptr->data, (*out_len));
    (*out)[(*out_len)] = '\0';

    BIO_free_all(buff);
}

/**
 * Base64 decode
 *
 * @param in
 * @param in_len
 * @param out
 * @param out_len
 */
void decode(const char *in, size_t in_len,
            uint8_t **out, size_t *out_len) {
    BIO *buff, *b64f;

    b64f = BIO_new(BIO_f_base64());
    buff = BIO_new_mem_buf((void *) in, in_len);
    buff = BIO_push(b64f, buff);
    (*out) = (uint8_t *) malloc(in_len * sizeof(uint8_t));

    BIO_set_flags(buff, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(buff, BIO_CLOSE);
    (*out_len) = BIO_read(buff, (*out), in_len);
    (*out) = (uint8_t *) realloc((void *) (*out), ((*out_len) + 1) * sizeof(uint8_t));
    (*out)[(*out_len)] = '\0';

    BIO_free_all(buff);
}