//
// Created by Assonance (Hexmark Records Ltd) on 31/05/2020.
//
#ifndef __NGX_AWS_AUTH__GENERATE_SIGNING_KEY__
#define __NGX_AWS_AUTH__GENERATE_SIGNING_KEY__

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/**
 * Function to get the UTC date string
 * @return - pointer to the string
 */
uint8_t *get_date_utc();


/**
 * AWS Keyscope requires for AWS4 request signing
 *
 * @param dateStamp
 * @param region
 * @param service
 * @return
 */
uint8_t *get_key_scope(uint8_t *, uint8_t *, uint8_t *);


/**
 * Generates the signing key for AWS4
 *
 * @param secretKey - AWS secret key
 * @param dateStamp - today's date in YYYYmmdd format
 * @param regionName - AWS e.g.
 * @param serviceName
 * @return
 */
uint8_t *get_signature_key(uint8_t *, uint8_t *, uint8_t *, uint8_t *);

/**
 * HMAC signing for AWS hash
 *
 * @param key
 * @param val
 * @return
 */
uint8_t *sign(uint8_t *, uint8_t *);


/**
 * Base64 encode
 *
 * @param in
 * @param in_len
 * @param out
 * @param out_len
 */
void encode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

/**
 * Base64 decode
 *
 * @param in
 * @param in_len
 * @param out
 * @param out_len
 */
void decode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);

#endif
