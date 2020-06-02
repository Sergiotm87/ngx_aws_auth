//
// Created by Assonance (Hexmark Records Ltd) on 31/05/2020.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>

uint8_t *getDateUTC();
uint8_t *getKeyScope(uint8_t *, uint8_t *, uint8_t *);
uint8_t *getSignatureKey(uint8_t *, uint8_t *, uint8_t *, uint8_t *);
uint8_t *hmacHex(uint8_t *, uint8_t *);
uint8_t *sign(uint8_t *, uint8_t *);
        void encode(const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len);
void decode(const char *in, size_t in_len, uint8_t **out, size_t *out_len);

