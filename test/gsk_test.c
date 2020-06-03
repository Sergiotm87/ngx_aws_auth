//
// Created by Aaron Browne on 03/06/2020.
//

#include "../generate_signing_key.h"

int main() {

    uint8_t *dateStamp = get_date_utc();

    uint8_t *keyScope = get_key_scope(dateStamp, (uint8_t *)"eu-west-2", (uint8_t *)"s3");
    uint8_t *signature = get_signature_key((uint8_t *)"12345", dateStamp, (uint8_t *)"eu-west-2", (uint8_t *)"s3");

    puts((char *)keyScope);
    puts((char *)signature);

    free(dateStamp);
    free(keyScope);
    free(signature);
    return 0;
}
