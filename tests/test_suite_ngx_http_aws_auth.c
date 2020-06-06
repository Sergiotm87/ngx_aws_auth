#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "vendor/cmocka/include/cmocka.h"

#include "../aws_functions.h"

ngx_pool_t *pool;

static void assert_ngx_string_equal(ngx_str_t a, ngx_str_t b) {
    int len = a.len < b.len ? a.len : b.len;
    assert_memory_equal(a.data, b.data, len);
}

static void null_test_success(void **state) {
    (void) state; /* unused */
}

/*
static void host_header_ctor(void **state) {
    ngx_str_t bucket;
    const ngx_str_t *host;

    (void) state;

    bucket.data = "test-es-three";
    bucket.len = strlen(bucket.data);
    host = ngx_aws_auth__host_from_bucket(pool, &bucket);
    assert_string_equal("test-es-three.s3.amazonaws.com", host->data);

    bucket.data = "complex.sub.domain.test";
    bucket.len = strlen(bucket.data);
    host = ngx_aws_auth__host_from_bucket(pool, &bucket);
    assert_string_equal("complex.sub.domain.test.s3.amazonaws.com", host->data);
}
*/

int main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(null_test_success),
//            cmocka_unit_test(host_header_ctor),
    };

    pool = ngx_create_pool(1000000, NULL);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
