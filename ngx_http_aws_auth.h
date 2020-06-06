#ifndef __NGX_HTTP_AWS_AUTH__H__
#define __NGX_HTTP_AWS_AUTH__H__


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#include "aws_functions.h"

#define AWS_S3_VARIABLE "s3_auth_token"
#define AWS_DATE_VARIABLE "aws_date"
#define AWS_DATE_WIDTH 8

typedef struct {
    ngx_str_t access_key;
    ngx_str_t key_scope;
    ngx_str_t secret_key;
    ngx_str_t signing_key_decoded;
    ngx_str_t region;
    ngx_str_t service;
    ngx_str_t endpoint;
    ngx_str_t bucket_name;
    ngx_uint_t enabled;
} ngx_http_aws_auth_conf_t;


static void
*ngx_http_aws_auth_create_loc_conf(ngx_conf_t *cf);

static char
*ngx_http_aws_auth_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static
ngx_int_t ngx_aws_auth_req_init(ngx_conf_t *cf);

static char
*ngx_http_aws_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char
*ngx_http_aws_sign(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void
update_credentials(ngx_pool_t *pool, ngx_http_aws_auth_conf_t *conf, time_t *time_p);

static void
init_field(ngx_pool_t *pool, ngx_str_t *field);

static void
update_key_scope(ngx_pool_t *pool, ngx_http_aws_auth_conf_t *conf, uint8_t *dateStamp);

static void
update_signing_key_decoded(ngx_pool_t *pool, ngx_http_aws_auth_conf_t *conf, uint8_t *dateStamp);

static int
is_signing_key_valid(ngx_http_aws_auth_conf_t *conf, const ngx_str_t *dateTimeStamp);

#endif
