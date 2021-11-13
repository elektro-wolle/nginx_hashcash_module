#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef UNIT_TEST
#include <libmemcached-1.0/memcached.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#endif

#include "ngx_http_hashcash_module.h"
#include <openssl/sha.h>

/**
 * Count the leading zeros in the data array.
 */
int16_t ngx_http_hashcash_module_count_leading_zeros(const unsigned char* data, size_t len)
{
    // count number of 0-bytes
    const unsigned char* ptr = data;
    size_t zeroCount = 0;
    while (zeroCount < len) {
        if (*ptr != 0) {
            break;
        }
        ptr++;
        zeroCount++;
    }
    // count number of unset bits in the first non-zero data
    uint8_t zeroBits = 0;
    while ((*ptr & (128 >> zeroBits)) == 0 && zeroBits < 8 && zeroCount != len) {
        zeroBits++;
    }
    return 8 * zeroCount + zeroBits;
}

/**
 * The proof-of-work amount equals to the number of zero-bits leading the sha256
 */
int16_t ngx_http_hashcash_module_get_pow_amount(const char* header_token, size_t len)
{

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, header_token, len);
    SHA256_Final(digest, &ctx);
    return ngx_http_hashcash_module_count_leading_zeros(digest, SHA256_DIGEST_LENGTH);
}

/**
 * validate a single If-Match token.
 *
 * The token is of the form timestamp-nonce-proof, where timestamp is in epoch.
 */
int16_t ngx_http_hashcash_module_validate_token(ngx_http_hashcash_module_check_ctx_t* ctx)
{
    char* token_to_check = strndup(ctx->header_token, ctx->header_length);
    char* token_ptr = NULL;

    // extract epoch
    char* epoch_string = strtok_r(token_to_check, "-", &token_ptr);
    if (epoch_string == NULL) {
        return NGX_MODULE_HASHCASH_INVALID_HEADER;
    }

    // extract nonce
    char* nonce = strtok_r(NULL, "-", &token_ptr);
    if (nonce == NULL) {
        return NGX_MODULE_HASHCASH_INVALID_HEADER;
    }

    // extract proof
    char* proof = strtok_r(NULL, "-", &token_ptr);
    if (proof == NULL) {
        return NGX_MODULE_HASHCASH_INVALID_HEADER;
    }

    // check expired
    time_t timestamp = (time_t)atol(epoch_string);
    if (timestamp == 0) {
        return NGX_MODULE_HASHCASH_INVALID_HEADER;
    }
    if (labs(ctx->check_time - timestamp) > ctx->max_time_diff) {
        return NGX_MODULE_HASHCASH_EXPIRED;
    }

    // check work
    unsigned int work = ngx_http_hashcash_module_get_pow_amount(ctx->header_token, ctx->header_length);
    if (work < ctx->min_work_needed) {
        return NGX_MODULE_HASHCASH_WORK_NEEDED;
    }

    // check if nonce is new
    if (ctx->validate_token_function != NULL) {
        return ctx->validate_token_function(nonce, ctx->max_time_diff);
    }
    return work;
}

#ifndef UNIT_TEST
typedef struct {
    ngx_str_t memcache_servers;
    ngx_str_t memcache_prefix;
    ngx_int_t max_time_diff;
    ngx_uint_t min_work_needed;

    memcached_st memcache;
} ngx_http_hashcash_loc_conf_t;

static void*
ngx_http_hashcash_create_loc_conf(ngx_conf_t* cf)
{
    ngx_http_hashcash_loc_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hashcash_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->max_time_diff = NGX_CONF_UNSET_UINT;
    conf->min_work_needed = NGX_CONF_UNSET_UINT;
    return conf;
}

static char*
ngx_http_hashcash_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
    ngx_http_hashcash_loc_conf_t* prev = parent;
    ngx_http_hashcash_loc_conf_t* conf = child;
    if (conf->memcache_servers.data == NULL) {
        conf->memcache = prev->memcache;
    }

    ngx_conf_merge_str_value(conf->memcache_servers, prev->memcache_servers, "127.0.0.1:11211");
    ngx_conf_merge_str_value(conf->memcache_prefix, prev->memcache_prefix, "__");
    ngx_conf_merge_sec_value(conf->max_time_diff, prev->max_time_diff, 60);
    ngx_conf_merge_uint_value(conf->min_work_needed, prev->min_work_needed, 16);

    if (conf->max_time_diff < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "max_time_diff must be equal or more than 1");
        return NGX_CONF_ERROR;
    }
    if (conf->min_work_needed < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "min_work_needed must be at least 1");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

char* ngx_http_hashcash_create_server_pool(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
    ngx_conf_set_str_slot(cf, cmd, conf);
    ngx_http_hashcash_loc_conf_t* cfg = (ngx_http_hashcash_loc_conf_t*)conf;
    memcached_server_list_st serverlist = memcached_servers_parse((const char*)cfg->memcache_servers.data);
    if (serverlist->number_of_hosts == 0) {
        return NGX_CONF_ERROR;
    }
    memcached_create(&cfg->memcache);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_hashcash_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_hashcash_create_loc_conf, /* create location configuration */
    ngx_http_hashcash_merge_loc_conf /* merge location configuration */
};

static ngx_command_t ngx_http_hashcash_commands[] = {
    { ngx_string("hashcash_memcache_servers"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_hashcash_create_server_pool,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hashcash_loc_conf_t, memcache_servers),
        NULL },
    { ngx_string("hashcash_min_work"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hashcash_loc_conf_t, min_work_needed),
        NULL },
    { ngx_string("hashcash_max_ttl"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hashcash_loc_conf_t, max_time_diff),
        NULL },
    { ngx_string("hashcash_memcache_prefix"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hashcash_loc_conf_t, memcache_prefix),
        NULL },
    ngx_null_command
};

ngx_module_t ngx_http_hashcash_module = {
    NGX_MODULE_V1,
    &ngx_http_hashcash_module_ctx, /* module context */
    ngx_http_hashcash_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};
#endif