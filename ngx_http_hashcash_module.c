#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef UNIT_TEST
#include <libmemcached-1.0/memcached.h>
#include <libmemcachedutil-1.0/pool.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#endif

#include "ngx_http_hashcash_module.h"
#include <openssl/evp.h>

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

    unsigned char digest[EVP_MAX_MD_SIZE];
    static const EVP_MD* EVP_MD_SHA256;
    if (EVP_MD_SHA256 == NULL) {
        EVP_MD_SHA256 = EVP_get_digestbyname("SHA256");
    }
    unsigned int digest_len;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, EVP_MD_SHA256, NULL);
    EVP_DigestUpdate(mdctx, header_token, len);
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    EVP_MD_CTX_free(mdctx);

    return ngx_http_hashcash_module_count_leading_zeros(digest, digest_len);
}

/**
 * validate a single If-Match token.
 *
 * The token is of the form timestamp-nonce-proof, where timestamp is in epoch.
 */
int16_t ngx_http_hashcash_module_validate_token(ngx_http_hashcash_module_check_ctx_t* ctx, ngx_http_hashcash_module_validate_token_is_new_t validate_token_function)
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

    ctx->sent_time = timestamp;
    ctx->nonce = nonce;
    ctx->proof = proof;

    // check if nonce is new
    if (validate_token_function != NULL) {
        int16_t validation = validate_token_function(ctx);
        if (validation < 0) {
            return validation;
        }
    }
    return work;
}

#ifndef UNIT_TEST
/** config options for module */
typedef struct {
    ngx_str_t memcache_servers;
    ngx_str_t memcache_prefix;
    ngx_int_t max_time_diff;
    ngx_uint_t min_work_needed;

    memcached_pool_st* pool;
} ngx_http_hashcash_loc_conf_t;

/** allocates space for config struct */
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

/** merges the config structs */
static char*
ngx_http_hashcash_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child)
{
    ngx_http_hashcash_loc_conf_t* prev = parent;
    ngx_http_hashcash_loc_conf_t* conf = child;
    bool create_new_pool = true;
    if (conf->memcache_servers.data == NULL && prev->pool != NULL) {
        ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Using pool defined in parent");
        conf->pool = prev->pool;
        create_new_pool = false;
    }

    ngx_conf_merge_str_value(conf->memcache_servers, prev->memcache_servers, "--SERVER=127.0.0.1:11211");
    ngx_conf_merge_str_value(conf->memcache_prefix, prev->memcache_prefix, "--");
    ngx_conf_merge_sec_value(conf->max_time_diff, prev->max_time_diff, 60);
    ngx_conf_merge_uint_value(conf->min_work_needed, prev->min_work_needed, 0);

    if (create_new_pool) {
        ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "create pool=%s, prefix=%s, ttl=%ld, work=%lu\n", conf->memcache_servers.data, conf->memcache_prefix.data, conf->max_time_diff, conf->min_work_needed);
        conf->pool = memcached_pool((const char*)conf->memcache_servers.data, conf->memcache_servers.len);
    }

    if (conf->max_time_diff < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "max_time_diff must be equal or more than 1");
        return NGX_CONF_ERROR;
    }
    if (conf->min_work_needed > 32) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "min_work_needed should be feasible");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/** Checks the token against the memcache pool */
static int16_t ngx_http_hashcash_header_check_memcache(ngx_http_hashcash_module_check_ctx_t* ctx)
{
    memcached_return rc;
    memcached_pool_st* pool = (memcached_pool_st*)ctx->pool;
    ngx_http_request_t* request = (ngx_http_request_t*)ctx->request;

    memcached_st* memcache = memcached_pool_pop(pool, true, &rc);
    if (rc != MEMCACHED_SUCCESS) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, request->connection->log, rc, "Failed to connect to memcached (%s)", memcached_strerror(memcache, rc));
        memcached_pool_push(pool, memcache);
        return NGX_OK;
    } else {
        size_t len = strlen(ctx->prefix) + strlen(ctx->nonce);
        char key[len + 1];
        key[0] = 0;
        strcat(key, ctx->prefix);
        strcat(key, ctx->nonce);

        rc = memcached_replace(memcache, key, strlen(key), "", 0, ctx->max_time_diff, (uint32_t)0);

        if (rc == MEMCACHED_SUCCESS) {
            memcached_pool_push(pool, memcache);
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, request->connection->log, rc, "refreshed used key '%s'", key);
            return NGX_MODULE_HASHCASH_DUPLICATE;
        } else if (rc == MEMCACHED_NOTSTORED) {
            rc = memcached_set(memcache, key, strlen(key), "", 0, ctx->max_time_diff, (uint32_t)0);
            if (rc == MEMCACHED_SUCCESS) {
                memcached_pool_push(pool, memcache);
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, request->connection->log, rc, "Saved key '%s' to memcache", key);
                return NGX_OK;
            } else {
                memcached_pool_push(pool, memcache);
                ngx_log_debug1(NGX_LOG_DEBUG_CORE, request->connection->log, rc, "Failed to save key (%s)", memcached_strerror(memcache, rc));
                return NGX_OK;
            }
        } else {
            memcached_pool_push(pool, memcache);
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, request->connection->log, rc, "Failed to replace key (%s)", memcached_strerror(memcache, rc));
            return NGX_OK;
        }
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_hashcash_init(ngx_conf_t* cf);

// NGINX Module stuff below
static ngx_http_module_t ngx_http_hashcash_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_hashcash_init, /* postconfiguration */

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
        ngx_conf_set_str_slot,
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

//static ngx_str_t ngx_http_hashcash_response_type = ngx_string("application/octet-stream");
static ngx_int_t
ngx_http_hashcash_header_set_response(ngx_http_request_t* request, const char* message)
{
    // ngx_table_elt_t* h = ngx_list_push(&request->headers_out.headers);
    // if (h == NULL) {
    //     return NGX_ERROR;
    // }
    // ngx_str_t key = ngx_string("X-HashCash");
    // ngx_str_t value = ngx_string(message);
    // h->key = key;
    // h->value = value;
    // h->hash = 1;

    // ngx_http_complex_value_t cv;
    // ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    // cv.value.len = 0;
    // cv.value.data = (unsigned char*)"";
    // request->headers_out.last_modified_time = time(NULL);
    // ngx_http_send_response(request, NGX_HTTP_PRECONDITION_FAILED, &ngx_http_hashcash_response_type, &cv);
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, request->connection->log, 0, message);
    return NGX_HTTP_PRECONDITION_FAILED;
}

/** Retrieve custom header with specified name */
char* ngx_http_hashcash_get_header(ngx_http_request_t* r, char* name)
{
    size_t len = strlen(name);
    ngx_list_part_t* part = &r->headers_in.headers.part;
    ngx_table_elt_t* h = part->elts;

    for (ngx_uint_t i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (len != h[i].key.len || ngx_strcasecmp((unsigned char*)name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }
        // ngx_log_debug(NGX_LOG_DEBUG_CORE, r->connection->log, 0, "header %s=%s", h[i].key.data, h[i].value.data);
        return (char*)h[i].value.data;
    }
    return NULL;
}

/** Checks the token in x-hashcash */
static ngx_int_t
ngx_http_hashcash_header_filter(ngx_http_request_t* request)
{
    ngx_http_hashcash_loc_conf_t* cfg = ngx_http_get_module_loc_conf(request, ngx_http_hashcash_module);

    if (cfg->min_work_needed == 0) {
        // ngx_log_debug0(NGX_LOG_DEBUG_CORE, request->connection->log, 0, "no hashcash defined");
        return NGX_DECLINED;
    } else {
        char* header = ngx_http_hashcash_get_header(request, "x-hashcash");
        if (header == NULL) {
            return ngx_http_hashcash_header_set_response(request, "Header missing");
        } else {
            ngx_http_hashcash_module_check_ctx_t ctx;
            ctx.check_time = time(NULL);
            ctx.header_token = header;
            ctx.header_length = strlen(header);
            ctx.prefix = (char*)cfg->memcache_prefix.data;
            ctx.max_time_diff = cfg->max_time_diff;
            ctx.min_work_needed = cfg->min_work_needed;
            ctx.pool = cfg->pool;
            ctx.request = request;

            int16_t c = ngx_http_hashcash_module_validate_token(&ctx, ngx_http_hashcash_header_check_memcache);
            if (c >= 0) {
                ngx_log_debug(NGX_LOG_DEBUG_CORE, request->connection->log, 0, "validated header %s=%d", ctx.header_token, c);
                return NGX_DECLINED;
            }
            switch (c) {
            case NGX_MODULE_HASHCASH_INVALID_HEADER:
                return ngx_http_hashcash_header_set_response(request, "Header invalid");
            case NGX_MODULE_HASHCASH_EXPIRED:
                return ngx_http_hashcash_header_set_response(request, "Header expired");
            case NGX_MODULE_HASHCASH_WORK_NEEDED:
                return ngx_http_hashcash_header_set_response(request, "Header insufficient");
            case NGX_MODULE_HASHCASH_DUPLICATE:
                return ngx_http_hashcash_header_set_response(request, "Header duplicate");
            default:
                return ngx_http_hashcash_header_set_response(request, "Header wrong");
            }
        }
    }
}

/** Install hash cash as first filter. */
static ngx_int_t
ngx_http_hashcash_init(ngx_conf_t* cf)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cf->log, 0, "installed hash-cash filter as first filter in chain");
    ngx_http_core_main_conf_t* cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    ngx_http_handler_pt* h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_hashcash_header_filter;

    return NGX_OK;
}

#endif