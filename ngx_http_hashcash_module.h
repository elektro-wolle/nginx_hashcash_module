#ifndef PROOF_H
#define PROOF_H 1
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define NGX_MODULE_HASHCASH_INVALID_HEADER -1
#define NGX_MODULE_HASHCASH_EXPIRED -2
#define NGX_MODULE_HASHCASH_WORK_NEEDED -3
#define NGX_MODULE_HASHCASH_DUPLICATE -4


typedef struct {
    char* header_token;
    size_t header_length;
    time_t check_time;
    unsigned int max_time_diff;
    unsigned int min_work_needed;

    time_t sent_time;
    char* nonce;
    char* proof;
    char* prefix;
    void* pool;
    void* request;
} ngx_http_hashcash_module_check_ctx_t;

typedef int16_t (*ngx_http_hashcash_module_validate_token_is_new_t)(ngx_http_hashcash_module_check_ctx_t* ctx);

int16_t ngx_http_hashcash_module_count_leading_zeros(const unsigned char* data, size_t len);
int16_t ngx_http_hashcash_module_get_pow_amount(const char* header_token, size_t len);

int16_t ngx_http_hashcash_module_validate_token(ngx_http_hashcash_module_check_ctx_t* ctx, ngx_http_hashcash_module_validate_token_is_new_t validation_function);

#endif