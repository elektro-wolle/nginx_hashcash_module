#include "nginx_hashcash_module.h"

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Count the leading zeros in the data array.
 */
int16_t nginx_hashcash_module_count_leading_zeros(const unsigned char* data, size_t len)
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
int16_t nginx_hashcash_module_get_pow_amount(const char* header_token, size_t len)
{
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, header_token, len);
    SHA256_Final(digest, &ctx);
    return nginx_hashcash_module_count_leading_zeros(digest, SHA256_DIGEST_LENGTH);
}

/**
 * validate a single If-Match token.
 * 
 * The token is of the form timestamp-nonce-proof, where timestamp is in epoch.
 */
int16_t nginx_hashcash_module_validate_token(nginx_hashcash_module_check_ctx_t* ctx)
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
    if (nonce == NULL) {
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
    int16_t work = nginx_hashcash_module_get_pow_amount(ctx->header_token, ctx->header_length);
    if (work < ctx->min_work_needed) {
        return NGX_MODULE_HASHCASH_WORK_NEEDED;
    }

    // check if nonce is new
    if (ctx->validate_token_function != NULL) {
        return ctx->validate_token_function(nonce, ctx->max_time_diff);
    }
    return work;
}
