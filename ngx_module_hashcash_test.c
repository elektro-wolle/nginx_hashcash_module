#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>
#include "ngx_module_hashcash.h"

static void test_clz_with_12_zeroes(void** state)
{
    const unsigned char vec[] = { 0x00, 0x08 };
    assert_int_equal(12, ngx_module_hashcash_count_leading_zeros(vec, 2));
}

static void test_clz_without_zeroes(void** state)
{
    const unsigned char vec[] = { 0x80, 0x08 };
    assert_int_equal(0, ngx_module_hashcash_count_leading_zeros(vec, 2));
}

static void test_clz_with_all_zeroes(void** state)
{
    const unsigned char vec[] = { 0x00, 0x00 };
    assert_int_equal(16, ngx_module_hashcash_count_leading_zeros(vec, 2));
}

static void test_clz_with_lsb_set(void** state)
{
    const unsigned char vec[] = { 0x01, 0x00 };
    assert_int_equal(7, ngx_module_hashcash_count_leading_zeros(vec, 2));
}

static void test_calculate_work_no_work(void** state)
{
    const char* header = "1636738046640-d9c38db5a0a74c7e94774e879d24c669-1";
    assert_int_equal(2, ngx_module_hashcash_get_pow_amount(header, strlen(header)));
}

static void test_calculate_work_20(void** state)
{
    const char* header = "1636738046640-d9c38db5a0a74c7e94774e879d24c669-19401";
    assert_int_equal(17, ngx_module_hashcash_get_pow_amount(header, strlen(header)));
}

static void test_check_wrong_header(void** state)
{
    ngx_module_hashcash_check_ctx_t ctx = {
        .check_time = 1,
        .header_token = "foobar",
        .header_length = 6,
        .min_work_needed = 1
    };

    assert_int_equal(NGX_MODULE_HASHCASH_INVALID_HEADER, ngx_module_hashcash_validate_token(&ctx));
}

static void test_check_malformed_header(void** state)
{
    ngx_module_hashcash_check_ctx_t ctx = {
        .check_time = 1,
        .header_token = "asd-foo-bar",
        .header_length = strlen("asd-foo-bar"),
        .min_work_needed = 1
    };

    assert_int_equal(NGX_MODULE_HASHCASH_INVALID_HEADER, ngx_module_hashcash_validate_token(&ctx));
}

static void test_check_expired_header(void** state)
{
    ngx_module_hashcash_check_ctx_t ctx = {
        .check_time = 123456780,
        .max_time_diff = 8,
        .header_token =  "1636738046640-d9c38db5a0a74c7e94774e879d24c669-19401",
        .header_length = strlen("1636738046640-d9c38db5a0a74c7e94774e879d24c669-19401"),
        .min_work_needed = 16
    };

    assert_int_equal(NGX_MODULE_HASHCASH_EXPIRED, ngx_module_hashcash_validate_token(&ctx));
}

static void test_check_non_expired_header(void** state)
{
    ngx_module_hashcash_check_ctx_t ctx = {
        .check_time = 1636738046640,
        .max_time_diff = 8,
        .header_token = "1636738046640-d9c38db5a0a74c7e94774e879d24c669-19401",
        .header_length = strlen("1636738046640-d9c38db5a0a74c7e94774e879d24c669-19401"),
        .min_work_needed = 16
    };

    assert_int_equal(17, ngx_module_hashcash_validate_token(&ctx));
}

int16_t return_duplicate(const char* nonce, int ttl) {
    return NGX_MODULE_HASHCASH_DUPLICATE;
}

static void test_check_duplicated_header(void** state)
{
    ngx_module_hashcash_check_ctx_t ctx = {
        .check_time = 1636738046640,
        .max_time_diff = 8,
        .header_token = "1636738046640-d9c38db5a0a74c7e94774e879d24c669-19401",
        .header_length = strlen("1636738046640-d9c38db5a0a74c7e94774e879d24c669-19401"),
        .min_work_needed = 16,
        .validate_token_function = &return_duplicate
    };

    assert_int_equal(NGX_MODULE_HASHCASH_DUPLICATE, ngx_module_hashcash_validate_token(&ctx));
}

static void test_check_not_enough_work(void** state)
{
    ngx_module_hashcash_check_ctx_t ctx = {
        .check_time = 1636738046640,
        .max_time_diff = 8,
        .header_token = "1636738046640-d9c38db5a0a74c7e94774e879d24c669-1",
        .header_length = strlen("1636738046640-d9c38db5a0a74c7e94774e879d24c669-1"),
        .min_work_needed = 16
    };

    assert_int_equal(NGX_MODULE_HASHCASH_WORK_NEEDED, ngx_module_hashcash_validate_token(&ctx));
}

int main(int argc, char** argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_clz_with_12_zeroes),
        cmocka_unit_test(test_clz_with_all_zeroes),
        cmocka_unit_test(test_clz_without_zeroes),
        cmocka_unit_test(test_clz_with_lsb_set),
        cmocka_unit_test(test_calculate_work_no_work),
        cmocka_unit_test(test_calculate_work_20),
        cmocka_unit_test(test_check_wrong_header),
        cmocka_unit_test(test_check_malformed_header),
        cmocka_unit_test(test_check_expired_header),
        cmocka_unit_test(test_check_non_expired_header),
        cmocka_unit_test(test_check_not_enough_work),
        cmocka_unit_test(test_check_duplicated_header),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
