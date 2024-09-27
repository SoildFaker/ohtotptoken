
#ifndef _LIBBASE32_BASE32_H
#define _LIBBASE32_BASE32_H
#include <inttypes.h>
#include <stdlib.h>

typedef enum cotp_error {
    NO_ERROR = 0,
    VALID,
    WCRYPT_VERSION_MISMATCH,
    INVALID_B32_INPUT,
    INVALID_ALGO,
    INVALID_DIGITS,
    INVALID_PERIOD,
    MEMORY_ALLOCATION_ERROR,
    INVALID_USER_INPUT,
    EMPTY_STRING,
    MISSING_LEADING_ZERO,
    INVALID_COUNTER,
    WHMAC_ERROR
} cotp_error_t;

uint8_t *base32_decode (const char *user_data_untrimmed, size_t data_len, cotp_error_t *err_code);
bool is_string_valid_b32 (const char *user_data);

#endif //LIBBASE32_BASE32_H