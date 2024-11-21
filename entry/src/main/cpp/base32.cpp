#include <cstddef>
#include <stdlib.h>
#include <string.h>
#include "base32.h"

#define BITS_PER_BYTE               8
#define BITS_PER_B32_BLOCK          5

// 64 MB should be more than enough
#define MAX_ENCODE_INPUT_LEN        (64*1024*1024)

// if 64 MB of data is encoded than it should be also possible to decode it. That's why a bigger input is allowed for decoding
#define MAX_DECODE_BASE32_INPUT_LEN ((MAX_ENCODE_INPUT_LEN * 8 + 4) / 5)

const uint8_t b32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int           get_char_index (uint8_t        c);

static bool          valid_b32_str (const char *str);

static bool          has_space      (const char *str);

static cotp_error_t  check_input    (const uint8_t *user_data,
                                     size_t         data_len,
                                     int32_t        max_len);

static int           strip_char     (char          *str);


// The encoding process represents 40-bit groups of input bits as output strings of 8 encoded characters. The input data must be null terminated.
char *
base32_encode (const uint8_t *user_data,
               size_t         data_len,
               cotp_error_t  *err_code)
{
    cotp_error_t error = check_input (user_data, data_len, MAX_ENCODE_INPUT_LEN);
    if (error == EMPTY_STRING) {
        *err_code = error;
        return strdup ("");
    }
    if (error != NO_ERROR) {
        *err_code = error;
        return NULL;
    }

    size_t user_data_chars = 0, total_bits = 0;
    int num_of_equals = 0;
    int null_terminated = false;
    if (strlen ((char *)user_data) == data_len - 1) {
        // the user might give the input with the null byte, we need to check for that
        null_terminated = true;
    }
    for (int i = 0; i < data_len; i++) {
        if (null_terminated == true && user_data[i] == '\0' && i == data_len-1) {
            break;
        }
        total_bits += 8;
        user_data_chars += 1;
    }
    switch (total_bits % 40) {
        case 8:  num_of_equals = 6; break;
        case 16: num_of_equals = 4; break;
        case 24: num_of_equals = 3; break;
        case 32: num_of_equals = 1; break;
    }

    size_t output_length = (user_data_chars * 8 + 4) / 5;
    char *encoded_data = (char *)calloc (output_length + num_of_equals + 1, 1);
    if (encoded_data == NULL) {
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    for (int i = 0, j = 0; i < user_data_chars; i += 5) {
        uint64_t quintuple = 0;

        for (int k = 0; k < 5; k++) {
            quintuple = (quintuple << 8) | (i + k < user_data_chars ? user_data[i + k] : 0);
        }

        for (int shift = 35; shift >= 0; shift -= 5) {
            encoded_data[j++] = (char)b32_alphabet[(quintuple >> shift) & 0x1F];
        }
    }

    for (int i = 0; i < num_of_equals; i++) {
        encoded_data[output_length + i] = '=';
    }
    encoded_data[output_length + num_of_equals] = '\0';

    *err_code = NO_ERROR;

    return encoded_data;
}


uint8_t *base32_decode(const char *user_data_untrimmed, size_t data_len, size_t *raw_len, cotp_error_t *err_code)
{
    cotp_error_t error = check_input((uint8_t *)user_data_untrimmed, data_len, MAX_DECODE_BASE32_INPUT_LEN);
    if (error == EMPTY_STRING) {
        *err_code = error;
        return (uint8_t *)strdup ("");
    }
    if (error != NO_ERROR) {
        *err_code = error;
        return NULL;
    }

    char *user_data = strdup (user_data_untrimmed);
    if (user_data == NULL) {
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }
    data_len -= strip_char (user_data);

    if (!is_string_valid_b32 (user_data)) {
        free (user_data);
        *err_code = INVALID_B32_INPUT;
        return NULL;
    }

    size_t user_data_chars = 0;
    for (int i = 0; i < data_len; i++) {
        // As it's not known whether data_len is with or without the +1 for the null byte, a manual check is required.
        if (user_data[i] != '=' && user_data[i] != '\0') {
            user_data_chars += 1;
        }
    }

    size_t output_length = (size_t)((user_data_chars + 1.6 + 1) / 1.6);  // round up
    *raw_len = output_length;
    uint8_t *decoded_data = (uint8_t *)calloc(output_length + 1, 1);
    if (decoded_data == NULL) {
        free (user_data);
        *err_code = MEMORY_ALLOCATION_ERROR;
        return NULL;
    }

    uint8_t mask, current_byte = 0;
    int bits_left = 8;
    for (int i = 0, j = 0; i < user_data_chars; i++) {
        int char_index = get_char_index ((uint8_t)user_data[i]);
        if (bits_left > BITS_PER_B32_BLOCK) {
            mask = (uint8_t)char_index << (bits_left - BITS_PER_B32_BLOCK);
            current_byte |= mask;
            bits_left -= BITS_PER_B32_BLOCK;
        } else {
            mask = (uint8_t)char_index >> (BITS_PER_B32_BLOCK - bits_left);
            current_byte |= mask;
            decoded_data[j++] = current_byte;
            current_byte = (uint8_t) (char_index << (BITS_PER_BYTE - BITS_PER_B32_BLOCK + bits_left));
            bits_left += BITS_PER_BYTE - BITS_PER_B32_BLOCK;
        }
    }
    decoded_data[output_length-1] = '\0';

    free (user_data);

    *err_code = NO_ERROR;

    return decoded_data;
}


bool
is_string_valid_b32 (const char *user_data)
{
    if (user_data == NULL) {
        return false;
    }

    if (has_space (user_data)) {
        char *trimmed = strdup (user_data);
        if (trimmed == NULL) {
            return false;
        }
        strip_char (trimmed);
        bool valid = valid_b32_str (trimmed);
        free(trimmed);
        return valid;
    }

    return valid_b32_str (user_data);
}


static bool
valid_b32_str (const char *str)
{
    if (str == NULL) {
        return false;
    }

    uint8_t table[128] = {0};
    for (const uint8_t *p = b32_alphabet; *p; p++) {
        table[*p] = 1;
    }
    table['='] = 1;

    while (*str) {
        if (!table[(uint8_t)*str]) {
            return false;
        }
        str++;
    }

    return true;
}


static bool
has_space (const char *str)
{
    while (*str) {
        if (*str == ' ') {
            return true;
        }
        str++;
    }
    return false;
}


static int
get_char_index (uint8_t c)
{
    for (int i = 0; i < sizeof(b32_alphabet); i++) {
        if (b32_alphabet[i] == c) {
            return i;
        }
    }
    return -1;
}


static int
strip_char (char *str)
{
    const char strip = ' ';
    uint8_t table[128] = {0};
    table[(uint8_t)strip] = 1;

    int found = 0;
    char *p, *q;
    for (q = p = str; *p; p++) {
        if (!table[*(uint8_t *)p]) {
            *q++ = *p;
        } else {
            found++;
        }
    }
    *q = '\0';
    return found;
}


static cotp_error_t
check_input (const uint8_t *user_data,
             size_t         data_len,
             int32_t        max_len)
{
    if (!user_data || data_len > max_len) {
        return INVALID_USER_INPUT;
    }

    if (data_len == 0) {
        return EMPTY_STRING;
    }

    return NO_ERROR;
}