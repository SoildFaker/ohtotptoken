/* Automatically generated nanopb header */
/* Generated by nanopb-1.0.0-dev */

#ifndef PB_GOOGLEAUTH_GOOGLE_AUTH_PB_H_INCLUDED
#define PB_GOOGLEAUTH_GOOGLE_AUTH_PB_H_INCLUDED
#include <pb.h>

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Enum definitions */
typedef enum _googleauth_MigrationPayload_Algorithm {
    googleauth_MigrationPayload_Algorithm_ALGORITHM_UNSPECIFIED = 0,
    googleauth_MigrationPayload_Algorithm_SHA1 = 1,
    googleauth_MigrationPayload_Algorithm_SHA256 = 2,
    googleauth_MigrationPayload_Algorithm_SHA512 = 3,
    googleauth_MigrationPayload_Algorithm_MD5 = 4
} googleauth_MigrationPayload_Algorithm;

typedef enum _googleauth_MigrationPayload_DigitCount {
    googleauth_MigrationPayload_DigitCount_DIGIT_COUNT_UNSPECIFIED = 0,
    googleauth_MigrationPayload_DigitCount_SIX = 1,
    googleauth_MigrationPayload_DigitCount_EIGHT = 2,
    googleauth_MigrationPayload_DigitCount_SEVEN = 3
} googleauth_MigrationPayload_DigitCount;

typedef enum _googleauth_MigrationPayload_OtpType {
    googleauth_MigrationPayload_OtpType_OTP_TYPE_UNSPECIFIED = 0,
    googleauth_MigrationPayload_OtpType_HOTP = 1,
    googleauth_MigrationPayload_OtpType_TOTP = 2
} googleauth_MigrationPayload_OtpType;

/* Struct definitions */
typedef struct _googleauth_MigrationPayload {
    pb_callback_t otp_parameters;
    int32_t version;
    int32_t batch_size;
    int32_t batch_index;
    int32_t batch_id;
} googleauth_MigrationPayload;

typedef struct _googleauth_MigrationPayload_OtpParameters {
    pb_callback_t secret;
    pb_callback_t name;
    pb_callback_t issuer;
    googleauth_MigrationPayload_Algorithm algorithm;
    googleauth_MigrationPayload_DigitCount digits;
    googleauth_MigrationPayload_OtpType type;
    int64_t counter;
    pb_callback_t unique_id;
} googleauth_MigrationPayload_OtpParameters;


#ifdef __cplusplus
extern "C" {
#endif

/* Helper constants for enums */
#define _googleauth_MigrationPayload_Algorithm_MIN googleauth_MigrationPayload_Algorithm_ALGORITHM_UNSPECIFIED
#define _googleauth_MigrationPayload_Algorithm_MAX googleauth_MigrationPayload_Algorithm_MD5
#define _googleauth_MigrationPayload_Algorithm_ARRAYSIZE ((googleauth_MigrationPayload_Algorithm)(googleauth_MigrationPayload_Algorithm_MD5+1))

#define _googleauth_MigrationPayload_DigitCount_MIN googleauth_MigrationPayload_DigitCount_DIGIT_COUNT_UNSPECIFIED
#define _googleauth_MigrationPayload_DigitCount_MAX googleauth_MigrationPayload_DigitCount_SEVEN
#define _googleauth_MigrationPayload_DigitCount_ARRAYSIZE ((googleauth_MigrationPayload_DigitCount)(googleauth_MigrationPayload_DigitCount_SEVEN+1))

#define _googleauth_MigrationPayload_OtpType_MIN googleauth_MigrationPayload_OtpType_OTP_TYPE_UNSPECIFIED
#define _googleauth_MigrationPayload_OtpType_MAX googleauth_MigrationPayload_OtpType_TOTP
#define _googleauth_MigrationPayload_OtpType_ARRAYSIZE ((googleauth_MigrationPayload_OtpType)(googleauth_MigrationPayload_OtpType_TOTP+1))


#define googleauth_MigrationPayload_OtpParameters_algorithm_ENUMTYPE googleauth_MigrationPayload_Algorithm
#define googleauth_MigrationPayload_OtpParameters_digits_ENUMTYPE googleauth_MigrationPayload_DigitCount
#define googleauth_MigrationPayload_OtpParameters_type_ENUMTYPE googleauth_MigrationPayload_OtpType


/* Initializer values for message structs */
#define googleauth_MigrationPayload_init_default {{{NULL}, NULL}, 0, 0, 0, 0}
#define googleauth_MigrationPayload_OtpParameters_init_default {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, _googleauth_MigrationPayload_Algorithm_MIN, _googleauth_MigrationPayload_DigitCount_MIN, _googleauth_MigrationPayload_OtpType_MIN, 0, {{NULL}, NULL}}
#define googleauth_MigrationPayload_init_zero    {{{NULL}, NULL}, 0, 0, 0, 0}
#define googleauth_MigrationPayload_OtpParameters_init_zero {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, _googleauth_MigrationPayload_Algorithm_MIN, _googleauth_MigrationPayload_DigitCount_MIN, _googleauth_MigrationPayload_OtpType_MIN, 0, {{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define googleauth_MigrationPayload_otp_parameters_tag 1
#define googleauth_MigrationPayload_version_tag  2
#define googleauth_MigrationPayload_batch_size_tag 3
#define googleauth_MigrationPayload_batch_index_tag 4
#define googleauth_MigrationPayload_batch_id_tag 5
#define googleauth_MigrationPayload_OtpParameters_secret_tag 1
#define googleauth_MigrationPayload_OtpParameters_name_tag 2
#define googleauth_MigrationPayload_OtpParameters_issuer_tag 3
#define googleauth_MigrationPayload_OtpParameters_algorithm_tag 4
#define googleauth_MigrationPayload_OtpParameters_digits_tag 5
#define googleauth_MigrationPayload_OtpParameters_type_tag 6
#define googleauth_MigrationPayload_OtpParameters_counter_tag 7
#define googleauth_MigrationPayload_OtpParameters_unique_id_tag 8

/* Struct field encoding specification for nanopb */
#define googleauth_MigrationPayload_FIELDLIST(X, a) \
X(a, CALLBACK, REPEATED, MESSAGE,  otp_parameters,    1) \
X(a, STATIC,   SINGULAR, INT32,    version,           2) \
X(a, STATIC,   SINGULAR, INT32,    batch_size,        3) \
X(a, STATIC,   SINGULAR, INT32,    batch_index,       4) \
X(a, STATIC,   SINGULAR, INT32,    batch_id,          5)
#define googleauth_MigrationPayload_CALLBACK pb_default_field_callback
#define googleauth_MigrationPayload_DEFAULT NULL
#define googleauth_MigrationPayload_otp_parameters_MSGTYPE googleauth_MigrationPayload_OtpParameters

#define googleauth_MigrationPayload_OtpParameters_FIELDLIST(X, a) \
X(a, CALLBACK, SINGULAR, BYTES,    secret,            1) \
X(a, CALLBACK, SINGULAR, STRING,   name,              2) \
X(a, CALLBACK, SINGULAR, STRING,   issuer,            3) \
X(a, STATIC,   SINGULAR, UENUM,    algorithm,         4) \
X(a, STATIC,   SINGULAR, UENUM,    digits,            5) \
X(a, STATIC,   SINGULAR, UENUM,    type,              6) \
X(a, STATIC,   SINGULAR, INT64,    counter,           7) \
X(a, CALLBACK, SINGULAR, STRING,   unique_id,         8)
#define googleauth_MigrationPayload_OtpParameters_CALLBACK pb_default_field_callback
#define googleauth_MigrationPayload_OtpParameters_DEFAULT NULL

extern const pb_msgdesc_t googleauth_MigrationPayload_msg;
extern const pb_msgdesc_t googleauth_MigrationPayload_OtpParameters_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define googleauth_MigrationPayload_fields &googleauth_MigrationPayload_msg
#define googleauth_MigrationPayload_OtpParameters_fields &googleauth_MigrationPayload_OtpParameters_msg

/* Maximum encoded size of messages (where known) */
/* googleauth_MigrationPayload_size depends on runtime parameters */
/* googleauth_MigrationPayload_OtpParameters_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif