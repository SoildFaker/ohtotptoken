//
// Created on 2024/11/20.
//
// Node APIs are not fully supported. To solve the compilation error of the interface cannot be found,
// please include "napi/native_api.h".

#include "base32.cpp"
#include "napi/native_api.h"
#include "hilog/log.h"

#include <string>
#include <js_native_api.h>
#include <js_native_api_types.h>

#include <stdlib.h>

#include "pb_encode.h"
#include "pb_decode.h"
#include "google_auth.pb.h"
#include "base32.h"

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') + 1)

#define CUTILS_LOG_ENABLE 1

#define CUTILS_LOGE(fmt, ...) if (CUTILS_LOG_ENABLE)                                                           \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b0, "CUTILS", "CUTILS [%{public}s %{public}d] " fmt, MAKE_FILE_NAME,  \
                 __LINE__, ##__VA_ARGS__)

#define CUTILS_LOGI(fmt, ...) if (CUTILS_LOG_ENABLE)                                                           \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b0, "CUTILS", "CUTILS [%{public}s %{public}d] " fmt, MAKE_FILE_NAME,   \
                 __LINE__, ##__VA_ARGS__)

#define CUTILS_LOGD(fmt, ...) if (CUTILS_LOG_ENABLE)                                                           \
    OH_LOG_Print(LOG_APP, LOG_DEBUG, 0x15b0, "CUTILS", "CUTILS [%{public}s %{public}d] " fmt, MAKE_FILE_NAME,  \
                 __LINE__, ##__VA_ARGS__)


std::string google_auth_json = "";

/**
decode callback
 **/
bool decode_string(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    uint8_t buffer[1024] = {0};
    
    /* We could read block-by-block to avoid the large buffer... */
    if (stream->bytes_left > sizeof(buffer) - 1)
        return false;
    
    if (!pb_read(stream, buffer, stream->bytes_left))
        return false;
    
    google_auth_json += "\"";
    google_auth_json += (char *)*arg;
    google_auth_json += "\":\"";
    google_auth_json += (char *)buffer;
    google_auth_json += "\",";
    return true;
}

bool decode_bytes(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    uint8_t buffer[1024] = {0};
    
    /* We could read block-by-block to avoid the large buffer... */
    size_t length = stream->bytes_left;
    if (stream->bytes_left > sizeof(buffer) - 1)
        return false;
    
    if (!pb_read(stream, buffer, stream->bytes_left))
        return false;
    
    cotp_error_t err;
    char * b32code = base32_encode(buffer, length, &err);
    google_auth_json += "\"";
    google_auth_json += (char *)*arg;
    google_auth_json += "\":\"";
    google_auth_json += b32code;
    google_auth_json += "\",";
    return true;
}

bool decode_otp_parameters(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    googleauth_MigrationPayload_OtpParameters message = googleauth_MigrationPayload_OtpParameters_init_zero;
    
    google_auth_json += "{";
    /* Now we are ready to decode the message. */
    message.secret.funcs.decode = decode_bytes;
    message.secret.arg = (void *)"secret";
    message.issuer.funcs.decode = decode_string;
    message.issuer.arg = (void *)"issuer";
    message.name.funcs.decode = decode_string;
    message.name.arg = (void *)"name";
    bool status = pb_decode(stream, googleauth_MigrationPayload_OtpParameters_fields, &message);
    google_auth_json += "\"digits\":";
    google_auth_json += std::to_string(message.digits);
    google_auth_json += ",\"counter\":";
    google_auth_json += std::to_string(message.counter);
    google_auth_json += ",\"algorithm\":";
    google_auth_json += std::to_string(message.algorithm);
    google_auth_json += ",\"type\":";
    google_auth_json += std::to_string(message.type);
    google_auth_json += "},";
    return status;
}

const char base46_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                           'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                           'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                           'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

char* base64_decode(char* cipher) {

    char counts = 0;
    char buffer[4];
    char* plain = (char *)malloc(strlen(cipher) * 3 / 4);
    int i = 0, p = 0;

    for(i = 0; cipher[i] != '\0'; i++) {
        char k;
        for(k = 0 ; k < 64 && base46_map[k] != cipher[i]; k++);
        buffer[counts++] = k;
        if(counts == 4) {
            plain[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
            if(buffer[2] != 64)
                plain[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
            if(buffer[3] != 64)
                plain[p++] = (buffer[2] << 6) + buffer[3];
            counts = 0;
        }
    }

    plain[p] = '\0';    /* string padding character */
    return plain;
}

static napi_value decode_google_auth_pb(napi_env env, napi_callback_info info) {
    size_t numArgs = 1;
    size_t argc = numArgs;
    napi_value args[1] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    constexpr int buffer_size = 8192;

    uint8_t buffer[buffer_size];
    size_t buffer_length;
    bool status;
    
    napi_get_value_string_utf8(env, args[0], (char *)buffer, buffer_size, &buffer_length);
    
    uint8_t *message_pb = (uint8_t *)base64_decode((char *)buffer);
    size_t message_length = buffer_length*3/4;
    for (int i = 0; i < 3; i++) {
        if (buffer[buffer_length-1-i] == '=') {
            message_length--;
        }
    }
    
    google_auth_json = "[";

    {
        /* Allocate space for the decoded message. */
        googleauth_MigrationPayload message = googleauth_MigrationPayload_init_zero;
        
        /* Create a stream that reads from the buffer. */
        pb_istream_t stream = pb_istream_from_buffer(message_pb, message_length);
        
        /* Now we are ready to decode the message. */
        message.otp_parameters.funcs.decode = decode_otp_parameters;
        status = pb_decode(&stream, googleauth_MigrationPayload_fields, &message);
        
        /* Check for errors... */
        if (!status) {
            CUTILS_LOGE("Decoding failed: %{public}s", PB_GET_ERROR(&stream));
        }
        CUTILS_LOGI("version: %{public}d", message.version);
    }
    google_auth_json.pop_back();
    google_auth_json += "]";
    
    napi_value result;
    napi_create_string_utf8(env, google_auth_json.c_str(), google_auth_json.size(), &result);
    return result;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"decode_google_auth_pb", nullptr, decode_google_auth_pb, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module otpcutils = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "otpcutils",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void)
{
    CUTILS_LOGI("%{public}s", "otpcutils registed!");
    napi_module_register(&otpcutils);
}