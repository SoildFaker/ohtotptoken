#include "napi/native_api.h"
#include "hilog/log.h"

#include <cstring>
#include <js_native_api.h>
#include <js_native_api_types.h>

#include "totp.h"
#include "base32.h"

#define MAKE_FILE_NAME (strrchr(__FILE__, '/') + 1)

#define TOTP_LOG_ENABLE 0

#define TOTP_LOGE(fmt, ...) if (TOTP_LOG_ENABLE)                                                                             \
    OH_LOG_Print(LOG_APP, LOG_ERROR, 0x15b0, "TOTP-MCU", "TOTP [%{public}s %{public}d] " fmt, MAKE_FILE_NAME,  \
                 __LINE__, ##__VA_ARGS__)

#define TOTP_LOGI(fmt, ...) if (TOTP_LOG_ENABLE)                                                                             \
    OH_LOG_Print(LOG_APP, LOG_INFO, 0x15b0, "TOTP-MCU", "TOTP [%{public}s %{public}d] " fmt, MAKE_FILE_NAME,   \
                 __LINE__, ##__VA_ARGS__)

#define TOTP_LOGD(fmt, ...) if (TOTP_LOG_ENABLE)                                                                             \
    OH_LOG_Print(LOG_APP, LOG_DEBUG, 0x15b0, "TOTP-MCU", "TOTP [%{public}s %{public}d] " fmt, MAKE_FILE_NAME,  \
                 __LINE__, ##__VA_ARGS__)


static napi_value generateTOTP(napi_env env, napi_callback_info info)
{
    size_t numArgs = 5;
    size_t argc = numArgs;
    napi_value args[5] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    uint32_t key_len = 16;
    napi_get_value_uint32(env, args[1], &key_len);
    
    size_t str_size_read;
    uint8_t* key_buf;
    key_buf = (uint8_t*)calloc(key_len + 1, sizeof(uint8_t));
    napi_get_value_string_utf8(env, args[0], (char *)key_buf, (size_t)key_len + 1, &str_size_read);
    
    uint32_t digits = 6;
    napi_get_value_uint32(env, args[2], &digits);
    
    uint32_t period = 30;
    napi_get_value_uint32(env, args[3], &period);
    
    uint32_t timestamp = 0;
    napi_get_value_uint32(env, args[4], &timestamp);
    cotp_error_t err_code;
    
    uint8_t* key_raw = base32_decode((const char *)key_buf, key_len, &err_code);
    uint32_t key_raw_len = key_len;
    
    TOTP_LOGD("key_raw:%{public}s, key_raw_len:%{public}d",
        key_raw, key_raw_len
    );
    
    uint32_t code = 0;
    
    if (err_code == NO_ERROR) {
    
        totp(key_raw, (uint8_t)key_raw_len, period);
        code = getCodeFromTimestamp(timestamp, digits);
        
        TOTP_LOGI("key_buf:%{public}s, key_len:%{public}d, period: %{public}d, digits: %{public}d, timestamp: %{public}d, token: %{public}d",
            key_buf, key_len, period, digits, timestamp, code
        );
        
        free((void *)key_raw);
    } else {
        TOTP_LOGE("decode error: %{public}d", err_code);
    }
    
    free((void *)key_buf);
    
    napi_value token;
    napi_create_uint32(env, code, &token);
    return token;
}

static napi_value generateHOTP(napi_env env, napi_callback_info info) {
    size_t numArgs = 5;
    size_t argc = numArgs;
    napi_value args[5] = {nullptr};
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    
    uint32_t key_len = 16;
    napi_get_value_uint32(env, args[1], &key_len);
    
    size_t str_size_read;
    uint8_t* key_buf;
    key_buf = (uint8_t*)calloc(key_len + 1, sizeof(uint8_t));
    napi_get_value_string_utf8(env, args[0], (char *)key_buf, (size_t)key_len + 1, &str_size_read);
    
    uint32_t digits = 6;
    napi_get_value_uint32(env, args[2], &digits);
    
    uint32_t init_counter = 30;
    napi_get_value_uint32(env, args[3], &init_counter);
    
    uint32_t counter = 0;
    napi_get_value_uint32(env, args[4], &counter);
    cotp_error_t err_code;
    
    uint8_t* key_raw = base32_decode((const char *)key_buf, key_len, &err_code);
    uint32_t key_raw_len = key_len;
    
    TOTP_LOGD("key_raw:%{public}s, key_raw_len:%{public}d",
        key_raw, key_raw_len
    );
    
    uint32_t code = 0;
    
    if (err_code == NO_ERROR) {
    
        hotp(key_raw, (uint8_t)key_raw_len, init_counter);
        code = getCodeFromCounter(counter, digits);
        
        TOTP_LOGI("key_buf:%{public}s, key_len:%{public}d, init_counter: %{public}d, digits: %{public}d, counter: %{public}d, token: %{public}d",
            key_buf, key_len, init_counter, digits, counter, code
        );
        
        free((void *)key_raw);
    } else {
        TOTP_LOGE("decode error: %{public}d", err_code);
    }
    
    free((void *)key_buf);
    
    napi_value token;
    napi_create_uint32(env, code, &token);
    return token;
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"generateTOTP", nullptr, generateTOTP, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"generateHOTP", nullptr, generateHOTP, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module totp_mcu = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "totp_mcu",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterEntryModule(void)
{
    TOTP_LOGI("%{public}s", "totp_mcu registed!");
    napi_module_register(&totp_mcu);
}
