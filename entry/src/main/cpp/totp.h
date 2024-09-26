//
// Created on 2024/9/26.
//
// Node APIs are not fully supported. To solve the compilation error of the interface cannot be found,
// please include "napi/native_api.h".

#ifndef TOTPTOKEN_TOTP_H
#define TOTPTOKEN_TOTP_H
#include <inttypes.h>
#include "time.h"

void totp(uint8_t* hmacKey, uint8_t keyLength, uint32_t timeStep);
void setTimezone(uint8_t timezone);
uint32_t getCodeFromTimestamp(uint32_t timeStamp, uint32_t digits);
uint32_t getCodeFromTimeStruct(struct tm time, uint32_t digits);
uint32_t getCodeFromSteps(uint32_t steps, uint32_t digits);

#endif //TOTPTOKEN_TOTP_H
