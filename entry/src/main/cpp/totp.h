#ifndef TOTPTOKEN_TOTP_H
#define TOTPTOKEN_TOTP_H
#include <inttypes.h>
#include "time.h"

void totp(uint8_t* hmacKey, uint8_t keyLength, uint32_t timeStep);
void hotp(uint8_t* hmacKey, uint8_t keyLength, uint32_t initCounter);
void setTimezone(uint8_t timezone);
uint32_t getCodeFromTimestamp(uint32_t timeStamp, uint32_t digits);
uint32_t getCodeFromTimeStruct(struct tm time, uint32_t digits);
uint32_t getCodeFromCounter(uint32_t counter, uint32_t digits);
uint32_t getCodeFromSteps(uint32_t steps, uint32_t digits);

#endif //TOTPTOKEN_TOTP_H
