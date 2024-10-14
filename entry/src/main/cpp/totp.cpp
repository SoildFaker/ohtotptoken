#include "totp.h"
#include "sha1.h"

uint8_t* _hmacKey;
uint8_t _keyLength;
uint8_t _timeZoneOffset;
uint32_t _timeStep;
uint32_t _initCounter;

// Init the library with the private key, its length and the timeStep duration
void totp(uint8_t* hmacKey, uint8_t keyLength, uint32_t timeStep) {
    _hmacKey = hmacKey;
    _keyLength = keyLength;
    _timeStep = timeStep;
}

void hotp(uint8_t* hmacKey, uint8_t keyLength, uint32_t initCounter) {
    _hmacKey = hmacKey;
    _keyLength = keyLength;
    _initCounter = initCounter;
}

void setTimezone(uint8_t timezone){
    _timeZoneOffset = timezone;
}

uint32_t TimeStruct2Timestamp(struct tm time){
    //time.tm_mon -= 1;
    //time.tm_year -= 1900;
    return mktime(&(time)) - (_timeZoneOffset * 3600) - 2208988800;
}

// Generate a code, using the timestamp provided
uint32_t getCodeFromTimestamp(uint32_t timeStamp, uint32_t digits) {
    uint32_t steps = timeStamp / _timeStep;
    return getCodeFromSteps(steps, digits);
}

// Generate a code, using the timestamp provided
uint32_t getCodeFromTimeStruct(struct tm time, uint32_t digits) {
    return getCodeFromTimestamp(TimeStruct2Timestamp(time), digits);
}

uint32_t getCodeFromCounter(uint32_t counter, uint32_t digits) {
    return getCodeFromSteps(_initCounter + counter, digits);
}

// Generate a code, using the number of steps provided
uint32_t getCodeFromSteps(uint32_t steps, uint32_t digits) {
    // STEP 0, map the number of steps in a 8-bytes array (counter value)
    uint8_t _byteArray[8];
    _byteArray[0] = 0x00;
    _byteArray[1] = 0x00;
    _byteArray[2] = 0x00;
    _byteArray[3] = 0x00;
    _byteArray[4] = (uint8_t)((steps >> 24) & 0xFF);
    _byteArray[5] = (uint8_t)((steps >> 16) & 0xFF);
    _byteArray[6] = (uint8_t)((steps >> 8) & 0XFF);
    _byteArray[7] = (uint8_t)((steps & 0XFF));

    // STEP 1, get the HMAC-SHA1 hash from counter and key
    initHmac(_hmacKey, _keyLength);
    writeArray(_byteArray, 8);
    uint8_t* _hash = resultHmac();

    // STEP 2, apply dynamic truncation to obtain a 4-bytes string
    uint32_t _truncatedHash = 0;
    uint8_t _offset = _hash[20 - 1] & 0xF;
    uint8_t j;
    for (j = 0; j < 4; ++j) {
        _truncatedHash <<= 8;
        _truncatedHash  |= _hash[_offset + j];
    }

    // STEP 3, compute the OTP value
    _truncatedHash &= 0x7FFFFFFF;    //Disabled
    if (digits < 10) {
        uint32_t filter = 1;
        for (size_t i = 0; i < digits; i++) {
            filter *= 10;
        }
        _truncatedHash %= filter;
    }
    
    return _truncatedHash;
}