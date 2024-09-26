//
// Created on 2024/9/26.
//
// Node APIs are not fully supported. To solve the compilation error of the interface cannot be found,
// please include "napi/native_api.h".

#ifndef TOTPTOKEN_SHA1_H
#define TOTPTOKEN_SHA1_H
#include <inttypes.h>

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

void init(void);
void initHmac(const uint8_t* secret, uint8_t secretLength);
uint8_t* result(void);
uint8_t* resultHmac(void);
void write(uint8_t);
void writeArray(uint8_t *buffer, uint8_t size);
#endif //TOTPTOKEN_SHA1_H
