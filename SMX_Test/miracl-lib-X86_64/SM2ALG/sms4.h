#ifndef NIST_SMS4_H
#define NIST_SMS4_H

#include <stdio.h>
#include <string.h>

//密钥128bits 数据分组128bits

#ifndef uint32_t
#define uint32_t unsigned int
#endif

#ifndef uint8_t
#define uint8_t unsigned char
#endif

#ifdef __cplusplus
extern "C" {
#endif

void SMS4_encrypt(const unsigned char *in, unsigned char *out, const unsigned char *key);
void SMS4_decrypt(const unsigned char *in, unsigned char *out, const unsigned char *key);


#ifdef __cplusplus
}
#endif


#endif
