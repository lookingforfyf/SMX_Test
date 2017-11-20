#ifndef NIST_SM2_H
#define NIST_SM2_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miracl.h"
#include "mirdef.h"

#include "sm3.h"

#define ERR_INFINITY_POINT    0x00000001
#define ERR_NOT_VALID_ELEMENT 0x00000002
#define ERR_NOT_VALID_POINT   0x00000003
#define ERR_ORDER             0x00000004
#define ERR_ECURVE_INIT       0x00000005
#define ERR_KEYEX_RA          0x00000006
#define ERR_KEYEX_RB          0x00000007
#define ERR_EQUAL_S1SB        0x00000008
#define ERR_EQUAL_S2SA        0x00000009
#define ERR_SELFTEST_Z        0x0000000A
#define ERR_SELFTEST_INI_I    0x0000000B
#define ERR_SELFTEST_RES_I    0x0000000C
#define ERR_SELFTEST_INI_II   0x0000000D
#define ERR_GENERATE_R        0x0000000E
#define ERR_GENERATE_S        0x0000000F
#define ERR_OUTRANGE_R        0x00000010
#define ERR_OUTRANGE_S        0x00000011
#define ERR_GENERATE_T        0x00000012
#define ERR_PUBKEY_INIT       0x00000013
#define ERR_DATA_MEMCMP       0x00000014
#define ERR_ARRAY_NULL        0x00000015
#define ERR_C3_MATCH          0x00000016
#define ERR_SELFTEST_KG       0x00000017
#define ERR_SELFTEST_ENC      0x00000018
#define ERR_SELFTEST_DEC      0x00000019

#define SM2_WORDSIZE 8
#define SM2_NUMBITS 256
#define SM2_NUMWORD	(SM2_NUMBITS / SM2_WORDSIZE) //32


#ifdef __cplusplus
extern "C" {
#endif

int SM2_standard_init(void);
int Test_Point(epoint* point);
int Test_PubKey(epoint *pubKey);
int Test_PrivKey(unsigned char privkey[]);
int Test_Range(big x);
int Test_Null(unsigned char array[], int len);
int Test_Zero(big x);
int Test_n(big x);
void SM3_kdf(unsigned char Z[], unsigned short zlen, unsigned short klen, unsigned char K[]);
int SM2_keygeneration_1(big priKey, epoint *pubKey);
int SM2_standard_encrypt(unsigned char* randK, epoint *pubKey, unsigned char M[], int klen, unsigned char C[]);
int SM2_standard_encrypt_2(unsigned char* randK, unsigned char px[], unsigned char py[], unsigned char M[], int klen, unsigned char C[]);
int SM2_standard_decrypt(big dB, unsigned char C[], int Clen, unsigned char M[]);
int SM2_standard_decrypt_2(unsigned char privkey[], unsigned char C[], int Clen, unsigned char M[]);
int SM2_enc_selftest();
int SM2_keygeneration_2(unsigned char PriKey[], unsigned char Px[], unsigned char Py[]);
void SM2_pre_ZA(unsigned char Px[], unsigned char Py[], unsigned char ZA[]);
int SM2_standard_sign(unsigned char *message, int len, unsigned char ZA[], unsigned char rand[], unsigned char d[], unsigned char R[], unsigned char S[]);
int SM2_standard_verify(unsigned char *message, int len, unsigned char ZA[], unsigned char Px[], unsigned char Py[], unsigned char R[], unsigned char S[]);
int SM2_sign_selftest();
int SM2_w(big n);
void SM3_z(unsigned char ID[], unsigned short int ELAN, epoint* pubKey, unsigned char hash[]);
int SM2_standard_keyex_init_i(big ra, epoint* RA);
int SM2_standard_keyex_re_i(big rb, big dB, epoint* RA, epoint* PA, unsigned char ZA[], unsigned char ZB[], unsigned char K[], int klen, epoint* RB, epoint* V, unsigned char hash[]);
int SM2_standard_keyex_init_ii(big ra, big dA, epoint* RA, epoint* RB, epoint* PB, unsigned char ZA[], unsigned char ZB[], unsigned char SB[], unsigned char K[], int klen, unsigned char SA[]);
int SM2_standard_keyex_re_ii(epoint *V, epoint *RA, epoint *RB, unsigned char ZA[], unsigned char ZB[], unsigned char SA[]);
int SM2_standard_keyex_selftest();


#ifdef __cplusplus
}
#endif



#endif
