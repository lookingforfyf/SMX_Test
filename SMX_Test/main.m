//
//  main.m
//  SMX_Test
//
//  Created by 范云飞 on 2017/11/20.
//  Copyright © 2017年 范云飞. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "sm2alg.h"
int main(int argc, const char * argv[]) {
    @autoreleasepool {
#pragma mark - SM2签名验签&&加密解密
        char* c_error[2] = {"error", "pass"};
        char* error = NULL;
        const char* c_base_message = "6D65737361676520646967657374";//"message digest"
        const char* c_base_data    = "656E6372797074696F6E207374616E64617264";//"encryption standard"
        const char* c_base_privkey = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8";//测试用私钥d
        const char* c_base_pubx    = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020";//测试用公钥GX
        const char* c_base_puby    = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13";//测试用公钥GY
        const char* c_base_rand    = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21";//测试用随机数k
        const char* c_base_za      = "B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3";//测试用ZA
        const char* c_base_sign_r  = "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3";//测试用SIGN_R
        const char* c_base_sign_s  = "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA";//测试用SIGN_S
        const char* c_base_kGx     = "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73";//C1:[k]G
        const char* c_base_kGy     = "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0";//C1:[k]G
        const char* c_base_C3      = "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766";//C3:Hash(kGx || M || KGy)
        const char* c_base_C2      = "21886CA989CA9C7D58087307CA93092D651EFA";//C2:M^KDF(kGx || kGy, bits(M))
        unsigned char base_message[14];
        unsigned char base_data[19];
        unsigned char base_privkey[32];
        unsigned char base_pubx[32];
        unsigned char base_puby[32];
        unsigned char base_rand[32];
        unsigned char base_za[32];
        unsigned char base_sign_r[32];
        unsigned char base_sign_s[32];
        unsigned char base_cipher[32+32+32+19];
        
        unsigned char temp[65] = {0};
        
        unsigned char privkey[32];
        unsigned char px[32];
        unsigned char py[32];
        unsigned char za[32];
        unsigned char sign_r[32];
        unsigned char sign_s[32];
        unsigned char cipher[32+32+32+19];
        unsigned char plain[19];
        
        hex2bytes(c_base_message, 28, base_message);
        hex2bytes(c_base_data, 38, base_data);
        hex2bytes(c_base_privkey, 64, base_privkey);
        hex2bytes(c_base_pubx, 64, base_pubx);
        hex2bytes(c_base_puby, 64, base_puby);
        hex2bytes(c_base_rand, 64, base_rand);
        hex2bytes(c_base_za, 64, base_za);
        hex2bytes(c_base_sign_r, 64, base_sign_r);
        hex2bytes(c_base_sign_s, 64, base_sign_s);
        hex2bytes(c_base_kGx, 64, base_cipher);
        hex2bytes(c_base_kGy, 64, base_cipher+32);
        hex2bytes(c_base_C3, 64, base_cipher+64);
        hex2bytes(c_base_C2, 38, base_cipher+96);
        
        printf("==============================================================================\n");
        printf("%-8s = %s [for test sign]\n", "message", c_base_message);
        printf("%-8s = %s [for test enc]\n", "data", c_base_data);
        printf("%-8s = %s\n", "privkey", c_base_privkey);
        printf("%-8s = %s\n", "pubx", c_base_pubx);
        printf("%-8s = %s\n", "puby", c_base_puby);
        printf("%-8s = %s\n", "rand", c_base_rand);
        printf("%-8s = %s\n", "ZA", c_base_za);
        printf("%-8s = %s\n", "sign_R", c_base_sign_r);
        printf("%-8s = %s\n", "sign_S", c_base_sign_s);
        printf("%-8s = %s\n", "cipher", c_base_kGx);
        printf("%-8s   %s\n", "", c_base_kGy);
        printf("%-8s   %s\n", "", c_base_C3);
        printf("%-8s   %s\n", "", c_base_C2);
        printf("==============================================================================\n\n");
        
        if(0 != SM2_keypair_generation(base_privkey, privkey, px, py))
        {
            printf("SM2_keypair_generation()==>error\n");
            return -1;
        }
        
        if(0 != memcmp(privkey, base_privkey, 32)) error = c_error[0];
        else error = c_error[1];
        bytes2hex(privkey, 32, temp);
        printf("generate privkey = %s [%s]\n", temp, error);
        
        if(0 != memcmp(px, base_pubx, 32)) error = c_error[0];
        else error = c_error[1];
        bytes2hex(px, 32, temp);
        printf("generate pubx    = %s [%s]\n", temp, error);
        
        if(0 != memcmp(py, base_puby, 32)) error = c_error[0];
        else error = c_error[1];
        bytes2hex(py, 32, temp);
        printf("generate puby    = %s [%s]\n", temp, error);
        
        SM2_sign_pre(px, py, za);
        if(0 != memcmp(za, base_za, 32)) error = c_error[0];
        else error = c_error[1];
        bytes2hex(za, 32, temp);
        printf("generate ZA      = %s [%s]\n", temp, error);
        
        if(0 != SM2_sign(privkey, za, base_message, sizeof(base_message), base_rand, sign_r, sign_s))
        {
            printf("SM2_sign()==>error\n");
            return -1;
        }
        
        if(0 != memcmp(sign_r, base_sign_r, 32)) error = c_error[0];
        else error = c_error[1];
        bytes2hex(sign_r, 32, temp);
        printf("generate sign_r  = %s [%s]\n", temp, error);
        
        if(0 != memcmp(sign_s, base_sign_s, 32)) error = c_error[0];
        else error = c_error[1];
        bytes2hex(sign_s, 32, temp);
        printf("generate sign_s  = %s [%s]\n", temp, error);
        
        if(0 != SM2_verify(px, py, za, base_message, sizeof(base_message), sign_r, sign_s))
        {
            printf("SM2_verify()==>error\n");
            return -1;
        }
        
        if(0 != SM2_encrypt(px, py, base_data, 19, base_rand, cipher))
        {
            printf("SM2_encrypt()==>error\n");
            return -1;
        }
        
        if(0 != memcmp(cipher, base_cipher, sizeof(cipher))) error = c_error[0];
        else error = c_error[1];
        bytes2hex(cipher, 32, temp);
        printf("generate cipher  = %s [%s]\n", temp, error);
        bytes2hex(cipher+32, 32, temp);
        printf("                   %s\n", temp);
        bytes2hex(cipher+64, 32, temp);
        printf("                   %s\n", temp);
        bytes2hex(cipher+96, 19, temp); temp[38]='\0';
        printf("                   %s\n", temp);
        
        if(0 != SM2_decrypt(privkey, cipher, sizeof(cipher), plain))
        {
            printf("SM2_decrypt()==>error\n");
            return -1;
        }
        
        printf("test pass\n");
        
        
        #pragma mark - SM3 哈希算法
        NSString * sm3String = @"fanyunfei";
        NSData * sm3Data = [sm3String dataUsingEncoding:NSUTF8StringEncoding];
        unsigned char data[[sm3Data length]];
        memcpy(data, [sm3Data bytes], [sm3Data length]);
        unsigned char hash[32];
        SM3(data, (int)[sm3Data length], hash);
        for (int i = 0; i < 32; i++)
        {
            printf("%c\n",hash[i]);
        }
        
        
        #pragma mark - SMS4加密解密
        unsigned char key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
        unsigned char input[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
        unsigned char output[16];
        for (int i = 0; i < sizeof(input); i++)
        {
            printf("message:%hhx\n",input[i]);
        }
        if (0 != SM4_encrypt(input, 16, output, key))
        {
            NSLog(@"NIST_sm4_encrypt error");
            return -1;
        }
        for (int i = 0; i < sizeof(output); i++)
        {
            printf("%hhx\n",output[i]);
        }
        printf("++++++++++++++++++++++++++++\n");
        if (0 != SM4_decrypt(output, sizeof(output), output, key))
        {
            NSLog(@"NIST_sm4_decrypt error");
            return -1;
        }
        for (int i = 0; i < sizeof(output); i++)
        {
            printf("%hhx\n",output[i]);
        }
    }
    return 0;
}
