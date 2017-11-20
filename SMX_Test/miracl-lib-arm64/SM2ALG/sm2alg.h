#ifndef NIST_SM_ALG_H
#define NIST_SM_ALG_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


//hex字符串转字节流
static void hex2bytes(const char* hex, int hlen, unsigned char* bytes)
{
	int n;
	char cH4,cL4;

	for (n = 0; n < hlen/2; n++) {
		cH4 = hex[2*n];
		cL4 = hex[2*n+1];

		cH4 = (cH4 >= '0' && cH4 <= '9')?(cH4 - '0'):(cH4);
		cH4 = (cH4 >= 'a' && cH4 <= 'f')?(cH4 - 'a' + 10):(cH4);
		cH4 = (cH4 >= 'A' && cH4 <= 'F')?(cH4 - 'A' + 10):(cH4);

		cL4 = (cL4 >= '0' && cL4 <= '9')?(cL4 - '0'):(cL4);
		cL4 = (cL4 >= 'a' && cL4 <= 'f')?(cL4 - 'a' + 10):(cL4);
		cL4 = (cL4 >= 'A' && cL4 <= 'F')?(cL4 - 'A' + 10):(cL4);
		
		bytes[n] = (unsigned char)(cH4<<4 | cL4);
	}
}

//字节流转hex字符串
static void bytes2hex(const unsigned char* bytes, int blen, char* hex) {
	int n, m = 0;
	char hexMap[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

	for (n = 0; n < blen; n++) {
		hex[m++] = hexMap[(bytes[n]>>4)&0x0f];
		hex[m++] = hexMap[bytes[n]&0x0f];
	}
}

static void dump_byte(const unsigned char* bytes, int blen)
{
	const unsigned char* p = bytes;

	while (blen > 16)
	{
		printf("\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
		blen -= 16;
		p += 16;
	}

	if (blen)
	{
		printf("\t");
		while (blen--)	printf("%02x ", *p++);
		printf("\n");
	}
	
	printf("\n");
}


/*
功能：生成指定长度随机数
输入：len随机数长度
输出：rand随机数
返回：无
*/
void SM2_gen_rand(unsigned char rnd[], int len);

/*
功能：SM2算法椭圆曲线参数初始化
输入：无
输出：无
返回：无
*/
void SM2_init(void);

/*
功能：生成SM2算法公私密钥对[d、G(x,y)]
输入：rand可选随机数
输出：privkey私钥d、px公钥Gx、py公钥Gy
返回：0成功 !0失败
*/
int SM2_keypair_generation(unsigned char rand[], unsigned char privkey[], unsigned char px[], unsigned char py[]);

/*
功能：预处理由公钥计算ZA
输入：px公钥Gx、py公钥Gy
输出：za
返回：无
*/
void SM2_sign_pre(unsigned char px[], unsigned char py[], unsigned char za[]);

/*
功能：SM2算法私钥签名
输入：privkey私钥d、za预处理值、msg消息、msglen消息长度、rand可选随机数
输出：signR签名R、signS签名S
返回：0成功 !0失败
*/
int SM2_sign(unsigned char privkey[], unsigned char za[], unsigned char msg[], int msglen, unsigned char rand[], unsigned char signR[], unsigned char signS[]);

/*
功能：SM2算法公钥验证签名
输入：px公钥Gx、py公钥Gy、msg消息、msglen消息长度、signR签名R、signS签名S
输出：无
返回：0成功 !0失败
*/
int SM2_verify(unsigned char px[], unsigned char py[], unsigned char za[], unsigned char msg[], int msglen, unsigned char signR[], unsigned char signS[]);

/*
功能：SM2算法公钥加密
输入：px公钥Gx、py公钥Gy、plain明文、plainlen明文长度、rand可选随机数
输出：cipher密文
返回：0成功 !0失败
*/
int SM2_encrypt(unsigned char px[], unsigned char py[], unsigned char plain[], int plainlen, unsigned char rand[], unsigned char cipher[]);

/*
功能：SM2算法私钥解密
输入：privkey私钥d、cipher密文、cipherlen密文长度
输出：plain明文
返回：0成功 !0失败
*/
int SM2_decrypt(unsigned char privkey[], unsigned char cipher[], int cipherlen, unsigned char plain[]);

/*
功能：SM3算法对数据进行HASH计算
输入：msg消息、mlen消息长度
输出：hash摘要值
返回：无
*/
void SM3(unsigned char msg[], int mlen, unsigned char hash[]);

/*
功能：SM4算法加密
输入：in明文、inlen明文长度、key密钥
输出：out密文
返回：0成功 !0失败
*/
int SM4_encrypt(const unsigned char in[], int inlen, unsigned char out[], const unsigned char key[]);

/*
功能：SM4算法解密
输入：in密文、inlen密文长度、key密钥
输出：out明文
返回：0成功 !0失败
*/
int SM4_decrypt(const unsigned char in[], int inlen, unsigned char out[], const unsigned char key[]);


#ifdef __cplusplus
}
#endif


#endif
