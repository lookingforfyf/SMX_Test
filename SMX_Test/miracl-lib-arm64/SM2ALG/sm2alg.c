#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "sm2alg.h"
#include "sm2.h"
#include "sm3.h"
#include "sms4.h"


/*
功能：生成指定长度随机数
输入：len随机数长度
输出：rand随机数
返回：无
*/
void SM2_gen_rand(unsigned char rnd[], int len)
{
	pid_t pid = getpid();
	int randData;
	int n = 0;
	
	srand((unsigned int) pid);
	while(len >= 4)
	{
		randData = rand();
		rnd[n++] = (unsigned char)(randData >> 24);
		rnd[n++] = (unsigned char)(randData >> 16);
		rnd[n++] = (unsigned char)(randData >> 8);
		rnd[n++] = (unsigned char)(randData);

		len -= 4;
	}

	if(len > 0)
	{
		randData = rand();
		for(len = len; len > 0; len--) rnd[n++] = (unsigned char)(randData >> (8 * len));
	}
}

/*
功能：SM2算法椭圆曲线参数初始化
输入：无
输出：无
返回：无
*/
void SM2_init(void)
{
	static unsigned char fRunOnce = 0;
	int iret;

	if(0 == fRunOnce)
	{
		if(0 != (iret = SM2_standard_init())) printf("[ERROR]%s %s: SM2_init() error\n", __FILE__, __LINE__);

		fRunOnce = 1;
	}
}


/*
功能：生成SM2算法公私密钥对[d、G(x,y)]
输入：rand可选随机数
输出：privkey私钥d、px公钥Gx、py公钥Gy
返回：0成功 !0失败
*/
int SM2_keypair_generation(unsigned char rand[], unsigned char privkey[], unsigned char px[], unsigned char py[])
{
	unsigned char seed[32];
	
	SM2_init();

	if(NULL == rand) SM2_gen_rand(seed, 32);
	else memcpy(seed, rand, 32);
	
	//私钥需满足[1,n-2]
	while(0 != Test_PrivKey(seed)) SM2_gen_rand(seed, 32);

	memcpy(privkey, seed, 32);

	SM2_keygeneration_2(privkey, px, py);

	return 0;
}

/*
功能：预处理由公钥计算ZA
输入：px公钥Gx、py公钥Gy
输出：za
返回：无
*/
void SM2_sign_pre(unsigned char px[], unsigned char py[], unsigned char za[])
{
	SM2_pre_ZA(px, py, za);
}


/*
功能：SM2算法私钥签名
输入：privkey私钥d、za预处理值、msg消息、msglen消息长度、rand可选随机数
输出：signR签名R、signS签名S
返回：0成功 !0失败
*/
int SM2_sign(unsigned char privkey[], unsigned char za[], unsigned char msg[], int msglen, unsigned char rand[], unsigned char signR[], unsigned char signS[])
{
	unsigned char seed[32];
	
	SM2_init();
	
	if(NULL == rand) SM2_gen_rand(seed, sizeof(seed));
	else memcpy(seed, rand, sizeof(seed));
	
	return SM2_standard_sign(msg, msglen, za, seed, privkey, signR, signS);
}

/*
功能：SM2算法公钥验证签名
输入：px公钥Gx、py公钥Gy、msg消息、msglen消息长度、signR签名R、signS签名S
输出：无
返回：0成功 !0失败
*/
int SM2_verify(unsigned char px[], unsigned char py[], unsigned char za[], unsigned char msg[], int msglen, unsigned char signR[], unsigned char signS[])
{
	SM2_init();
	
	return SM2_standard_verify(msg, msglen, za, px, py, signR, signS);
}

/*
功能：SM2算法公钥加密
输入：px公钥Gx、py公钥Gy、plain明文、plainlen明文长度、rand可选随机数
输出：cipher密文
返回：0成功 !0失败
*/
int SM2_encrypt(unsigned char px[], unsigned char py[], unsigned char plain[], int plainlen, unsigned char rand[], unsigned char cipher[])
{
	unsigned char seed[32];
	
	SM2_init();
	
	if(NULL == rand) SM2_gen_rand(seed, sizeof(seed));
	else memcpy(seed, rand, sizeof(seed));

	return SM2_standard_encrypt_2(seed, px, py, plain, plainlen, cipher);
}

/*
功能：SM2算法私钥解密
输入：privkey私钥d、cipher密文、cipherlen密文长度
输出：plain明文
返回：0成功 !0失败
*/
int SM2_decrypt(unsigned char privkey[], unsigned char cipher[], int cipherlen, unsigned char plain[])
{
	SM2_init();

	return SM2_standard_decrypt_2(privkey, cipher, cipherlen, plain);
}


/*
功能：SM3算法对数据进行HASH计算
输入：msg消息、mlen消息长度
输出：hash摘要值
返回：无
*/
void SM3(unsigned char msg[], int mlen, unsigned char hash[])
{
	SM3_256(msg, mlen, hash);
}


/*
功能：SM4算法加密
输入：in明文、inlen明文长度、key密钥
输出：out密文
返回：0成功 !0失败
*/
int SM4_encrypt(const unsigned char in[], int inlen, unsigned char out[], const unsigned char key[])
{
	int i = 0;
	if(0 != (inlen % 16)) return -1;

	while(inlen > 0)
	{
		SMS4_encrypt(in[i], out[i], key);

		i += 16;
		inlen -= 16;
	}

	return 0;
}


/*
功能：SM4算法解密
输入：in密文、inlen密文长度、key密钥
输出：out明文
返回：0成功 !0失败
*/
int SM4_decrypt(const unsigned char in[], int inlen, unsigned char out[], const unsigned char key[])
{
	
	int i = 0;
	if(0 != (inlen % 16)) return -1;

	while(inlen > 0)
	{
		SMS4_decrypt(in[i], out[i], key);

		i += 16;
		inlen -= 16;
	}

	return 0;
}

