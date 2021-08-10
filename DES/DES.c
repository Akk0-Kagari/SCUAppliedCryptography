#include<stdio.h>
#include<string.h>
#include "tables.h"    //数据表
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include<malloc.h>
#include<time.h>


typedef struct {
	char* plainfile;
	char* keyfile;
	char* vifile;
	char* mode;
	char* cipherfile;
	char* decryption;
}s_param;

void premutation(char* in, char* out, int n, char* P);//初始IP置换

void xor (char* in1, char* in2, int n, char* out);//与K的异或运算

void circleShift(char* In, char* Out, int n, int s);//循环左移

void subKey(char* K, char(*SK)[49]);//生成子密钥函数

void functionF(char* L, char* R, char* SK, int t);//f函数

void hexToBin(char* str, char* dest, int times);//16进制转2进制

void binToHex(char* sSrc, char* sDest, int times);//2进制转16进制

void getText(char* filename, char* dest);//读取文本内容

void move(char* reg, char* cipher, int t);//移位

void DES_Encryption(char* plainBit, char* keyBit, char* cipherBit);

void DES_Decryption(char* cipherBit, char* keyBit, char* plainBit);

int ECB(char* plainfile, char* keyfile, char* cipherfile);

int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile);

int CFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile);

int OFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile);

int deECB(char* cipher, char* keyfile, char* plainfile);

int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile);

int deCFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile);

int deOFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile);


void test(s_param param);




int main(int argc, char* argv[]) {
	s_param param;
	int i = 1;
	param.plainfile = "test_plain.txt";
	param.cipherfile = "test_cipher.txt";
	param.keyfile = "test_key.txt";
	param.mode = "ECB";
	param.vifile = "test_vi.txt";
	param.decryption = "test_decryption.txt";


	//test(param);
	
	while (i<argc)
	{
		if (!strcmp(argv[i], "-p"))
			param.plainfile = argv[i + 1];
		else if (!strcmp(argv[i], "-k"))
			param.keyfile = argv[i + 1];
		else if (!strcmp(argv[i], "-m"))
			param.mode = argv[i + 1];
		else if (!strcmp(argv[i], "-c"))
			param.cipherfile = argv[i + 1];
		else if (!strcmp(argv[i], "-v"))
			param.vifile = argv[i + 1];
		i += 2;
	}
	if (!strcmp(param.mode, "ECB")) {
		ECB(param.plainfile, param.keyfile, param.cipherfile);
		deECB(param.cipherfile, param.keyfile, param.decryption);
	}
	else if (!strcmp(param.mode, "CBC")) {
		CBC(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deCBC(param.cipherfile, param.keyfile, param.decryption, param.vifile);
	}
	else if (!strcmp(param.mode, "CFB")) {
		CFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deCFB(param.cipherfile, param.keyfile, param.decryption, param.vifile);
	}
	else if (!strcmp(param.mode, "OFB")) {
		OFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deOFB(param.cipherfile, param.keyfile, param.decryption, param.vifile);
	}
	else
		printf("Mode error!");
	printf("DONE!");
	getchar();
	return 0;

}


/*
初始置换
参数：in：待置换数据指针	out：置换输出指针	n：置换表长度	P：置换表指针
通过查表将指针所指向的数据替换为表数据中所对应位置的数据。
*/
void premutation(char* in, char* out, int n, char* P) {
	int i = 0;
	for ( i = 0; i < n; i++)
		*(out + i) = *(in + *(P + i) - 1);
	*(out + i) = '\0';
}


/* 异或运算
参数：in1：二进制串，in2：二进制串，n：二进制长度 Out：异或结果
循环异或运算两个二进制串的每一位
*/
void xor (char* in1, char* in2, int n, char* out) {
	for (int i = 0; i < n; i++) {
		if (*(in1 + i) != *(in2 + i))
		{
			*(out+i)='1';
		}else
		{
			*(out + i) = '0';
		}
	}
}


/*循环左移
参数：In：需移位字符串	Out：移位后字符串 n:二进制串长度	s：循环位数
实现循环的左移二进制串
*/
void circleShift(char* In, char* Out, int n, int s) {
	for (int i = 0; i < n; i++)
		*(Out + i) = *(In + (s + i) % n);
	*(Out + n) = '\0';
}


/*生成子密钥
参数：K：64位密钥	(*SK)[49]：得到的一轮子密钥
将64位密钥通过PC-1置换后变成56位，16轮得到16个子密钥，每一轮密钥分成两部分做相应的移位操作，然后通过PC-2置换得到该轮密钥。
*/
void subKey(char* K, char(*SK)[49]) {
	char out[57], C[57], D[29], e[29], t[57];
	premutation(K, out, 56, *PC_1);
	strcpy(C, out);		//C0
	strcpy(D, out + 28);	//D0
	for (int j = 0; j < 16; j++)
	{
		circleShift(C, e, 28, move_time[j]);		//循环左移	
		strcpy(C, e);								//Cj
		circleShift(D, e, 28,move_time[j]);
		strcpy(D, e);								//Dj
		strncpy(t, C, 28);
		strncpy(t + 28, D, 28);
		premutation(t, *(SK + j), 48, *PC_2);	//选择置换，得到Kj
	}
}


/*f函数
参数：L：第t轮的32位L组	R：第t轮的32位R组	SK：第t轮的48位子密钥	t：轮数
将输入的32位R组数据进行扩展置换，生成48位的数据。将置换后的48位结果与输入的48位子密钥进行异或运算，得到48位的运算结果。
将48位运算结果分成8组，每组6Bit数据，按照组号对应相应的S盒，进行8个S盒置换，生成8个4Bit的数据。将这8个4Bit数据合并，得到一个32位数据。将32位进行置换P就得到最后的32位处理结果。
*/
void functionF(char* L, char* R, char* SK, int t) {
	int i = 0, j = 0;
	char out1[49] = { 0 }, out2[49] = { 0 }, out3[33] = { 0 }, out4[33] = { 0 }, temp[33] = { 0 };
	//out1用于输出扩展置换后的数据
	//out2用于输出与子密钥异或后的结果
	//out3用于输出S盒代换后的结果
	//out4用于输出P置换后的结果
	//temp用于保存旧R
	int row, col;

	premutation(R, out1, 48, *E);//扩展置换E

	xor (out1, SK, 48, out2);//与子密钥异或
	
	for (i = 0; i < 8; i++)
	{
		//行号
		row = (((out2[i * 6]) - '0') << 1) + ((out2[i * 6 + 5]) - '0');
		//列号
		col = (((out2[i * 6 + 1]) - '0') << 3) + (((out2[i * 6 + 2]) - '0') << 2) + (((out2[i * 6 + 3]) - '0') << 1) + ((out2[i * 6 + 4]) - '0');
		
		for (j = 3; j >= 0; j--)
			*(out3 + (i * 4 + 3 - j)) = ((S_Box[i][row * 16 + col] >> j) & 1) + '0';
	}
	*(out3 + 32) = "\0";
	premutation(out3, out4, 32, *P);

	strcpy(temp, R);//保存旧R
	xor (L, out4, 32, R);//更新R

	strcpy(L, temp);//更新L
}

/* 16进制字符串转2进制字符串 
参数：str：16进制字符串		dest：2进制字符串		times：2进制字符串长度	
*/
void hexToBin(char* str, char* dest, int times) {
	int res;
	char des[65] = { 0 };

	char reference[16][5] = {
		"0000","0001","0010","0011",
		"0100","0101","0110","0111",
		"1000","1001","1010","1011",
		"1100","1101","1110","1111"
	};
	int i = 0;
	while (i<times/4)
	{
		char num = str[i];
		switch (num)
		{
		case 'A':
			res = 10;
			break;
		case 'B':
			res = 11;
			break;
		case 'C':
			res = 12;
			break;
		case 'D':
			res = 13;
			break;
		case 'E':
			res = 14;
			break;
		case 'F':
			res = 15;
			break;
		default:
			res = (int)num - 48;
			break;
		}
		strcat(des, reference[res]);
		i++;
	}
	strncpy(dest, des, times);
}


/* 2进制字符串转16进制字符串
参数：str：2进制字符串		dest：16进制字符串		times：16进制字符串长度
*/
void binToHex(char* sSrc, char* sDest, int times) {
	char temp[17] = { 0 };
	int x = 0;
	for (int i = 0; i < times; i++)
	{
		x = 8 * (sSrc[i * 4] - '0');
		x += 4 * (sSrc[i * 4 + 1] - '0');
		x += 2 * (sSrc[i * 4 + 2] - '0');
		x += sSrc[i * 4 + 3] - '0';
		switch (x)
		{
		case 10:
			temp[i] = 'A';
			break;
		case 11:
			temp[i] = 'B';
			break;
		case 12:
			temp[i] = 'C';
			break;
		case 13:
			temp[i] = 'D';
			break;
		case 14:
			temp[i] = 'E';
			break;
		case 15:
			temp[i] = 'F';
			break;
		default:
			temp[i] = (char)(x + 48);
			break;
		}
	}

	strncpy(sDest, temp, times);
	
}

/*读取文本中的参数
参数：filename：文件名		dest：返回的二进制字符串
已经将16进制转换为2进制
*/
void getText(char* filename, char* dest) {
	FILE* pFile = fopen(filename, "r");
	if (pFile == NULL)
	{
		printf("文件打开失败\n");
	}
	char output[65] = { 0 };//密钥二进制
	char key[17] = { 0 };//密钥16进制
	fread(key, sizeof(char), 16, pFile);
	fclose(pFile);//关闭文件并保存
	hexToBin(key, output, 64);
	strcpy(dest, output);
}


/* 移位 
参数：reg:寄存器	cipher：密文	t：移动位数
*/
void move(char* reg, char* cipher, int t) {
	int j, i = 0;
	while (i < strlen(reg) - t)
	{
		reg[i] = reg[i + t];
		i++;
	}
	for (j = 0; j < t; j++)
		reg[i + j] = cipher[j];
}


/*	DES加密
*	参数：plainBit：明文二进制	keyBit：密钥二进制	cipherBit：密文二进制
*/
void DES_Encryption(char* plainBit, char* keyBit, char* cipherBit) {
	char* K = keyBit;//密钥
	char* M = plainBit;//明文

	char out[65], L[33], R[33], SK[16][49];
	//out:存放初始置换后的密文
	//L:L组
	//R:R组
	//SK:子密钥

	subKey(K, SK);//16轮子密钥
	premutation(M, out, 64, *IP);//初始置换IP

	strncpy(L, out, 32);
	strcpy(R, out + 32);

	//16轮
	for (int i = 0; i < 16; i++)
	{
		functionF(L, R, *(SK + i), i);
	}

	strncpy(out, R, 32);
	strncpy(out + 32, L, 32);

	//逆初始置换
	premutation(out, cipherBit, 64, *C_IP);
}

/*	DES解密
*	参数：cipherBit：密文二进制	keyBit：密钥二进制	plainBit：明文二进制
*/
void DES_Decryption(char* cipherBit, char* keyBit, char* plainBit) {
		char* K = keyBit;//密钥
		char* C = cipherBit;//密文

		char out[65], L[33], R[33], SK[16][49];
		////out:存放初始置换后的密文
		////L:L组
		////R:R组
		////SK:子密钥

		
		subKey(K, SK);//16轮子密钥
		premutation(C, out, 64, *IP);//初始置换IP

		strncpy(L, out, 32);
		strcpy(R, out + 32);

		//16轮
		for (int i = 0; i < 16; i++)
		{
			functionF(L, R, *(SK + 15 - i), i);
		}

		strncpy(out, R, 32);
		strncpy(out + 32, L, 32);

		//逆初始置换
		premutation(out, plainBit, 64, *C_IP);
}

/* ECB
参数：plainfile：明文文件名	keyfile：密钥文件名	cipherfile：密文文件名
电子密码本ECB模式是最简单的模式。它直接利用加密算法分别对每个明文分组使用相同密钥进行加密。
*/
int ECB(char* plainfile, char* keyfile, char* cipherfile) {
	
	char plainBit[65] = { 0 };//明文二进制
	char keyBit[65] = { 0 };//密钥二进制
	char cipherBit[65] = { 0 };//密文二进制
	char plain[17] = { 0 };//明文16进制
	char cipher[17] = { 0 };//密文16进制
	

	FILE* pFileCipher = fopen(cipherfile, "w");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "r");//打开明文文件

	int i = 0;
	getText(keyfile, keyBit);
	int flag = fread(plain, sizeof(char), 16, pFilePlain);
	while (flag)
	{
		hexToBin(plain, plainBit, 64);

		DES_Encryption(plainBit, keyBit, cipherBit);
		
		binToHex(cipherBit, cipher, 16);

		fwrite(cipher, sizeof(char), 16, pFileCipher);//写入密文

		flag = fread(plain, sizeof(char), 16, pFilePlain);//读取下一组明文

	}
	fclose(pFilePlain);
	fclose(pFileCipher);
	return 0;
}

/*deECB
*参数：cipherfile：密文文件名	keyfile：密钥文件名	plainfile：明文文件名
*/
int deECB(char* cipherfile, char* keyfile, char* plainfile) {

	char plainBit[65] = { 0 };//明文二进制
	char keyBit[65] = { 0 };//密钥二进制
	char cipherBit[65] = { 0 };//密文二进制
	char plain[17] = { 0 };//明文16进制
	char cipher[17] = { 0 };//密文16进制


	FILE* pFileCipher = fopen(cipherfile, "r");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "w");//打开明文文件

	int i = 0;
	getText(keyfile, keyBit);
	int flag = fread(cipher, sizeof(char), 16, pFileCipher);
	while (flag)
	{
		hexToBin(cipher, cipherBit, 64);

		DES_Decryption(cipherBit, keyBit, plainBit);
		binToHex(plainBit, plain, 16);

		fwrite(plain, sizeof(char), 16, pFilePlain);//写入密文

		flag = fread(cipher, sizeof(char), 16, pFileCipher);//读取下一组明文

	}
	fclose(pFilePlain);
	fclose(pFileCipher);
	return 0;
}


/*CBC
参数：plainfile：明文文件名	keyfile：密钥文件名	cipherfile：密文文件名 vifile：初始向量文件名
在CBC模式中，加密算法的输入是当前的明文分组和上一次的产生的密文分组的异或，其输出为当前的密文分组
*/
int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {
	char plainBit[65] = { 0 };//明文二进制
	char keyBit[65] = { 0 };//密钥二进制
	char cipherBit[65] = { 0 };//密文二进制
	char ivBit[65] = { 0 };//iv二进制
	char temp[65] = { 0 };

	char plain[17] = { 0 };//明文16进制
	char cipher[17] = { 0 };//密文16进制


	FILE* pFileCipher = fopen(cipherfile, "w");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "r");//打开明文文件

	int i = 0;
	
	int flag = fread(plain, sizeof(char), 16, pFilePlain);
	getText(keyfile, keyBit);//得到密钥二进制
	getText(vifile, ivBit);//得到向量二进制
	hexToBin(plain, plainBit, 64);//得到明文二进制
	strcpy(temp, plainBit);
	xor (temp, ivBit, 64, plainBit);//向量与明文异或

	while (flag)
	{
		DES_Encryption(plainBit, keyBit, cipherBit);

		binToHex(cipherBit, cipher, 16);

		fwrite(cipher, sizeof(char), 16, pFileCipher);

		flag = fread(plain, sizeof(char), 16, pFilePlain);
		hexToBin(plain, plainBit, 64);
		strcpy(temp, cipherBit);
		xor (plainBit, temp, 64, plainBit);//密文和要加密的明文异或
	}

	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}

/*deCBC
*参数：cipherfile：密文文件名	keyfile：密钥文件名	plainfile：明文文件名 vifile：向量文件名
*/
int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	char plainBit[65] = { 0 };//明文二进制
	char keyBit[65] = { 0 };//密钥二进制
	char cipherBit[65] = { 0 };//密文二进制
	char ivBit[65] = { 0 };//iv二进制
	char temp[65] = { 0 };

	char plain[17] = { 0 };//明文16进制
	char cipher[17] = { 0 };//密文16进制


	FILE* pFileCipher = fopen(cipherfile, "r");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "w");//打开明文文件

	int i = 0;

	int flag = fread(cipher, sizeof(char), 16, pFileCipher);
	getText(keyfile, keyBit);//得到密钥二进制
	getText(vifile, ivBit);//得到向量二进制
	hexToBin(cipher, cipherBit, 64);//得到明文二进制
	
	//strcpy(temp, output1);
	//xor (temp, output4, 64, output1);//向量与明文异或

	while (flag)
	{
		DES_Decryption(cipherBit, keyBit, plainBit);

		strcpy(temp, plainBit);
		xor (temp, ivBit, 64, plainBit);//向量与密文异或

		binToHex(plainBit, plain, 16);

		fwrite(plain, sizeof(char), 16, pFilePlain);
		strcpy(ivBit, cipherBit);

		flag = fread(cipher, sizeof(char), 16, pFileCipher);
		hexToBin(cipher, cipherBit, 64);
	}

	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}


/*CFB
参数：plainfile：明文文件名	keyfile：密钥文件名	cipherfile：密文文件名 vifile：初始向量文件名
在s位CFB模式，加密函数的输入是一个b位的移位寄存器，这个移位寄存器被初始化为一个初始向量IV。加密函数处理结果的最高位（最左边）的s位与明文的第一个分组进行异或产生第一个密文分组。
同时，移位寄存器的值向左移s位，且用密文分组替换寄存器的最低（最右边）的s位。
这里选用的s为8
*/
int CFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {

	char regBit[65] = { 0 };//移位寄存器2进制
	char keyBit[65] = { 0 };//密钥2进制
	char outputBit[65] = { 0 };//输出2进制
	char ivBit[65] = { 0 };//初始化向量2进制
	char cipherBit[9] = { 0 };//密文2进制
	char plainBit[9] = { 0 };//明文2进制
	char plain[3] = { 0 };//明文16进制
	char cipher[3] = { 0 };//密文16进制

	
	char temp[9] = { 0 };//异或的中间变量

	getText(keyfile, keyBit);//获得密钥二进制
	getText(vifile, ivBit);//获得初始向量二进制

	FILE* pFileCipher = fopen(cipherfile, "w");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "r");//打开明文文件

	int flag = fread(plain, sizeof(char), 2, pFilePlain);
	
	hexToBin(plain, plainBit, 8);//得到明文二进制
	strcpy(regBit, ivBit);//放入初始向量到移位寄存器

	while (flag)
	{
		DES_Encryption(regBit, keyBit, outputBit);

		strncpy(temp, outputBit, 8);//选取最左边的8位
		xor (temp, plainBit, 8, cipherBit);

		binToHex(cipherBit, cipher, 2);
		fwrite(cipher, sizeof(char), 2, pFileCipher);

		move(regBit, cipherBit, 8);
		flag = fread(plain, sizeof(char), 2, pFilePlain);
		hexToBin(plain, plainBit, 8);

	}

	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}

/*deCFB
*参数：cipherfile：密文文件名	keyfile：密钥文件名	plainfile：明文文件名 vifile：向量文件名
*/
int deCFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	char regBit[65] = { 0 };//移位寄存器2进制
	char keyBit[65] = { 0 };//密钥2进制
	char outputBit[65] = { 0 };//输出2进制
	char ivBit[65] = { 0 };//初始化向量2进制
	char cipherBit[9] = { 0 };//密文2进制
	char plainBit[9] = { 0 };//明文2进制
	char plain[3] = { 0 };//明文16进制
	char cipher[3] = { 0 };//密文16进制


	char temp[9] = { 0 };//异或的中间变量

	getText(keyfile, keyBit);//获得密钥二进制
	getText(vifile, ivBit);//获得初始向量二进制

	FILE* pFileCipher = fopen(cipherfile, "r");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "w");//打开明文文件

	int flag = fread(cipher, sizeof(char), 2, pFileCipher);

	hexToBin(cipher, cipherBit, 8);//得到密文二进制
	strcpy(regBit, ivBit);//放入初始向量到移位寄存器

	while (flag)
	{
		DES_Encryption(regBit, keyBit, outputBit);

		strncpy(temp, outputBit, 8);//选取最左边的8位
		xor (temp,cipherBit, 8, plainBit);

		binToHex(plainBit, plain, 2);
		fwrite(plain, sizeof(char), 2, pFilePlain);

		move(regBit, cipherBit, 8);
		flag = fread(cipher, sizeof(char), 2, pFileCipher);
		hexToBin(cipher, cipherBit, 8);

	}

	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}

/*OFB
参数：plainfile：明文文件名	keyfile：密钥文件名	cipherfile：密文文件名 vifile：初始向量文件名
在OFB模式中，先产生一个密钥流，然后将其与明文相异或。
因此，OFB模式实际上就是一个同步流密码，通过反复加密一个初始向量IV来得到密钥流。
*/
int OFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {
	char regBit[65] = { 0 };//移位寄存器
	char keyBit[65] = { 0 };//密钥二进制
	char outputBit[65] = { 0 };//输出二进制
	char ivBit[65] = { 0 };//初始化向量2进制
	char cipherBit[9] = { 0 };//密文2进制
	char plainBit[9] = { 0 };//明文2进制
	char plain[3] = { 0 };//明文16进制
	char cipher[3] = { 0 };//密文16进制

	char temp[9] = { 0 };//异或的中间变量
	getText(keyfile, keyBit);//得到密钥二进制
	getText(vifile, ivBit);//得到初始向量二进制

	FILE* pFileCipher = fopen(cipherfile, "w");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "r");//打开明文文件

	int flag = fread(plain, sizeof(char), 2, pFilePlain);
	hexToBin(plain, plainBit, 8);//得到8位明文二进制
	strcpy(regBit, ivBit);//将初始向量放入移位寄存器

	while (flag)
	{
		DES_Encryption(regBit, keyBit, outputBit);

		strncpy(temp, outputBit, 8);//选择最左边的8位
		
		xor (temp, plainBit, 8, cipherBit);
		binToHex(cipherBit, cipher, 2);
		fwrite(cipher, sizeof(char), 2, pFileCipher);

		move(regBit, temp, 8);
		flag = fread(plain, sizeof(char), 2, pFilePlain);
		hexToBin(plain, plainBit, 8);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	
	return 0;
}

/*deOFB
*参数：cipherfile：密文文件名	keyfile：密钥文件名	plainfile：明文文件名 vifile：向量文件名
*/
int deOFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	char regBit[65] = { 0 };//移位寄存器
	char keyBit[65] = { 0 };//密钥二进制
	char outputBit[65] = { 0 };//输出二进制
	char ivBit[65] = { 0 };//初始化向量2进制
	char cipherBit[9] = { 0 };//密文2进制
	char plainBit[9] = { 0 };//明文2进制
	char plain[3] = { 0 };//明文16进制
	char cipher[3] = { 0 };//密文16进制

	char temp[9] = { 0 };//异或的中间变量
	getText(keyfile, keyBit);//得到密钥二进制
	getText(vifile, ivBit);//得到初始向量二进制

	FILE* pFileCipher = fopen(cipherfile, "r");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "w");//打开明文文件

	int flag = fread(cipher, sizeof(char), 2, pFileCipher);
	hexToBin(cipher, cipherBit, 8);//得到8位密文二进制
	strcpy(regBit, ivBit);//将初始向量放入移位寄存器

	while (flag)
	{
		DES_Encryption(regBit, keyBit, outputBit);

		strncpy(temp, outputBit, 8);//选择最左边的8位

		xor (temp, cipherBit, 8, plainBit);
		binToHex(plainBit, plain, 2);
		fwrite(plain, sizeof(char), 2, pFilePlain);

		move(regBit, temp, 8);
		flag = fread(cipher, sizeof(char), 2, pFileCipher);
		hexToBin(cipher, cipherBit, 8);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);

	return 0;
	
}


void test(s_param param) {
	clock_t start, end;
	int alltime = 0;
	double avgspeed=0,nowspeed=0;

	/***************** ECB *****************/
	/*for(int i = 0;i < 20;i++){
		start = clock();
		ECB(param.plainfile, param.keyfile, param.cipherfile);
		deECB(param.cipherfile, param.keyfile, param.decryption);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i)/ (i + 1);
		printf("第%d轮：ECB测试用时：%d ms\t速度：%.3f MByete/s\n",i+1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n20轮ECB测试用时：%d ms速度：%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** CBC *****************/
	/*for (int i = 0; i < 20; i++) {
		start = clock();
		CBC(param.plainfile, param.keyfile, param.cipherfile,param.vifile);
		deCBC(param.cipherfile, param.keyfile, param.decryption,param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("第%d轮：CBC测试用时：%d ms\t速度：%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n20轮CBC测试用时：%d ms速度：%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** CFB *****************/
	/*for (int i = 0; i < 5; i++) {
		start = clock();
		CFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deCFB(param.cipherfile, param.keyfile, param.decryption, param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("第%d轮：CFB测试用时：%d ms\t速度：%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n5轮CFB测试用时：%d ms速度：%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** OFB *****************/
	/*for (int i = 0; i < 5; i++) {
		start = clock();
		OFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deOFB(param.cipherfile, param.keyfile, param.decryption, param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("第%d轮：OFB测试用时：%d ms\t速度：%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n5轮OFB测试用时：%d ms速度：%.3f MByete/s\n", alltime, avgspeed);*/

	/******************** some test in my programming ***************************************************/

}