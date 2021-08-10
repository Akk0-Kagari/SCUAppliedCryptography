#include<stdio.h>
#include<string.h>
#include "table.h"
#include<time.h>
#include "aes.h"

void getText(char* filename, char* dest);//读取文本内容

void hexToByte(const unsigned char* hexString, unsigned char* byteString, int len);//将16进制表示的字节转换为char

void byteToHex(const unsigned char* byteString, unsigned char* hexString, int len);//将byte转换为16进制

int StringToArray(const unsigned char* String, unsigned char(*Array)[4]);//将字符串转换为AES标准数组

int ArrayToString(const unsigned char(*Array)[4], unsigned char* String);//将AES标准数组转换为字符串

int Key_S_Substitution(unsigned char(*ExtendKeyArray)[44], unsigned int nCol);//对指定的扩展密钥矩阵列进行S盒替换

int G_Function(unsigned char(*ExtendKeyArray)[44], unsigned int nCol);//对列号是四的倍数的密钥扩展矩阵执行G函数

int CalculateExtendKeyArray(const unsigned char(*PasswordArray)[4], unsigned char(*ExtendKeyArray)[44]);//计算扩展密钥数组

int AddRoundKey(unsigned char(*PlainArray)[4], unsigned char(*ExtendKeyArray)[44], unsigned int MinCol);//轮密钥加

int Plain_S_Substitution(unsigned char* PlainArray);//对明文矩阵进行S盒的字节代换

int ShiftRows(unsigned int* PlainArray);//ShiftRows

char GaloisMultiplication(unsigned char Num_L, unsigned char Num_R);//伽罗瓦域内的乘法运算

int MixColumn(unsigned char(*PlainArray)[4]);//MixColumn

int AES_EnCryption(const unsigned char* PlainText, const unsigned char* Key, unsigned char* CipherText);//AES加密

int ReShiftRows(unsigned int* CipherArray);//逆向ShiftRows

int Cipher_S_Substitution(unsigned char* CipherArray);//逆向S盒字节代换

int ReMixColumn(unsigned char(*CipherArray)[4]);//逆向Mixcolumn列混淆

int AES_DeCryption(const unsigned char* CipherText, const unsigned char* PassWord, unsigned char* DeCipherText);//AES解密

int xor (const unsigned char* string1, const unsigned char* string2, int n, unsigned char* out);//异或

int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile);

int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile);


/* 读取文件中的参数(读取密钥及向量)
* 参数：filename：文件名		dest：返回的二进制字符串
* 读取明文，密钥，初始向量等
*/
void getText(char* filename, char* dest) {
	FILE* pFile = fopen(filename, "r");
	if (pFile == NULL) {
		printf("文件打开失败！\n");
	}
	unsigned char content[33] = { 0 };

	fread(content, sizeof(char), 32, pFile);

	memcpy(dest, content, 32);

}

/* 将16进制表示的字节转换为char
* 参数：hexString：16进制字符串		byteString：字节字符串		len：字节长度
*/
void hexToByte(const unsigned char* hexString, unsigned char* byteString, int len) {
	char bytes[17] = { 0 };
	int a, b, res;//分别为16进制的两位,res为对应的10进制
	int i = 0, j = 0;
	while (i < len * 2)
	{
		char num = hexString[i];
		switch (num)
		{
		case 'A':
			a = 10;
			break;
		case 'B':
			a = 11;
			break;
		case 'C':
			a = 12;
			break;
		case 'D':
			a = 13;
			break;
		case 'E':
			a = 14;
			break;
		case 'F':
			a = 15;
			break;
		default:
			a = (int)num - 48;
			break;
		}
		num = hexString[i + 1];
		switch (num)
		{
		case 'A':
			b = 10;
			break;
		case 'B':
			b = 11;
			break;
		case 'C':
			b = 12;
			break;
		case 'D':
			b = 13;
			break;
		case 'E':
			b = 14;
			break;
		case 'F':
			b = 15;
			break;
		default:
			b = (int)num - 48;
			break;
		}
		res = a * 16 + b;
		bytes[j++] = res;
		i += 2;
	}
	memcpy(byteString, bytes, len);
}

/* 将byte转换为16进制
* 参数：byteString：字节串		hexString：16进制串		len：16进制串长度
*/
void byteToHex(const unsigned char* byteString, unsigned char* hexString, int len) {
	char hex[33] = { 0 };
	int i = 0;
	int a, b;//16进制的两位
	while (i < len / 2)
	{
		int temp = (int)byteString[i];
		a = temp / 16;
		b = temp % 16;
		switch (a)
		{
		case 10:
			hex[i * 2] = 'A';
			break;
		case 11:
			hex[i * 2] = 'B';
			break;
		case 12:
			hex[i * 2] = 'C';
			break;
		case 13:
			hex[i * 2] = 'D';
			break;
		case 14:
			hex[i * 2] = 'E';
			break;
		case 15:
			hex[i * 2] = 'F';
			break;
		default:
			hex[i * 2] = a + 48;
			break;
		}
		switch (b)
		{
		case 10:
			hex[i * 2 + 1] = 'A';
			break;
		case 11:
			hex[i * 2 + 1] = 'B';
			break;
		case 12:
			hex[i * 2 + 1] = 'C';
			break;
		case 13:
			hex[i * 2 + 1] = 'D';
			break;
		case 14:
			hex[i * 2 + 1] = 'E';
			break;
		case 15:
			hex[i * 2 + 1] = 'F';
			break;
		default:
			hex[i * 2 + 1] = b + 48;
			break;
		}
		i++;
	}
	memcpy(hexString, hex, len);

}

/*将字符串转换为AES标准数组
* 参数：String：输入的字符串	Array：输出的AES标准数组
*/
int StringToArray(const unsigned char* String, unsigned char(*Array)[4]) {
	int ret = 0;

	for (int i = 0; i < 16; i++)
	{
		Array[i & 0x03][i >> 2] = String[i];
	}

	return ret;
}

/*	将AES标准数组转换成字符串
*	参数：Array：输入的AES标准数组		String：输出的字符串
*/
int ArrayToString(const unsigned char(*Array)[4], unsigned char* String) {
	int ret = 0;

	for (int i = 0; i < 16; i++)
	{
		String[i] = Array[i & 0x03][i >> 2];
	}

	return ret;
}

/* 对指定的扩展密钥矩阵列进行S盒替换
* 参数：ExtendKeyArray：输入的扩展密钥矩阵	nCol：输入的列号
*
*/
int Key_S_Substitution(unsigned char(*ExtendKeyArray)[44], unsigned int nCol) {
	int ret = 0;

	for (int i = 0; i < 4; i++)
	{
		//>>4	取行号	&0x0F 取列号
		ExtendKeyArray[i][nCol] = S_Table[(ExtendKeyArray[i][nCol]) >> 4][(ExtendKeyArray[i][nCol]) & 0x0F];
	}

	return ret;
}

/* 对列号是四的倍数的密钥扩展矩阵执行G函数
*	参数：ExtendKeyArray：输入的扩展密钥矩阵	nCol：输入的列号
*/
int G_Function(unsigned char(*ExtendKeyArray)[44], unsigned int nCol) {
	int ret = 0;

	//1、将扩展密钥矩阵的nCol-1列复制到nCol列上，并将nCol列第一行的元素移动到最后一行，其他行数上移一行
	for (int i = 0; i < 4; i++)
	{
		ExtendKeyArray[i][nCol] = ExtendKeyArray[(i + 1) % 4][nCol - 1];
	}

	//2、将nCol列进行S盒替换
	Key_S_Substitution(ExtendKeyArray, nCol);

	//3、将该列第一行元素与Rcon进行异或运算
	ExtendKeyArray[0][nCol] ^= Rcon[nCol / 4];

	return ret;
}


/* 计算扩展密钥数组
*	参数：keyArray: 输入的密钥字符串数组		ExtendKeyArray：输出的扩展密钥数组
*/
int CalculateExtendKeyArray(const unsigned char(*KeyArray)[4], unsigned char(*ExtendKeyArray)[44])
{
	int ret = 0;

	//1、将密钥数组放入前四列扩展密钥组
	for (int i = 0; i < 16; i++)
	{
		ExtendKeyArray[i & 0x03][i >> 2] = KeyArray[i & 0x03][i >> 2];
	}

	//2、计算扩展矩阵的后四十列
	for (int i = 1; i < 11; i++)	//进行十轮循环
	{
		//(1)如果列号是4的倍数，这执行G函数  否则将nCol-1列复制到nCol列上
		//该轮列数为4倍数的列先得到G函数处理后的列
		G_Function(ExtendKeyArray, 4 * i);

		//(2)每一轮中，各列进行异或运算
		// 1<= i <= 10
		//1 <= j <= 3
		//w[4i] = W[4(i - 1)] + G(W[4i - 1]);
		//w[4i + j] = W[4(i - 1) + j] + W[4i - 1 + j];

		//列号是4的倍数，和前一列进行异或
		for (int k = 0; k < 4; k++)//行号
		{
			ExtendKeyArray[k][4 * i] = ExtendKeyArray[k][4 * i] ^ ExtendKeyArray[k][4 * (i - 1)];
		}

		//此处必须先进行处理4倍数的列，因为后面的列需要与前一列进行异或

		//其他三列，上一轮的列和前一列进行异或
		for (int j = 1; j < 4; j++)//每一轮的列号
		{
			for (int k = 0; k < 4; k++)//行号
			{
				ExtendKeyArray[k][4 * i + j] = ExtendKeyArray[k][4 * i + j - 1] ^ ExtendKeyArray[k][4 * (i - 1) + j];
			}
		}
	}

	return ret;
}

/*	轮密钥加
*	参数：PlainArray：明文数组			ExtendKeyArray：扩展密钥数组	MinCol：输入的最小列号
*/
int AddRoundKey(unsigned char(*PlainArray)[4], unsigned char(*ExtendKeyArray)[44], unsigned int MinCol) {
	int ret = 0;

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			PlainArray[i][j] ^= ExtendKeyArray[i][MinCol + j];
		}
	}
	return ret;
}

/*	对明文矩阵进行S盒的字节代换
*	参数：PlainArray：输入的明文矩阵
*/
int Plain_S_Substitution(unsigned char* PlainArray) {
	int ret = 0;
	for (int i = 0; i < 16; i++)
		PlainArray[i] = S_Table[PlainArray[i] >> 4][PlainArray[i] & 0x0F];

	return ret;
}

/*	ShiftRows子层的行位移
*	参数：PlainArray：输入的明文矩阵（强制转换为int类型）
*/
int ShiftRows(unsigned int* PlainArray) {
	int ret = 0;

	//第一行不位移

	//第二行左移8bit
	PlainArray[1] = (PlainArray[1] >> 8) | (PlainArray[1] << 24);

	//第三行左移16bit
	PlainArray[2] = (PlainArray[2] >> 16) | (PlainArray[2] << 16);

	//第四行左移24bit
	PlainArray[3] = (PlainArray[3] >> 24) | (PlainArray[3] << 8);

	return ret;
}

/*	伽罗瓦域内的乘法运算
*	Num_L：左参数		Num_R：右参数
*/
char GaloisMultiplication(unsigned char Num_L, unsigned char Num_R) {
	unsigned char result = 0;
	while (Num_L)
	{
		//如果Num_L最低位为1则异或Num_R
		if (Num_L & 0x01)
		{
			result ^= Num_R;
		}

		Num_L = Num_L >> 1;

		if (Num_R & 0x80)
		{
			Num_R = Num_R << 1;

			Num_R ^= 0x1B;
		}
		else
		{
			Num_R = Num_R << 1;
		}
	}
	return result;
}

/*	MixColumn子层的列混淆
*	参数：PlainArray：输入的明文矩阵
*/
int MixColumn(unsigned char(*PlainArray)[4]) {
	int ret = 0;

	unsigned char ArrayTemp[4][4];

	memcpy(ArrayTemp, PlainArray, 16);

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			PlainArray[i][j] =
				GaloisMultiplication(MixArray[i][0], ArrayTemp[0][j]) ^
				GaloisMultiplication(MixArray[i][1], ArrayTemp[1][j]) ^
				GaloisMultiplication(MixArray[i][2], ArrayTemp[2][j]) ^
				GaloisMultiplication(MixArray[i][3], ArrayTemp[3][j]);
		}
	}
	return ret;
}

/*	AES加密
*	参数：PlainText：明文		key：密钥		CipherText：密文
*/
int AES_EnCryption(const unsigned char* PlainText, const unsigned char* Key, unsigned char* CipherText) {
	int ret = 0;

	unsigned char PlainArray[4][4];	//明文4*4矩阵
	unsigned char KeyArray[4][4];	//密钥扩展前的4*4矩阵
	unsigned char ExtendKeyArray[4][44];	//存储密钥扩展后的矩阵

	memset(PlainArray, 0, 16);
	memset(KeyArray, 0, 16);
	memset(ExtendKeyArray, 0, 176);

	StringToArray(PlainText, PlainArray);
	StringToArray(Key, KeyArray);

	CalculateExtendKeyArray(KeyArray, ExtendKeyArray);

	AddRoundKey(PlainArray, ExtendKeyArray, 0);

	for (int i = 1; i < 10; i++)
	{
		Plain_S_Substitution((unsigned char*)PlainArray);

		ShiftRows((unsigned int*)PlainArray);

		MixColumn(PlainArray);

		AddRoundKey(PlainArray, ExtendKeyArray, 4 * i);

		//学号最后一位为5，此处的轮密钥加为下一轮的开始
		/*if (i == 4)
		{
			char output[33] = { 0 };
			byteToHex(PlainArray, output, 32);
			printf("第5轮轮密钥加的输出结果：%s\n", output);
		}*/
	}

	Plain_S_Substitution((unsigned int*)PlainArray);

	ShiftRows((unsigned int*)PlainArray);

	AddRoundKey(PlainArray, ExtendKeyArray, 4 * 10);

	ArrayToString(PlainArray, CipherText);

	return ret;

}

/*	逆向ShiftRows子层的行位移
*	参数：CipherArray：输入的密文矩阵（强转为int类型）
*/
int ReShiftRows(unsigned int* CipherArray) {
	int ret = 0;

	//第一行不位移

	//第二行向右移8bit
	CipherArray[1] = (CipherArray[1] << 8) | (CipherArray[1] >> 24);

	//第三行向右移16bit
	CipherArray[2] = (CipherArray[2] << 16) | (CipherArray[2] >> 16);

	//第四行向右移24bit
	CipherArray[3] = (CipherArray[3] << 24) | (CipherArray[3] >> 8);

	return ret;
}

/*	逆向S盒字节代换
*	参数：CipherArray：输入的密文矩阵
*/
int Cipher_S_Substitution(unsigned char* CipherArray) {
	int ret = 0;

	for (int i = 0; i < 16; i++)
	{
		CipherArray[i] = ReS_Table[CipherArray[i] >> 4][CipherArray[i] & 0x0F];
	}

	return ret;
}

/*	逆向MixColum子层的列混淆
*	参数：CipherArray：输入的密文矩阵
*/
int ReMixColumn(unsigned char(*CipherArray)[4]) {
	int ret = 0;

	unsigned char ArrayTemp[4][4];

	memcpy(ArrayTemp, CipherArray, 16);

	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			CipherArray[i][j] =
				GaloisMultiplication(ReMixArray[i][0], ArrayTemp[0][j]) ^
				GaloisMultiplication(ReMixArray[i][1], ArrayTemp[1][j]) ^
				GaloisMultiplication(ReMixArray[i][2], ArrayTemp[2][j]) ^
				GaloisMultiplication(ReMixArray[i][3], ArrayTemp[3][j]);
		}
	}
	return ret;
}

/*	AES解密
*	参数：CipherText：密文字符串	Key：密钥		DeCipherText：解密后的字符串
*/
int AES_DeCryption(const unsigned char* CipherText, const unsigned char* Key, unsigned char* DeCipherText) {
	int ret = 0;

	unsigned char CipherArray[4][4];
	unsigned char KeyArray[4][4];
	unsigned char ExtendKeyArray[4][44];

	memset(CipherArray, 0, 16);
	memset(KeyArray, 0, 16);
	memset(ExtendKeyArray, 0, 176);

	StringToArray(CipherText, CipherArray);
	StringToArray(Key, KeyArray);

	CalculateExtendKeyArray(KeyArray, ExtendKeyArray);

	AddRoundKey(CipherArray, ExtendKeyArray, 4 * 10);

	ReShiftRows((unsigned int*)CipherArray);

	Cipher_S_Substitution((unsigned char*)CipherArray);

	for (int i = 9; i > 0; i--)
	{
		//(1)密钥加法层
		AddRoundKey(CipherArray, ExtendKeyArray, 4 * i);

		//(2)逆向列混淆
		ReMixColumn(CipherArray);

		//(3)逆向ShiftRows
		ReShiftRows((unsigned int*)CipherArray);

		//(4)逆向字节代换
		Cipher_S_Substitution((unsigned char*)CipherArray);
	}

	AddRoundKey(CipherArray, ExtendKeyArray, 0);

	ArrayToString(CipherArray, DeCipherText);

	return ret;
}

/* 字符串异或
*	参数：string1：字符串1		string2：字符串2	n：长度		out：结果
*/
int xor (const unsigned char* string1, const unsigned char* string2, int n, unsigned char* out) {
	int ret = 0;
	for (int i = 0; i < n; i++)
	{
		out[i] = string1[i] ^ string2[i];
	}
	out[n] = '\0';

	return ret;
}


int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {
	FILE* pFileCipher = fopen(cipherfile, "w");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "r");//打开密文文件

	char plain[17] = { 0 };
	char cipher[17] = { 0 };
	char key[17] = { 0 };
	char vi[17] = { 0 };
	char temp[17] = { 0 };
	char PlainText[33] = { 0 };
	char CipherText[33] = { 0 };
	char KeyText[33] = { 0 };
	char ViText[33] = { 0 };

	getText(keyfile, KeyText);
	getText(vifile, ViText);
	hexToByte(KeyText, key, 16);
	hexToByte(ViText, vi, 16);

	int flag = fread(PlainText, sizeof(char), 32, pFilePlain);
	hexToByte(PlainText, plain, 16);
	while (flag)
	{
		memcpy(temp, plain, 16);
		xor (temp, vi, 16, plain);
		AES_EnCryption(plain, key, cipher);

		byteToHex(cipher, CipherText, 32);

		fwrite(CipherText, sizeof(char), 32, pFileCipher);

		flag = fread(PlainText, sizeof(char), 32, pFilePlain);
		hexToByte(PlainText, plain, 16);
		memcpy(vi, cipher, 16);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}

int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	FILE* pFileCipher = fopen(cipherfile, "r");//打开密文文件
	FILE* pFilePlain = fopen(plainfile, "w");//打开密文文件

	char plain[17] = { 0 };
	char cipher[17] = { 0 };
	char key[17] = { 0 };
	char vi[17] = { 0 };
	char temp[17] = { 0 };
	char PlainText[33] = { 0 };
	char CipherText[33] = { 0 };
	char KeyText[33] = { 0 };
	char ViText[33] = { 0 };

	getText(keyfile, KeyText);
	getText(vifile, ViText);
	hexToByte(KeyText, key, 16);
	hexToByte(ViText, vi, 16);

	int flag = fread(CipherText, sizeof(char), 32, pFileCipher);
	hexToByte(CipherText, cipher, 16);
	while (flag)
	{
		AES_DeCryption(cipher, key, plain);

		memcpy(temp, plain, 16);
		xor (temp, vi, 16, plain);

		byteToHex(plain, PlainText, 32);

		fwrite(PlainText, sizeof(char), 32, pFilePlain);

		memcpy(vi, cipher, 16);
		flag = fread(CipherText, sizeof(char), 32, pFileCipher);
		hexToByte(CipherText, cipher, 16);

	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}
