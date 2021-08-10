#pragma once
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

int xor(const unsigned char* string1, const unsigned char* string2, int n, unsigned char* out);//异或

int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile);


int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile);
