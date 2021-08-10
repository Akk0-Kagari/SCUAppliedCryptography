#pragma once
void getText(char* filename, char* dest);//��ȡ�ı�����

void hexToByte(const unsigned char* hexString, unsigned char* byteString, int len);//��16���Ʊ�ʾ���ֽ�ת��Ϊchar

void byteToHex(const unsigned char* byteString, unsigned char* hexString, int len);//��byteת��Ϊ16����

int StringToArray(const unsigned char* String, unsigned char(*Array)[4]);//���ַ���ת��ΪAES��׼����

int ArrayToString(const unsigned char(*Array)[4], unsigned char* String);//��AES��׼����ת��Ϊ�ַ���

int Key_S_Substitution(unsigned char(*ExtendKeyArray)[44], unsigned int nCol);//��ָ������չ��Կ�����н���S���滻

int G_Function(unsigned char(*ExtendKeyArray)[44], unsigned int nCol);//���к����ĵı�������Կ��չ����ִ��G����

int CalculateExtendKeyArray(const unsigned char(*PasswordArray)[4], unsigned char(*ExtendKeyArray)[44]);//������չ��Կ����

int AddRoundKey(unsigned char(*PlainArray)[4], unsigned char(*ExtendKeyArray)[44], unsigned int MinCol);//����Կ��

int Plain_S_Substitution(unsigned char* PlainArray);//�����ľ������S�е��ֽڴ���

int ShiftRows(unsigned int* PlainArray);//ShiftRows

char GaloisMultiplication(unsigned char Num_L, unsigned char Num_R);//٤�������ڵĳ˷�����

int MixColumn(unsigned char(*PlainArray)[4]);//MixColumn

int AES_EnCryption(const unsigned char* PlainText, const unsigned char* Key, unsigned char* CipherText);//AES����

int ReShiftRows(unsigned int* CipherArray);//����ShiftRows

int Cipher_S_Substitution(unsigned char* CipherArray);//����S���ֽڴ���

int ReMixColumn(unsigned char(*CipherArray)[4]);//����Mixcolumn�л���

int AES_DeCryption(const unsigned char* CipherText, const unsigned char* PassWord, unsigned char* DeCipherText);//AES����

int xor(const unsigned char* string1, const unsigned char* string2, int n, unsigned char* out);//���

int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile);


int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile);
