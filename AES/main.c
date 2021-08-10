#include<stdio.h>
#include<string.h>
#include "table.h"
#include<time.h>

typedef struct {
	char* plainfile;
	char* keyfile;
	char* vifile;
	char* mode;
	char* cipherfile;
	char* decryption;
}s_param;


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

int xor(const unsigned char* string1, const unsigned char* string2,int n, unsigned char* out);//���

int RegMove(unsigned char* reg, unsigned char* patch, int n);//�Ĵ���λ��

int ECB(char* plainfile, char* keyfile, char* cipherfile);

int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile);

int CFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile);

int OFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile);

int deECB(char* cipherfile, char* keyfile, char* plainfile);

int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile);

int deCFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile);

int deOFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile);

void test(s_param param);

int main(int argc, char* argv[]) {
	s_param param;
	int i = 1;
	param.plainfile = "aes_plain.txt";
	param.cipherfile = "aes_cipher.txt";
	param.keyfile = "aes_key.txt";
	param.mode = "ECB";
	param.vifile = "aes_vi.txt";
	param.decryption = "aes_decryption.txt";

	test(param);

	while (i < argc)
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

/* ��ȡ�ļ��еĲ���(��ȡ��Կ������)
* ������filename���ļ���		dest�����صĶ������ַ���
* ��ȡ���ģ���Կ����ʼ������
*/
void getText(char* filename, char* dest) {
	FILE* pFile = fopen(filename, "r");
	if (pFile == NULL) {
		printf("�ļ���ʧ�ܣ�\n");
	}
	unsigned char content[33] = {0};
	
	fread(content, sizeof(char), 32, pFile);

	memcpy(dest, content,32);

}

/* ��16���Ʊ�ʾ���ֽ�ת��Ϊchar
* ������hexString��16�����ַ���		byteString���ֽ��ַ���		len���ֽڳ���	
*/
void hexToByte(const unsigned char* hexString, unsigned char* byteString,int len) {
	char bytes[17] = { 0 };
	int a, b,res;//�ֱ�Ϊ16���Ƶ���λ,resΪ��Ӧ��10����
	int i = 0,j=0;
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
		i+=2;
	}
	memcpy(byteString, bytes, len);
}

/* ��byteת��Ϊ16����
* ������byteString���ֽڴ�		hexString��16���ƴ�		len��16���ƴ�����
*/
void byteToHex(const unsigned char* byteString, unsigned char* hexString, int len) {
	char hex[33] = { 0 };
	int i = 0;
	int a, b;//16���Ƶ���λ
	while (i < len/2)
	{
		int temp = (int)byteString[i];
		a = temp / 16;
		b = temp % 16;
		switch (a)
		{
		case 10:
			hex[i*2] = 'A';
			break;
		case 11:
			hex[i*2] = 'B';
			break;
		case 12:
			hex[i*2] = 'C';
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
			hex[i * 2 +1] = 'A';
			break;
		case 11:
			hex[i * 2 +1] = 'B';
			break;
		case 12:
			hex[i * 2 +1] = 'C';
			break;
		case 13:
			hex[i * 2 +1] = 'D';
			break;
		case 14:
			hex[i * 2 +1] = 'E';
			break;
		case 15:
			hex[i * 2 +1] = 'F';
			break;
		default:
			hex[i * 2 +1] = b + 48;
			break;
		}
		i++;
	}
	memcpy(hexString, hex, len);
	
}

/*���ַ���ת��ΪAES��׼����
* ������String��������ַ���	Array�������AES��׼����
*/
int StringToArray(const unsigned char* String, unsigned char(*Array)[4]) {
	int ret = 0;

	for (int i = 0; i < 16; i++)
	{
		Array[i & 0x03][i >> 2] = String[i];
	}

	return ret;
}

/*	��AES��׼����ת�����ַ���
*	������Array�������AES��׼����		String��������ַ���
*/
int ArrayToString(const unsigned char(*Array)[4], unsigned char* String) {
	int ret = 0;

	for (int i = 0; i < 16; i++)
	{
		String[i] = Array[i & 0x03][i >> 2];
	}

	return ret;
}

/* ��ָ������չ��Կ�����н���S���滻
* ������ExtendKeyArray���������չ��Կ����	nCol��������к�
* 
*/
int Key_S_Substitution(unsigned char(*ExtendKeyArray)[44], unsigned int nCol) {
	int ret = 0;

	for (int i = 0; i < 4; i++)
	{
		//>>4	ȡ�к�	&0x0F ȡ�к�
		ExtendKeyArray[i][nCol] = S_Table[(ExtendKeyArray[i][nCol]) >> 4][(ExtendKeyArray[i][nCol]) & 0x0F];
	}

	return ret;
}

/* ���к����ĵı�������Կ��չ����ִ��G����
*	������ExtendKeyArray���������չ��Կ����	nCol��������к�
*/
int G_Function(unsigned char(*ExtendKeyArray)[44], unsigned int nCol) {
	int ret = 0;

	//1������չ��Կ�����nCol-1�и��Ƶ�nCol���ϣ�����nCol�е�һ�е�Ԫ���ƶ������һ�У�������������һ��
	for (int i = 0; i < 4; i++)
	{
		ExtendKeyArray[i][nCol] = ExtendKeyArray[(i + 1) % 4][nCol - 1];
	}

	//2����nCol�н���S���滻
	Key_S_Substitution(ExtendKeyArray, nCol);

	//3�������е�һ��Ԫ����Rcon�����������
	ExtendKeyArray[0][nCol] ^= Rcon[nCol / 4];

	return ret;
}


/* ������չ��Կ����
*	������keyArray: �������Կ�ַ�������		ExtendKeyArray���������չ��Կ����
*/
int CalculateExtendKeyArray(const unsigned char(*KeyArray)[4], unsigned char(*ExtendKeyArray)[44])
{
	int ret = 0;

	//1������Կ�������ǰ������չ��Կ��
	for (int i = 0; i < 16; i++)
	{ 
		ExtendKeyArray[i & 0x03][i >> 2] = KeyArray[i & 0x03][i >> 2];
	}

	//2��������չ����ĺ���ʮ��
	for (int i = 1; i < 11; i++)	//����ʮ��ѭ��
	{
		//(1)����к���4�ı�������ִ��G����  ����nCol-1�и��Ƶ�nCol����
		//��������Ϊ4���������ȵõ�G�������������
		G_Function(ExtendKeyArray, 4 * i);

		//(2)ÿһ���У����н����������
		// 1<= i <= 10
		//1 <= j <= 3
		//w[4i] = W[4(i - 1)] + G(W[4i - 1]);
		//w[4i + j] = W[4(i - 1) + j] + W[4i - 1 + j];
		
		//�к���4�ı�������ǰһ�н������
		for (int k = 0; k < 4; k++)//�к�
		{
			ExtendKeyArray[k][4 * i] = ExtendKeyArray[k][4 * i] ^ ExtendKeyArray[k][4 * (i - 1)];
		}

		//�˴������Ƚ��д���4�������У���Ϊ���������Ҫ��ǰһ�н������

		//�������У���һ�ֵ��к�ǰһ�н������
		for (int j = 1; j < 4; j++)//ÿһ�ֵ��к�
		{
			for (int k = 0; k < 4; k++)//�к�
			{
				ExtendKeyArray[k][4 * i + j] = ExtendKeyArray[k][4 * i + j - 1] ^ ExtendKeyArray[k][4 * (i - 1) + j];
			}
		}
	}

	return ret;
}

/*	����Կ��
*	������PlainArray����������			ExtendKeyArray����չ��Կ����	MinCol���������С�к�
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

/*	�����ľ������S�е��ֽڴ���
*	������PlainArray����������ľ���
*/
int Plain_S_Substitution(unsigned char* PlainArray) {
	int ret = 0;
	for (int i = 0; i < 16; i++)
		PlainArray[i] = S_Table[PlainArray[i] >> 4][PlainArray[i] & 0x0F];

	return ret;
}

/*	ShiftRows�Ӳ����λ��
*	������PlainArray����������ľ���ǿ��ת��Ϊint���ͣ�
*/
int ShiftRows(unsigned int* PlainArray) {
	int ret = 0;

	//��һ�в�λ��

	//�ڶ�������8bit
	PlainArray[1] = (PlainArray[1] >> 8) | (PlainArray[1] << 24);
	
	//����������16bit
	PlainArray[2] = (PlainArray[2] >> 16) | (PlainArray[2] << 16);

	//����������24bit
	PlainArray[3] = (PlainArray[3] >> 24) | (PlainArray[3] << 8);

	return ret;
}

/*	٤�������ڵĳ˷�����
*	Num_L�������		Num_R���Ҳ���
*/
char GaloisMultiplication(unsigned char Num_L, unsigned char Num_R) {
	unsigned char result = 0;
	while (Num_L)
	{
		//���Num_L���λΪ1�����Num_R
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

/*	MixColumn�Ӳ���л���
*	������PlainArray����������ľ���
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

/*	AES����
*	������PlainText������		key����Կ		CipherText������
*/
int AES_EnCryption(const unsigned char* PlainText, const unsigned char* Key, unsigned char* CipherText) {
	int ret = 0;

	unsigned char PlainArray[4][4];	//����4*4����
	unsigned char KeyArray[4][4];	//��Կ��չǰ��4*4����
	unsigned char ExtendKeyArray[4][44];	//�洢��Կ��չ��ľ���

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

	}

	Plain_S_Substitution((unsigned int*)PlainArray);

	ShiftRows((unsigned int*)PlainArray);

	AddRoundKey(PlainArray, ExtendKeyArray, 4 * 10);

	ArrayToString(PlainArray, CipherText);

	return ret;

}

/*	����ShiftRows�Ӳ����λ��
*	������CipherArray����������ľ���ǿתΪint���ͣ�
*/
int ReShiftRows(unsigned int* CipherArray) {
	int ret = 0;

	//��һ�в�λ��

	//�ڶ���������8bit
	CipherArray[1] = (CipherArray[1] << 8) | (CipherArray[1] >> 24);

	//������������16bit
	CipherArray[2] = (CipherArray[2] << 16) | (CipherArray[2] >> 16);

	//������������24bit
	CipherArray[3] = (CipherArray[3] << 24) | (CipherArray[3] >> 8);

	return ret;
}

/*	����S���ֽڴ���
*	������CipherArray����������ľ���
*/
int Cipher_S_Substitution(unsigned char* CipherArray) {
	int ret = 0;

	for (int i = 0; i < 16; i++)
	{
		CipherArray[i] = ReS_Table[CipherArray[i] >> 4][CipherArray[i] & 0x0F];
	}

	return ret;
}

/*	����MixColum�Ӳ���л���
*	������CipherArray����������ľ���
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

/*	AES����
*	������CipherText�������ַ���	Key����Կ		DeCipherText�����ܺ���ַ���
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
		//(1)��Կ�ӷ���
		AddRoundKey(CipherArray, ExtendKeyArray, 4 * i);

		//(2)�����л���
		ReMixColumn(CipherArray);

		//(3)����ShiftRows
		ReShiftRows((unsigned int*)CipherArray);

		//(4)�����ֽڴ���
		Cipher_S_Substitution((unsigned char*)CipherArray);
	}

	AddRoundKey(CipherArray, ExtendKeyArray, 0);

	ArrayToString(CipherArray, DeCipherText);

	return ret;
}

/* �ַ������
*	������string1���ַ���1		string2���ַ���2	n������		out�����
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

/*	�Ĵ���λ��
*	������reg���Ĵ���	patch��λ�ƺ����Ķ���		n��λ�Ƴ���
*/
int RegMove(unsigned char* reg, unsigned char* patch, int n) {
	int j, i = 0, ret = 0;
	while (i < 16 - n)
	{
		reg[i] = reg[i + n];
		i++;
	}
	for (j = 0; j < n; j++)
		reg[i + j] = patch[j];
	
	return ret;
}


int ECB(char* plainfile, char* keyfile, char* cipherfile) {
	FILE* pFileCipher = fopen(cipherfile, "w");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "r");//�������ļ�

	char plain[17] = { 0 };
	char cipher[17] = { 0 };
	char key[17] = { 0 };
	char PlainText[33] = { 0 };
	char CipherText[33] = { 0 };
	char KeyText[33] = { 0 };

	int i = 0;
	getText(keyfile, KeyText);
	hexToByte(KeyText, key, 16);

	int flag = fread(PlainText, sizeof(char), 32, pFilePlain);
	hexToByte(PlainText, plain, 16);
	while (flag)
	{
		AES_EnCryption(plain, key, cipher);
		byteToHex(cipher, CipherText, 32);

		fwrite(CipherText, sizeof(char), 32, pFileCipher);

		flag = fread(PlainText, sizeof(char), 32, pFilePlain);
		hexToByte(PlainText, plain, 16);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}


int deECB(char* cipherfile, char* keyfile, char* plainfile) {
	FILE* pFileCipher = fopen(cipherfile, "r");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "w");//�������ļ�

	char plain[17] = { 0 };
	char cipher[17] = { 0 };
	char key[17] = { 0 };
	char PlainText[33] = { 0 };
	char CipherText[33] = { 0 };
	char KeyText[33] = { 0 };

	int i = 0;
	getText(keyfile, KeyText);
	hexToByte(KeyText, key, 16);

	int flag = fread(CipherText, sizeof(char), 32, pFileCipher);
	hexToByte(CipherText, cipher, 16);
	while (flag)
	{
		//AES_EnCryption(plain, key, cipher);
		AES_DeCryption(cipher, key, plain);
		byteToHex(plain, PlainText, 32);

		fwrite(PlainText, sizeof(char), 32, pFilePlain);

		flag = fread(CipherText, sizeof(char), 32, pFileCipher);
		hexToByte(CipherText, cipher, 16);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}


int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {
	FILE* pFileCipher = fopen(cipherfile, "w");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "r");//�������ļ�
	
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
	hexToByte(KeyText, key,16);
	hexToByte(ViText, vi,16);

	int flag = fread(PlainText, sizeof(char), 32, pFilePlain);
	hexToByte(PlainText, plain, 16);
	while (flag)
	{
		memcpy(temp, plain,16);
		xor (temp, vi, 16, plain);
		AES_EnCryption(plain, key, cipher);

		byteToHex(cipher, CipherText, 32);

		fwrite(CipherText, sizeof(char), 32, pFileCipher);

		flag = fread(PlainText, sizeof(char), 32, pFilePlain);
		hexToByte(PlainText, plain, 16);
		memcpy(vi, cipher,16);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}

int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	FILE* pFileCipher = fopen(cipherfile, "r");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "w");//�������ļ�

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

		memcpy(temp, plain,16);
		xor (temp, vi, 16, plain);

		byteToHex(plain, PlainText, 32);

		fwrite(PlainText, sizeof(char), 32, pFilePlain);

		memcpy(vi, cipher,16);
		flag = fread(CipherText, sizeof(char), 32, pFileCipher);
		hexToByte(CipherText, cipher, 16);
		
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}


int CFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {
	FILE* pFileCipher = fopen(cipherfile, "w");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "r");//���������ļ�

	char plain[5] = { 0 };
	char cipher[5] = { 0 };
	char key[17] = { 0 };
	char vi[17] = { 0 };
	char PlainText[9] = { 0 };
	char CipherText[9] = { 0 };
	char KeyText[33] = { 0 };
	char ViText[33] = { 0 };
	char reg[17] = { 0 };
	char temp[5] = { 0 };
	char output[17] = { 0 };//�洢��λ�Ĵ������ܺ���

	getText(keyfile, KeyText);
	getText(vifile, ViText);
	hexToByte(KeyText, key, 16);
	hexToByte(ViText, vi, 16);
	memcpy(reg, vi,16);

	int flag = fread(PlainText, sizeof(char), 8, pFilePlain);
	hexToByte(PlainText, plain, 4);

	while (flag)
	{
		AES_EnCryption(reg, key, output);

		memcpy(temp, output, 4);

		xor (plain, temp, 4, cipher);
		byteToHex(cipher, CipherText, 8);

		fwrite(CipherText, sizeof(char), 8, pFileCipher);

		RegMove(reg, cipher, 4);
		flag = fread(PlainText, sizeof(char), 8, pFilePlain);
		hexToByte(PlainText, plain, 4);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;

}


int deCFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	FILE* pFileCipher = fopen(cipherfile, "r");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "w");//���������ļ�

	char plain[5] = { 0 };
	char cipher[5] = { 0 };
	char key[17] = { 0 };
	char vi[17] = { 0 };
	char PlainText[9] = { 0 };
	char CipherText[9] = { 0 };
	char KeyText[33] = { 0 };
	char ViText[33] = { 0 };
	char reg[17] = { 0 };
	char temp[5] = { 0 };
	char output[17] = { 0 };//�洢��λ�Ĵ������ܺ���

	getText(keyfile, KeyText);
	getText(vifile, ViText);
	hexToByte(KeyText, key, 16);
	hexToByte(ViText, vi, 16);
	memcpy(reg, vi,16);

	int flag = fread(CipherText, sizeof(char), 8, pFileCipher);
	hexToByte(CipherText, cipher, 4);

	while (flag)
	{
		AES_EnCryption(reg, key, output);

		memcpy(temp, output, 4);

		xor (cipher, temp, 4, plain);
		byteToHex(plain, PlainText, 8);

		fwrite(PlainText, sizeof(char), 8, pFilePlain);

		RegMove(reg, cipher, 4);
		flag = fread(CipherText, sizeof(char), 8, pFileCipher);
		hexToByte(CipherText, cipher, 4);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}


int OFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {
	FILE* pFileCipher = fopen(cipherfile, "w");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "r");//���������ļ�

	char plain[5] = { 0 };
	char cipher[5] = { 0 };
	char key[17] = { 0 };
	char vi[17] = { 0 };
	char PlainText[9] = { 0 };
	char CipherText[9] = { 0 };
	char KeyText[33] = { 0 };
	char ViText[33] = { 0 };
	char reg[17] = { 0 };
	char temp[5] = { 0 };
	char output[17] = { 0 };//�洢��λ�Ĵ������ܺ���

	getText(keyfile, KeyText);
	getText(vifile, ViText);
	hexToByte(KeyText, key, 16);
	hexToByte(ViText, vi, 16);
	memcpy(reg, vi,16);

	int flag = fread(PlainText, sizeof(char), 8, pFilePlain);
	hexToByte(PlainText, plain, 4);

	while (flag)
	{
		AES_EnCryption(reg, key, output);

		memcpy(temp, output, 4);

		xor (plain, temp, 4, cipher);
		byteToHex(cipher, CipherText, 8);

		fwrite(CipherText, sizeof(char), 8, pFileCipher);

		RegMove(reg, temp, 4);
		flag = fread(PlainText, sizeof(char), 8, pFilePlain);
		hexToByte(PlainText, plain, 4);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}


int deOFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	FILE* pFileCipher = fopen(cipherfile, "r");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "w");//���������ļ�

	char plain[5] = { 0 };
	char cipher[5] = { 0 };
	char key[17] = { 0 };
	char vi[17] = { 0 };
	char PlainText[9] = { 0 };
	char CipherText[9] = { 0 };
	char KeyText[33] = { 0 };
	char ViText[33] = { 0 };
	char reg[17] = { 0 };
	char temp[5] = { 0 };
	char output[17] = { 0 };//�洢��λ�Ĵ������ܺ���

	getText(keyfile, KeyText);
	getText(vifile, ViText);
	hexToByte(KeyText, key, 16);
	hexToByte(ViText, vi, 16);
	memcpy(reg, vi,16);

	int flag = fread(CipherText, sizeof(char), 8, pFileCipher);
	hexToByte(CipherText, cipher, 4);

	while (flag)
	{
		AES_EnCryption(reg, key, output);

		memcpy(temp, output, 4);

		xor (cipher, temp, 4, plain);
		byteToHex(plain, PlainText, 8);

		fwrite(PlainText, sizeof(char), 8, pFilePlain);

		RegMove(reg, temp, 4);
		flag = fread(CipherText, sizeof(char), 8, pFileCipher);
		hexToByte(CipherText, cipher, 4);
	}
	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}


void test(s_param param) {
	clock_t start, end;
	int alltime = 0;
	double avgspeed = 0, nowspeed = 0;

	/***************** ECB *****************/
	/*for(int i = 0;i < 10;i++){
		start = clock();
		ECB(param.plainfile, param.keyfile, param.cipherfile);
		deECB(param.cipherfile, param.keyfile, param.decryption);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i)/ (i + 1);
		printf("��%d�֣�ECB������ʱ��%d ms\t�ٶȣ�%.3f MByete/s\n",i+1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n20��ECB������ʱ��%d ms�ٶȣ�%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** CBC *****************/
	/*for (int i = 0; i < 10; i++) {
		start = clock();
		CBC(param.plainfile, param.keyfile, param.cipherfile,param.vifile);
		deCBC(param.cipherfile, param.keyfile, param.decryption,param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("��%d�֣�CBC������ʱ��%d ms\t�ٶȣ�%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n10��CBC������ʱ��%d ms�ٶȣ�%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** CFB *****************/
	/*for (int i = 0; i < 10; i++) {
		start = clock();
		CFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deCFB(param.cipherfile, param.keyfile, param.decryption, param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("��%d�֣�CFB������ʱ��%d ms\t�ٶȣ�%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n10��CFB������ʱ��%d ms�ٶȣ�%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** OFB *****************/
	/*for (int i = 0; i < 10; i++) {
		start = clock();
		OFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deOFB(param.cipherfile, param.keyfile, param.decryption, param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("��%d�֣�OFB������ʱ��%d ms\t�ٶȣ�%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n10��OFB������ʱ��%d ms�ٶȣ�%.3f MByete/s\n", alltime, avgspeed);*/


	/*some test in programming*/
	/* getText test */
	/*char plain[33] = { 0 };
	char key[33] = { 0 };
	char vi[33] = { 0 };
	getText(param.plainfile,plain);
	getText(param.keyfile, key);
	getText(param.vifile, vi);
	printf("%s\n",plain);
	printf("%s\n", key);
	printf("%s\n", vi);*/

	/* hexToByte & byteToHex test*/
	/*unsigned char plain[33] = "7970746F6437277B5365637572697479";
	unsigned char byteString[17] = { 0 };
	unsigned char hexString[33] = { 0 };
	hexToByte(plain, byteString, 4);
	printf("%s\n", byteString);
	byteToHex(byteString, hexString, 8);
	printf("%s\n", hexString);*/
}
