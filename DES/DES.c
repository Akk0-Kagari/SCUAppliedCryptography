#include<stdio.h>
#include<string.h>
#include "tables.h"    //���ݱ�
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

void premutation(char* in, char* out, int n, char* P);//��ʼIP�û�

void xor (char* in1, char* in2, int n, char* out);//��K���������

void circleShift(char* In, char* Out, int n, int s);//ѭ������

void subKey(char* K, char(*SK)[49]);//��������Կ����

void functionF(char* L, char* R, char* SK, int t);//f����

void hexToBin(char* str, char* dest, int times);//16����ת2����

void binToHex(char* sSrc, char* sDest, int times);//2����ת16����

void getText(char* filename, char* dest);//��ȡ�ı�����

void move(char* reg, char* cipher, int t);//��λ

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
��ʼ�û�
������in�����û�����ָ��	out���û����ָ��	n���û�����	P���û���ָ��
ͨ�����ָ����ָ��������滻Ϊ������������Ӧλ�õ����ݡ�
*/
void premutation(char* in, char* out, int n, char* P) {
	int i = 0;
	for ( i = 0; i < n; i++)
		*(out + i) = *(in + *(P + i) - 1);
	*(out + i) = '\0';
}


/* �������
������in1�������ƴ���in2�������ƴ���n�������Ƴ��� Out�������
ѭ������������������ƴ���ÿһλ
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


/*ѭ������
������In������λ�ַ���	Out����λ���ַ��� n:�����ƴ�����	s��ѭ��λ��
ʵ��ѭ�������ƶ����ƴ�
*/
void circleShift(char* In, char* Out, int n, int s) {
	for (int i = 0; i < n; i++)
		*(Out + i) = *(In + (s + i) % n);
	*(Out + n) = '\0';
}


/*��������Կ
������K��64λ��Կ	(*SK)[49]���õ���һ������Կ
��64λ��Կͨ��PC-1�û�����56λ��16�ֵõ�16������Կ��ÿһ����Կ�ֳ�����������Ӧ����λ������Ȼ��ͨ��PC-2�û��õ�������Կ��
*/
void subKey(char* K, char(*SK)[49]) {
	char out[57], C[57], D[29], e[29], t[57];
	premutation(K, out, 56, *PC_1);
	strcpy(C, out);		//C0
	strcpy(D, out + 28);	//D0
	for (int j = 0; j < 16; j++)
	{
		circleShift(C, e, 28, move_time[j]);		//ѭ������	
		strcpy(C, e);								//Cj
		circleShift(D, e, 28,move_time[j]);
		strcpy(D, e);								//Dj
		strncpy(t, C, 28);
		strncpy(t + 28, D, 28);
		premutation(t, *(SK + j), 48, *PC_2);	//ѡ���û����õ�Kj
	}
}


/*f����
������L����t�ֵ�32λL��	R����t�ֵ�32λR��	SK����t�ֵ�48λ����Կ	t������
�������32λR�����ݽ�����չ�û�������48λ�����ݡ����û����48λ����������48λ����Կ����������㣬�õ�48λ����������
��48λ�������ֳ�8�飬ÿ��6Bit���ݣ�������Ŷ�Ӧ��Ӧ��S�У�����8��S���û�������8��4Bit�����ݡ�����8��4Bit���ݺϲ����õ�һ��32λ���ݡ���32λ�����û�P�͵õ�����32λ��������
*/
void functionF(char* L, char* R, char* SK, int t) {
	int i = 0, j = 0;
	char out1[49] = { 0 }, out2[49] = { 0 }, out3[33] = { 0 }, out4[33] = { 0 }, temp[33] = { 0 };
	//out1���������չ�û��������
	//out2�������������Կ����Ľ��
	//out3�������S�д�����Ľ��
	//out4�������P�û���Ľ��
	//temp���ڱ����R
	int row, col;

	premutation(R, out1, 48, *E);//��չ�û�E

	xor (out1, SK, 48, out2);//������Կ���
	
	for (i = 0; i < 8; i++)
	{
		//�к�
		row = (((out2[i * 6]) - '0') << 1) + ((out2[i * 6 + 5]) - '0');
		//�к�
		col = (((out2[i * 6 + 1]) - '0') << 3) + (((out2[i * 6 + 2]) - '0') << 2) + (((out2[i * 6 + 3]) - '0') << 1) + ((out2[i * 6 + 4]) - '0');
		
		for (j = 3; j >= 0; j--)
			*(out3 + (i * 4 + 3 - j)) = ((S_Box[i][row * 16 + col] >> j) & 1) + '0';
	}
	*(out3 + 32) = "\0";
	premutation(out3, out4, 32, *P);

	strcpy(temp, R);//�����R
	xor (L, out4, 32, R);//����R

	strcpy(L, temp);//����L
}

/* 16�����ַ���ת2�����ַ��� 
������str��16�����ַ���		dest��2�����ַ���		times��2�����ַ�������	
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


/* 2�����ַ���ת16�����ַ���
������str��2�����ַ���		dest��16�����ַ���		times��16�����ַ�������
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

/*��ȡ�ı��еĲ���
������filename���ļ���		dest�����صĶ������ַ���
�Ѿ���16����ת��Ϊ2����
*/
void getText(char* filename, char* dest) {
	FILE* pFile = fopen(filename, "r");
	if (pFile == NULL)
	{
		printf("�ļ���ʧ��\n");
	}
	char output[65] = { 0 };//��Կ������
	char key[17] = { 0 };//��Կ16����
	fread(key, sizeof(char), 16, pFile);
	fclose(pFile);//�ر��ļ�������
	hexToBin(key, output, 64);
	strcpy(dest, output);
}


/* ��λ 
������reg:�Ĵ���	cipher������	t���ƶ�λ��
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


/*	DES����
*	������plainBit�����Ķ�����	keyBit����Կ������	cipherBit�����Ķ�����
*/
void DES_Encryption(char* plainBit, char* keyBit, char* cipherBit) {
	char* K = keyBit;//��Կ
	char* M = plainBit;//����

	char out[65], L[33], R[33], SK[16][49];
	//out:��ų�ʼ�û��������
	//L:L��
	//R:R��
	//SK:����Կ

	subKey(K, SK);//16������Կ
	premutation(M, out, 64, *IP);//��ʼ�û�IP

	strncpy(L, out, 32);
	strcpy(R, out + 32);

	//16��
	for (int i = 0; i < 16; i++)
	{
		functionF(L, R, *(SK + i), i);
	}

	strncpy(out, R, 32);
	strncpy(out + 32, L, 32);

	//���ʼ�û�
	premutation(out, cipherBit, 64, *C_IP);
}

/*	DES����
*	������cipherBit�����Ķ�����	keyBit����Կ������	plainBit�����Ķ�����
*/
void DES_Decryption(char* cipherBit, char* keyBit, char* plainBit) {
		char* K = keyBit;//��Կ
		char* C = cipherBit;//����

		char out[65], L[33], R[33], SK[16][49];
		////out:��ų�ʼ�û��������
		////L:L��
		////R:R��
		////SK:����Կ

		
		subKey(K, SK);//16������Կ
		premutation(C, out, 64, *IP);//��ʼ�û�IP

		strncpy(L, out, 32);
		strcpy(R, out + 32);

		//16��
		for (int i = 0; i < 16; i++)
		{
			functionF(L, R, *(SK + 15 - i), i);
		}

		strncpy(out, R, 32);
		strncpy(out + 32, L, 32);

		//���ʼ�û�
		premutation(out, plainBit, 64, *C_IP);
}

/* ECB
������plainfile�������ļ���	keyfile����Կ�ļ���	cipherfile�������ļ���
�������뱾ECBģʽ����򵥵�ģʽ����ֱ�����ü����㷨�ֱ��ÿ�����ķ���ʹ����ͬ��Կ���м��ܡ�
*/
int ECB(char* plainfile, char* keyfile, char* cipherfile) {
	
	char plainBit[65] = { 0 };//���Ķ�����
	char keyBit[65] = { 0 };//��Կ������
	char cipherBit[65] = { 0 };//���Ķ�����
	char plain[17] = { 0 };//����16����
	char cipher[17] = { 0 };//����16����
	

	FILE* pFileCipher = fopen(cipherfile, "w");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "r");//�������ļ�

	int i = 0;
	getText(keyfile, keyBit);
	int flag = fread(plain, sizeof(char), 16, pFilePlain);
	while (flag)
	{
		hexToBin(plain, plainBit, 64);

		DES_Encryption(plainBit, keyBit, cipherBit);
		
		binToHex(cipherBit, cipher, 16);

		fwrite(cipher, sizeof(char), 16, pFileCipher);//д������

		flag = fread(plain, sizeof(char), 16, pFilePlain);//��ȡ��һ������

	}
	fclose(pFilePlain);
	fclose(pFileCipher);
	return 0;
}

/*deECB
*������cipherfile�������ļ���	keyfile����Կ�ļ���	plainfile�������ļ���
*/
int deECB(char* cipherfile, char* keyfile, char* plainfile) {

	char plainBit[65] = { 0 };//���Ķ�����
	char keyBit[65] = { 0 };//��Կ������
	char cipherBit[65] = { 0 };//���Ķ�����
	char plain[17] = { 0 };//����16����
	char cipher[17] = { 0 };//����16����


	FILE* pFileCipher = fopen(cipherfile, "r");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "w");//�������ļ�

	int i = 0;
	getText(keyfile, keyBit);
	int flag = fread(cipher, sizeof(char), 16, pFileCipher);
	while (flag)
	{
		hexToBin(cipher, cipherBit, 64);

		DES_Decryption(cipherBit, keyBit, plainBit);
		binToHex(plainBit, plain, 16);

		fwrite(plain, sizeof(char), 16, pFilePlain);//д������

		flag = fread(cipher, sizeof(char), 16, pFileCipher);//��ȡ��һ������

	}
	fclose(pFilePlain);
	fclose(pFileCipher);
	return 0;
}


/*CBC
������plainfile�������ļ���	keyfile����Կ�ļ���	cipherfile�������ļ��� vifile����ʼ�����ļ���
��CBCģʽ�У������㷨�������ǵ�ǰ�����ķ������һ�εĲ��������ķ������������Ϊ��ǰ�����ķ���
*/
int CBC(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {
	char plainBit[65] = { 0 };//���Ķ�����
	char keyBit[65] = { 0 };//��Կ������
	char cipherBit[65] = { 0 };//���Ķ�����
	char ivBit[65] = { 0 };//iv������
	char temp[65] = { 0 };

	char plain[17] = { 0 };//����16����
	char cipher[17] = { 0 };//����16����


	FILE* pFileCipher = fopen(cipherfile, "w");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "r");//�������ļ�

	int i = 0;
	
	int flag = fread(plain, sizeof(char), 16, pFilePlain);
	getText(keyfile, keyBit);//�õ���Կ������
	getText(vifile, ivBit);//�õ�����������
	hexToBin(plain, plainBit, 64);//�õ����Ķ�����
	strcpy(temp, plainBit);
	xor (temp, ivBit, 64, plainBit);//�������������

	while (flag)
	{
		DES_Encryption(plainBit, keyBit, cipherBit);

		binToHex(cipherBit, cipher, 16);

		fwrite(cipher, sizeof(char), 16, pFileCipher);

		flag = fread(plain, sizeof(char), 16, pFilePlain);
		hexToBin(plain, plainBit, 64);
		strcpy(temp, cipherBit);
		xor (plainBit, temp, 64, plainBit);//���ĺ�Ҫ���ܵ��������
	}

	fclose(pFileCipher);
	fclose(pFilePlain);
	return 0;
}

/*deCBC
*������cipherfile�������ļ���	keyfile����Կ�ļ���	plainfile�������ļ��� vifile�������ļ���
*/
int deCBC(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	char plainBit[65] = { 0 };//���Ķ�����
	char keyBit[65] = { 0 };//��Կ������
	char cipherBit[65] = { 0 };//���Ķ�����
	char ivBit[65] = { 0 };//iv������
	char temp[65] = { 0 };

	char plain[17] = { 0 };//����16����
	char cipher[17] = { 0 };//����16����


	FILE* pFileCipher = fopen(cipherfile, "r");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "w");//�������ļ�

	int i = 0;

	int flag = fread(cipher, sizeof(char), 16, pFileCipher);
	getText(keyfile, keyBit);//�õ���Կ������
	getText(vifile, ivBit);//�õ�����������
	hexToBin(cipher, cipherBit, 64);//�õ����Ķ�����
	
	//strcpy(temp, output1);
	//xor (temp, output4, 64, output1);//�������������

	while (flag)
	{
		DES_Decryption(cipherBit, keyBit, plainBit);

		strcpy(temp, plainBit);
		xor (temp, ivBit, 64, plainBit);//�������������

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
������plainfile�������ļ���	keyfile����Կ�ļ���	cipherfile�������ļ��� vifile����ʼ�����ļ���
��sλCFBģʽ�����ܺ�����������һ��bλ����λ�Ĵ����������λ�Ĵ�������ʼ��Ϊһ����ʼ����IV�����ܺ��������������λ������ߣ���sλ�����ĵĵ�һ�����������������һ�����ķ��顣
ͬʱ����λ�Ĵ�����ֵ������sλ���������ķ����滻�Ĵ�������ͣ����ұߣ���sλ��
����ѡ�õ�sΪ8
*/
int CFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {

	char regBit[65] = { 0 };//��λ�Ĵ���2����
	char keyBit[65] = { 0 };//��Կ2����
	char outputBit[65] = { 0 };//���2����
	char ivBit[65] = { 0 };//��ʼ������2����
	char cipherBit[9] = { 0 };//����2����
	char plainBit[9] = { 0 };//����2����
	char plain[3] = { 0 };//����16����
	char cipher[3] = { 0 };//����16����

	
	char temp[9] = { 0 };//�����м����

	getText(keyfile, keyBit);//�����Կ������
	getText(vifile, ivBit);//��ó�ʼ����������

	FILE* pFileCipher = fopen(cipherfile, "w");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "r");//�������ļ�

	int flag = fread(plain, sizeof(char), 2, pFilePlain);
	
	hexToBin(plain, plainBit, 8);//�õ����Ķ�����
	strcpy(regBit, ivBit);//�����ʼ��������λ�Ĵ���

	while (flag)
	{
		DES_Encryption(regBit, keyBit, outputBit);

		strncpy(temp, outputBit, 8);//ѡȡ����ߵ�8λ
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
*������cipherfile�������ļ���	keyfile����Կ�ļ���	plainfile�������ļ��� vifile�������ļ���
*/
int deCFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	char regBit[65] = { 0 };//��λ�Ĵ���2����
	char keyBit[65] = { 0 };//��Կ2����
	char outputBit[65] = { 0 };//���2����
	char ivBit[65] = { 0 };//��ʼ������2����
	char cipherBit[9] = { 0 };//����2����
	char plainBit[9] = { 0 };//����2����
	char plain[3] = { 0 };//����16����
	char cipher[3] = { 0 };//����16����


	char temp[9] = { 0 };//�����м����

	getText(keyfile, keyBit);//�����Կ������
	getText(vifile, ivBit);//��ó�ʼ����������

	FILE* pFileCipher = fopen(cipherfile, "r");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "w");//�������ļ�

	int flag = fread(cipher, sizeof(char), 2, pFileCipher);

	hexToBin(cipher, cipherBit, 8);//�õ����Ķ�����
	strcpy(regBit, ivBit);//�����ʼ��������λ�Ĵ���

	while (flag)
	{
		DES_Encryption(regBit, keyBit, outputBit);

		strncpy(temp, outputBit, 8);//ѡȡ����ߵ�8λ
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
������plainfile�������ļ���	keyfile����Կ�ļ���	cipherfile�������ļ��� vifile����ʼ�����ļ���
��OFBģʽ�У��Ȳ���һ����Կ����Ȼ���������������
��ˣ�OFBģʽʵ���Ͼ���һ��ͬ�������룬ͨ����������һ����ʼ����IV���õ���Կ����
*/
int OFB(char* plainfile, char* keyfile, char* cipherfile, char* vifile) {
	char regBit[65] = { 0 };//��λ�Ĵ���
	char keyBit[65] = { 0 };//��Կ������
	char outputBit[65] = { 0 };//���������
	char ivBit[65] = { 0 };//��ʼ������2����
	char cipherBit[9] = { 0 };//����2����
	char plainBit[9] = { 0 };//����2����
	char plain[3] = { 0 };//����16����
	char cipher[3] = { 0 };//����16����

	char temp[9] = { 0 };//�����м����
	getText(keyfile, keyBit);//�õ���Կ������
	getText(vifile, ivBit);//�õ���ʼ����������

	FILE* pFileCipher = fopen(cipherfile, "w");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "r");//�������ļ�

	int flag = fread(plain, sizeof(char), 2, pFilePlain);
	hexToBin(plain, plainBit, 8);//�õ�8λ���Ķ�����
	strcpy(regBit, ivBit);//����ʼ����������λ�Ĵ���

	while (flag)
	{
		DES_Encryption(regBit, keyBit, outputBit);

		strncpy(temp, outputBit, 8);//ѡ������ߵ�8λ
		
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
*������cipherfile�������ļ���	keyfile����Կ�ļ���	plainfile�������ļ��� vifile�������ļ���
*/
int deOFB(char* cipherfile, char* keyfile, char* plainfile, char* vifile) {
	char regBit[65] = { 0 };//��λ�Ĵ���
	char keyBit[65] = { 0 };//��Կ������
	char outputBit[65] = { 0 };//���������
	char ivBit[65] = { 0 };//��ʼ������2����
	char cipherBit[9] = { 0 };//����2����
	char plainBit[9] = { 0 };//����2����
	char plain[3] = { 0 };//����16����
	char cipher[3] = { 0 };//����16����

	char temp[9] = { 0 };//�����м����
	getText(keyfile, keyBit);//�õ���Կ������
	getText(vifile, ivBit);//�õ���ʼ����������

	FILE* pFileCipher = fopen(cipherfile, "r");//�������ļ�
	FILE* pFilePlain = fopen(plainfile, "w");//�������ļ�

	int flag = fread(cipher, sizeof(char), 2, pFileCipher);
	hexToBin(cipher, cipherBit, 8);//�õ�8λ���Ķ�����
	strcpy(regBit, ivBit);//����ʼ����������λ�Ĵ���

	while (flag)
	{
		DES_Encryption(regBit, keyBit, outputBit);

		strncpy(temp, outputBit, 8);//ѡ������ߵ�8λ

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
		printf("��%d�֣�ECB������ʱ��%d ms\t�ٶȣ�%.3f MByete/s\n",i+1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n20��ECB������ʱ��%d ms�ٶȣ�%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** CBC *****************/
	/*for (int i = 0; i < 20; i++) {
		start = clock();
		CBC(param.plainfile, param.keyfile, param.cipherfile,param.vifile);
		deCBC(param.cipherfile, param.keyfile, param.decryption,param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("��%d�֣�CBC������ʱ��%d ms\t�ٶȣ�%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n20��CBC������ʱ��%d ms�ٶȣ�%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** CFB *****************/
	/*for (int i = 0; i < 5; i++) {
		start = clock();
		CFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deCFB(param.cipherfile, param.keyfile, param.decryption, param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("��%d�֣�CFB������ʱ��%d ms\t�ٶȣ�%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n5��CFB������ʱ��%d ms�ٶȣ�%.3f MByete/s\n", alltime, avgspeed);*/

	/***************** OFB *****************/
	/*for (int i = 0; i < 5; i++) {
		start = clock();
		OFB(param.plainfile, param.keyfile, param.cipherfile, param.vifile);
		deOFB(param.cipherfile, param.keyfile, param.decryption, param.vifile);
		end = clock();
		alltime += (int)(end - start);
		nowspeed = (5.0 / (((int)(end - start)) / 1000));
		avgspeed = (nowspeed + avgspeed * i) / (i + 1);
		printf("��%d�֣�OFB������ʱ��%d ms\t�ٶȣ�%.3f MByete/s\n", i + 1, (int)(end - start), nowspeed);
	}
	printf("**************************************************\n5��OFB������ʱ��%d ms�ٶȣ�%.3f MByete/s\n", alltime, avgspeed);*/

	/******************** some test in my programming ***************************************************/

}