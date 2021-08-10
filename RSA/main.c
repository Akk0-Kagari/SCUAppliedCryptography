#include <stdio.h>
#include <gmp.h>
typedef struct {
	char* plainfile;
	char* nfile;
	char* efile;
	char* dfile;
	char* cipherfile;
	char* decryption;
	char* signfile;
}s_param;

mpz_t n, e, d, plain, cipher, decryption;

int getText(char* filename, char ch);//读取文本	
int writeFile(char* filename, mpz_t x);//写入文件
int RSA_Encryption(mpz_t plain, mpz_t key, mpz_t n, char* filename);//RSA加密
int dataEncryption(char* plainfile, char* efile, char* nfile, char* cipherfile);//数据加密
int digitalSignature(char* plainfile, char* dfile, char* nfile, char* signfile);//数字签名
int keyGeneration();//密钥生成

int main(int argc, char* argv[]) {
	s_param param;
	int i = 1;
	param.plainfile = "RSA_plain.txt";
	param.cipherfile = "RSA_cipher.txt";
	param.nfile = "RSA_n.txt";
	param.efile = "RSA_e.txt";
	param.dfile = "RSA_d.txt";
	param.decryption = "RSA_decryption.txt";
	param.signfile = "RSA_sign.txt";


	while (i < argc)
	{
		if (!strcmp(argv[i], "-p"))
			param.plainfile = argv[i + 1];
		else if (!strcmp(argv[i], "-n"))
			param.nfile = argv[i + 1];
		else if (!strcmp(argv[i], "-e"))
			param.efile = argv[i + 1];
		else if (!strcmp(argv[i], "-d"))
			param.dfile = argv[i + 1];
		else if (!strcmp(argv[i], "-c"))
			param.cipherfile = argv[i + 1];
		i += 2;
	}

	/* getText test */
	/*getText(param.plainfile, plain);
	getText(param.nfile, n);
	getText(param.dfile, d);
	getText(param.efile, e);*/
	

	/* RSA_Encryption test */
	/*RSA_Encryption(plain, e, n, cipher,param.cipherfile);
	RSA_Encryption(cipher, d, n, decryption,param.decryption);
	RSA_Encryption(plain, d, n,cipher,param.sign);*/

	dataEncryption(param.plainfile, param.efile, param.nfile, param.cipherfile);

	digitalSignature(param.plainfile, param.dfile, param.nfile, param.signfile);

	keyGeneration();

	printf("DONE!");
	getchar();
	return 0;

}


/* 读取文本	
*	参数：filename：文件名	x：要读取的参数
*/
int getText(char* filename, mpz_t x) {
	FILE* pFile = fopen(filename, "r");
	if (pFile == NULL)
	{
		printf("文件%s打开失败", filename);
		exit(-1);
	}else {
		mpz_inp_str(x, pFile, 16);
		/*mpz_out_str(stdout, 16, x);
		printf("\n");*/
		fclose(pFile);
	}
	return 0;
}

/* 写入文件
*	参数：filename：文件名	x：写入的参数
*/
int writeFile(char* filename, mpz_t x) {
	int ret = 0;

	FILE* pFile = fopen(filename, "w");
	if (pFile == NULL) {
		printf("文件%s写入失败\n", filename);
		exit(-1);
	}
	mpz_out_str(pFile, 16, x);
	fclose(pFile);
	return ret;
}

/* RSA_加密
*	参数：plain：m	key：密钥	n：n
*	可用于签名，加密与解密，最终将结果写入相应的文件
*/
int RSA_Encryption(mpz_t plain, mpz_t key, mpz_t n, char* filename) {
	
	mpz_init(cipher);

	mpz_powm(cipher, plain, key, n);
	/*mpz_out_str(stdout, 16, cipher);
	printf("\n");*/
	writeFile(filename, cipher);
	return 0;
}

/*	数据加密
*	参数：plainfile：明文文件名	efile：e文件名	nfile：n文件名	cipherfile：密文文件名
*/
int dataEncryption(char* plainfile, char* efile, char* nfile, char* cipherfile) {
	int ret = 0;

	getText(plainfile, plain);
	getText(efile, e);
	getText(nfile, n);
	
	RSA_Encryption(plain, e, n, cipherfile);
	return ret;
}


/*	数字签名
*	参数：plainfile：明文文件名	dfile：d文件名	nfile：n文件名	signfile：数字签名文件名
*/
int digitalSignature(char* plainfile, char* dfile, char* nfile, char* signfile) {
	int ret = 0;

	getText(plainfile, plain);
	getText(dfile, d);
	getText(nfile, n);

	RSA_Encryption(plain, d, n, signfile);
	return ret;
}
/*	密钥生成
*/
int keyGeneration() {
	int ret = 0;

	mpz_t p, q, phi_p, phi_q, phi, rop, One;
	mpz_init(p);
	mpz_init(q);
	mpz_init(phi_p);
	mpz_init(phi_q);
	mpz_init(phi);
	mpz_init(n);
	mpz_init(e);
	mpz_init(d);
	mpz_init(rop);
	mpz_init(One);

	mpz_init_set_ui(One, 1);
	gmp_randstate_t randNum;
	gmp_randinit_default(randNum);
	gmp_randseed_ui(randNum,time(NULL));
	mpz_urandomb(p, randNum, 512);
	mpz_urandomb(q, randNum, 512);

	mpz_nextprime(p, p);
	mpz_nextprime(q, q);

	mpz_mul(n, p, q);
	mpz_sub(phi_p, p, One);
	mpz_sub(phi_q, q, One);

	mpz_mul(phi, phi_p, phi_q);

	mpz_init_set_ui(e, 65537);
	mpz_invert(d, e, phi);

	writeFile(".\\key\\P.txt", p);
	writeFile(".\\key\\Q.txt", q);
	writeFile(".\\key\\N.txt", n);
	writeFile(".\\key\\E.txt", e);
	writeFile(".\\key\\D.txt", d);
	return ret;

}