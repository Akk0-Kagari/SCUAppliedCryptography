#include <stdio.h>
#include <string.h>
#include<openssl/sha.h>

#include "mzc_base64.h"
#include "mzc_rsa.h"
#include "aes.h"

#define MAX_DATA_LEN 1024
#define SHA256_LENTH 32

typedef struct {
    char* keyfile;//�ҵ�˽Կ
    char* vifile;//aes�ĳ�ʼ����
    char* keycipher;//�׷����ҵļ��ܺ���Կ
    char* cipherfile;//����
    char* sign;//�׵�ǩ��
    char* mode;
    char* recvkey;
    char* recvplain;
    char* pbk_a;//�׵Ĺ�Կ
    char* plainfile;
}s_param;

int keycipherDecryption(char* keycipherName, char* keyfileName, char* recvkeyfileName);//��ȡ�ļ��ӽ�����Կ
int signatureVertify(char* pubkeyName, char* signfileName, char* recvplainName);//��֤֤��
char* readfile(char* path, int* length);
int d2h(int a, char* res);//dec2hex
int datacheck(char* plainfile,char* recvplainfile);
int shatest(char* strFilePath);//sha�Ĳ��Ժ����������˼׵�ǩ��
int test();

int main(int argc, char* argv[])
{
    s_param param;
    int i = 1;
    param.cipherfile = "a_cipher.txt";
    param.keycipher = "a_cipher_key.txt";
    param.keyfile = "childpvk_b.pem";//�ҵ�˽Կ֤��
    param.mode = "A";
    param.sign = "a_sign.txt";
    param.vifile = "a_vi.txt";
    param.recvkey = "a_recvkey.txt";
    param.recvplain = "a_recvplain.txt";
    param.pbk_a = "childpbk_a.pem";
    param.plainfile="a_plain.txt";
    while (i < argc)
    {
        if (!strcmp(argv[i], "-c"))
            param.cipherfile = argv[i + 1];//�����ļ�
        else if (!strcmp(argv[i], "-kc"))
            param.keycipher = argv[i + 1];//���ܵ���Կ
        else if (!strcmp(argv[i], "-k"))
            param.keyfile = argv[i + 1];//�ҵ�˽Կ
        else if (!strcmp(argv[i], "-m"))
            param.mode = argv[i + 1];//ģʽ
        else if (!strcmp(argv[i], "-s"))
            param.sign = argv[i + 1];//�׵�����ǩ��
        else if (!strcmp(argv[i], "-p"))
            param.plainfile = argv[i + 1];//�׵�����
        else if (!strcmp(argv[i], "-ka"))
            param.pbk_a = argv[i + 1];//�׵Ĺ�Կ
        else if (!strcmp(argv[i], "-rp"))
            param.recvplain = argv[i + 1];//�ָ�������
        else if (!strcmp(argv[i], "-rk"))
            param.recvkey = argv[i + 1];//�ָ�����Կ
        i += 2;
    }
    if (!strcmp(param.mode, "A")) {
        keycipherDecryption(param.keycipher, param.keyfile, param.recvkey);
        printf("�ļ�������Կ�ѻ�ȡ��\n");
    }
    else if (!strcmp(param.mode, "B")) {
        deCBC(param.cipherfile, param.recvkey, param.recvplain, param.vifile);
        printf("�ļ���������ɣ�\n");
    }
    else if (!strcmp(param.mode, "C")) {
        signatureVertify(param.pbk_a, param.sign, param.recvplain);
        printf("ǩ����֤����ɣ�\n");
    }
    else if (!strcmp(param.mode, "D")) {
        datacheck(param.plainfile, param.recvplain);
        printf("����У������ɣ�\n");
    }
    else
        printf("Mode error!");
    printf("DONE!");
    getchar();
    return 0;
}

/*  ��ȡ�ļ��е���������
*   ������path:�ļ�·��    len����ȡ���ȣ�ִ�к�õ���
*/
char* readfile(char* path, int* length)
{
    FILE* pfile;
    char* data;

    pfile = fopen(path, "rb");
    if (pfile == NULL)
    {
        return NULL;
    }
    fseek(pfile, 0, SEEK_END);
    *length = ftell(pfile);
    data = (char*)malloc((*length + 1) * sizeof(char));
    rewind(pfile);
    *length = fread(data, 1, *length, pfile);
    data[*length] = '\0';
    fclose(pfile);
    return data;
}

/*  ��ȡ�ļ��ӽ�����Կ
*   ������keycipher���ҹ�Կ���ܺ����Կ  keyfile���ҵ���Կ֤��
* 
*/
int keycipherDecryption(char* keycipherName, char* keyfileName, char* recvkeyfileName) {
    FILE* recvkeyfile = fopen(recvkeyfileName,"w");
    unsigned char privateKey[2048];
    unsigned char encrypted_str[128];
    unsigned char decrypted_str[128];
    int pvkkey_len = 0;
    int encrypted_length = 0;

    char* temp = NULL;
    

    // ��Ҫ��ʼ����������ܳ������ַ������ж��������
    memset(encrypted_str, '\0', sizeof(encrypted_str));
    memset(decrypted_str, '\0', sizeof(decrypted_str));
    memset(privateKey, '\0', sizeof(privateKey));
    
    temp = readfile(keyfileName, &pvkkey_len);
    memcpy(privateKey, temp, pvkkey_len);
    
    temp = readfile(keycipherName, &encrypted_length);
    memcpy(encrypted_str, temp, encrypted_length);

    int decrypted_length = private_key_decrypt(encrypted_str, encrypted_length, privateKey, decrypted_str);
    //printf("%d\n", encrypted_length);
    if (decrypted_length == -1)
    {
        printf("Public Decrypt failed\n");
    }
    printf("Decrypted Text = %s\n", decrypted_str);
    printf("Decrypted Length = %d\n", decrypted_length);
    fwrite(decrypted_str, sizeof(char), decrypted_length, recvkeyfile);
    return 0;
}

/*  10����ת16����
*   ������a��ʮ������   res��������ַ���
*/
int d2h(int a, char* res) {
    char hex[2] = "";
    int ch1 = 0, ch2 = 0;
    ch1 = a / 16;
    switch (ch1)
    {
    case 15:
        hex[0] = 'f';
        break;
    case 14:
        hex[0] = 'e';
        break;
    case 13:
        hex[0] = 'd';
        break;
    case 12:
        hex[0] = 'c';
        break;
    case 11:
        hex[0] = 'b';
        break;
    case 10:
        hex[0] = 'a';
        break;

    default:
        hex[0] = ch1 + 48;
        break;
    }
    ch2 = a % 16;
    switch (ch2)
    {
    case 15:
        hex[1] = 'f';
        break;
    case 14:
        hex[1] = 'e';
        break;
    case 13:
        hex[1] = 'd';
        break;
    case 12:
        hex[1] = 'c';
        break;
    case 11:
        hex[1] = 'b';
        break;
    case 10:
        hex[1] = 'a';
        break;

    default:
        hex[1] = ch2 + 48;
        break;
    }
    strncpy(res, hex, 2);
    return 0;
}

/*  ǩ����֤
*   ������pubkeyName����Կ֤���ļ���   signfileName��ǩ���ļ���  recvplainName���ָ����ļ���
*/
int signatureVertify(char* pubkeyName, char* signfileName, char* recvplainName) {
    SHA256_CTX sha256_ctx;
    FILE* fp = NULL;
    unsigned char SHA256result[SHA256_LENTH];
    char DataBuff[MAX_DATA_LEN];
    int len;
    int t = 0;
    int i;
    int hash_len;
    char tempchunk[3] = { '\0' };
    char shadata[1024] = { '\0' };
    unsigned char publicKey[2048];
    unsigned char encrypted_str[128];
    unsigned char decrypted_str[128];
    int pbkkey_len = 0;
    int encrypted_length = 0;
    char* temp = NULL;

    fp = fopen(recvplainName, "rb");  //���ļ�

    // ��Ҫ��ʼ����������ܳ������ַ������ж��������
    memset(encrypted_str, '\0', sizeof(encrypted_str));
    memset(decrypted_str, '\0', sizeof(decrypted_str));
    memset(publicKey, '\0', sizeof(publicKey));

    temp = readfile(pubkeyName, &pbkkey_len);
    memcpy(publicKey, temp, pbkkey_len);

    temp = readfile(signfileName, &encrypted_length);
    memcpy(encrypted_str, temp, encrypted_length);

    int decrypted_length = public_key_decrypt(encrypted_str, encrypted_length, publicKey, decrypted_str);
    //printf("%d\n", encrypted_length);
    if (decrypted_length == -1)
    {
        printf("Public Decrypt failed\n");
    }
    printf("Decrypted Signature\n%s\n", decrypted_str);
    

    SHA256_Init(&sha256_ctx);

    while (!feof(fp))
    {
        memset(DataBuff, 0x00, sizeof(DataBuff));

        len = fread(DataBuff, 1, MAX_DATA_LEN, fp);
        if (len)
        {
            t += len;
            //printf("len = [%d] 1\n", len);
            SHA256_Update(&sha256_ctx, DataBuff, len);   //����ǰ�ļ�����벢����SHA256
        }
    }

    //    //printf("len = [%d]\n", t);

    SHA256_Final(SHA256result, &sha256_ctx); //��ȡSHA256k

    puts("SHA256:");
    for (i = 0; i < SHA256_LENTH; i++) //��SHA256��16�������
    {
        printf("%02x", (int)SHA256result[i]);
        d2h((int)SHA256result[i], tempchunk);
        //printf("%s\n", temp);
        strcat(shadata, tempchunk);
    }
    
    printf("\nǩ����֤��%s\n", strcmp(shadata, decrypted_str)==0 ? "TRUE":"FALSE");

    return 0;
}

/*  ����У��
*   ������plainfile�������ļ���  recvplainfile���ָ��������ļ���
*/
int datacheck(char* plainfile, char* recvplainfile){
    FILE* f1 = fopen(plainfile, "r");
    FILE* f2 = fopen(recvplainfile, "r");
    char c1 = fgetc(f1);
    char c2 = fgetc(f2);
    while (!feof(f1) && !feof(f2)) {
        if (c1 != c2) 
        { 
            printf("�ļ����ݲ�һ��");  
            return 0; 
        }
        c1 = fgetc(f1);
        c2 = fgetc(f2);
    }
    if (c1 == EOF && c2 == EOF) /* �ж������ļ��Ƿ񶼵���β */
        printf("�ļ�����һ��");
    else
        printf("�ļ����ݲ�һ��");
    printf("\n");
    fclose(f1);
    fclose(f2);
    return 0;
}

/*  �����д�����е�һЩ����
*   �ò�������˶Լ׷���Կ�ļ���
*/
int test() {
    unsigned char plainText[] = "57696C6C69616D53";
    FILE* pvkfile;
    FILE* pbkfile;
    FILE* keycipehrFile;
    unsigned char publicKey[2048];
    unsigned char privateKey[2048];
    unsigned char encrypted_str[128];
    unsigned char decrypted_str[128];
    int pvkkey_len = 0;
    int pbkkey_len = 0;
    char* temp = NULL;


    // ��Ҫ��ʼ����������ܳ������ַ������ж��������
    memset(encrypted_str, '\0', sizeof(encrypted_str));
    memset(decrypted_str, '\0', sizeof(decrypted_str));
    memset(publicKey, '\0', sizeof(publicKey));
    memset(privateKey, '\0', sizeof(privateKey));

    keycipehrFile = fopen("a_cipher_key.txt", "w");
    temp = readfile("childpvk_b.pem", &pvkkey_len);
    memcpy(privateKey, temp, pvkkey_len);
    temp = readfile("childpbk_b.pem", &pbkkey_len);
    memcpy(publicKey, temp, pbkkey_len);

    size_t len = strlen((const char*)plainText);
    printf("Encrypted length =%d\n", len);


    // ��Կ����
    int encrypted_length = public_key_encrypt(plainText, len, publicKey, encrypted_str);
    if (encrypted_length == -1)
    {
        printf("Private Encrypt failed\n");
        exit(0);
    }
    printf("Encrypted Text=%s\n", encrypted_str);
    fwrite(encrypted_str, sizeof(char), encrypted_length, keycipehrFile);
    // ˽Կ����
    int decrypted_length = private_key_decrypt(encrypted_str, encrypted_length, privateKey, decrypted_str);
    if (decrypted_length == -1)
    {
        printf("Public Decrypt failed\n");
        exit(0);
    }
    printf("Decrypted Text =%s\n", decrypted_str);
    printf("Decrypted Length =%d\n", decrypted_length);

    return 0;
}


/*
* sha���Բ������˼׵�ǩ��
*/
int shatest(char* strFilePath) {
    SHA256_CTX sha256_ctx;
    FILE* fp = NULL;
    FILE* signFile = fopen("a_sign.txt", "w");
    unsigned char SHA256result[SHA256_LENTH];
    char DataBuff[MAX_DATA_LEN];
    int len;
    int t = 0;
    int i;
    int hash_len;
    char temp[3] = { '\0' };
    int pvkkey_len;//a��˽Կ����
    int pbkkey_len;//a�Ĺ�Կ����
    char shadata[1024] = { '\0' };
    FILE* pvkfile;
    unsigned char privateKey[2048];
    unsigned char publicKey[2048];
    unsigned char encrypted_str[128];
    unsigned char decrypted_str[128];
    char* temppvk = NULL;
    char* temppbk = NULL;
    int enc_len = 0;


    memset(encrypted_str, '\0', sizeof(encrypted_str));
    memset(decrypted_str, '\0', sizeof(decrypted_str));
    memset(publicKey, '\0', sizeof(publicKey));
    memset(privateKey, '\0', sizeof(privateKey));

    fp = fopen(strFilePath, "rb");  //���ļ�

    do
    {
        SHA256_Init(&sha256_ctx);

        while (!feof(fp))
        {
            memset(DataBuff, 0x00, sizeof(DataBuff));

            len = fread(DataBuff, 1, MAX_DATA_LEN, fp);
            if (len)
            {
                t += len;
                //printf("len = [%d] 1\n", len);
                SHA256_Update(&sha256_ctx, DataBuff, len);   //����ǰ�ļ�����벢����SHA256
            }
        }

        //    //printf("len = [%d]\n", t);

        SHA256_Final(SHA256result, &sha256_ctx); //��ȡSHA256

        puts("SHA256:");
        for (i = 0; i < SHA256_LENTH; i++) //��SHA256��16�������
        {
            printf("%02x", (int)SHA256result[i]);
            d2h((int)SHA256result[i], temp);
            //printf("%s\n", temp);
            strcat(shadata, temp);
        }
        puts("\n");

    } while (0);
    printf("%s\n", shadata);
    printf("%d\n", strlen(shadata));
    hash_len = strlen(shadata);

    temppvk = readfile("childpvk_a.pem", &pvkkey_len);
    memcpy(privateKey, temppvk, pvkkey_len);
    temppbk = readfile("childpbk_a.pem", &pbkkey_len);
    memcpy(publicKey, temppbk, pbkkey_len);


    int encrypted_length = private_key_encrypt(shadata, hash_len, privateKey, encrypted_str);

    printf("enc:%s\n", encrypted_str);

    fwrite(encrypted_str, sizeof(char), encrypted_length, signFile);

    int decrypted_length = public_key_decrypt(encrypted_str, encrypted_length, publicKey, decrypted_str);

    printf("dec:%s\n", decrypted_str);


    fclose(signFile);
    //memset(encrypted_str, '\0', sizeof(encrypted_str));

    //tempencstr = getfileall("D:\\ctf\\crypto\\IntegratedPractice\\IntegratedPractice\\Debug\\NeededFiles\\a_sign.txt", &enc_len);

    //memcpy(encrypted_str, tempencstr, enc_len);

    //printf("%s\t%d\n", encrypted_str,enc_len);

    //int decrypted_length = public_key_decrypt(encrypted_str, encrypted_length, publicKey, decrypted_str);

    //printf("%d\n", decrypted_length);

    //printf("decrypt: %s\n", decrypted_str);

    //fclose(fp);
    //fclose(signRead);
    return 0;
}